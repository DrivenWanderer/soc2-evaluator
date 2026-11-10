using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Soc2Evaluator.Adapters;
using Soc2Evaluator.Adapters.Dependencies;
using Soc2Evaluator.Adapters.Gitleaks;
using Soc2Evaluator.Cli;
using Soc2Evaluator.Core.Adapters;
using Soc2Evaluator.Core.Models;
using Soc2Evaluator.Core.Services;
using Soc2Evaluator.Reporting;
using Soc2Evaluator.Rules;
using Soc2Evaluator.Rules.Checks;

var services = new ServiceCollection();

// Logging
services.AddLogging(builder =>
{
    builder.AddSimpleConsole(options =>
    {
        options.SingleLine = true;
        options.TimestampFormat = "HH:mm:ss ";
    });
    builder.SetMinimumLevel(LogLevel.Information);
});

// Core services
services.AddSingleton<IEvidenceHasher, EvidenceHasher>();
services.AddSingleton<IProcessRunner, ProcessRunner>();
services.AddSingleton<IControlMappingService, ControlMappingService>();
services.AddSingleton<IRemediationService, RemediationService>();
services.AddSingleton<IBaselineDiffService, BaselineDiffService>();
services.AddSingleton<ISuppressionService, SuppressionService>();

// Rules
services.AddSingleton<IRuleCheck, VerboseErrorsCheck>();

// Adapters
services.AddSingleton<IScannerAdapter, GitleaksAdapter>();
services.AddSingleton<IScannerAdapter, DependencyScannerAdapter>();
services.AddSingleton<IScannerAdapter, RulesScannerAdapter>();

// Reporters
services.AddSingleton<IReporter, MarkdownReporter>();
services.AddSingleton<IReporter, JsonReporter>();
services.AddSingleton<ReporterFactory>();

// Orchestrator
services.AddSingleton<IEvaluationOrchestrator, EvaluationOrchestrator>();

var serviceProvider = services.BuildServiceProvider();
var logger = serviceProvider.GetRequiredService<ILogger<Program>>();
var orchestrator = serviceProvider.GetRequiredService<IEvaluationOrchestrator>();
var reporterFactory = serviceProvider.GetRequiredService<ReporterFactory>();
var processRunner = serviceProvider.GetRequiredService<IProcessRunner>();

var rootCommand = CommandLineBuilder.BuildRootCommand(async (scanOptions, cancellationToken) =>
{
    logger.LogInformation("================================================================================");
    logger.LogInformation("SOC 2 Readiness Assessment Evaluator (v0.1.0)");
    logger.LogInformation("================================================================================");
    logger.LogInformation("Target: {Target}", Path.GetFullPath(scanOptions.Target));
    logger.LogInformation("Criteria in scope: {Criteria}", string.Join(", ", scanOptions.Criteria));
    logger.LogInformation("Output destination: {OutputPath}", Path.GetFullPath(scanOptions.OutputPath));
    if (!string.IsNullOrWhiteSpace(scanOptions.OrgConfigPath))
    {
        logger.LogInformation("Organization configuration: {OrgConfig}", Path.GetFullPath(scanOptions.OrgConfigPath));
    }
    if (!string.IsNullOrWhiteSpace(scanOptions.IgnorePath))
    {
        logger.LogInformation("Suppressions file: {IgnorePath}", Path.GetFullPath(scanOptions.IgnorePath));
    }
    if (!string.IsNullOrWhiteSpace(scanOptions.BaselinePath))
    {
        logger.LogInformation("Baseline findings comparison: {BaselinePath}", Path.GetFullPath(scanOptions.BaselinePath));
    }
    if (!string.IsNullOrWhiteSpace(scanOptions.Url))
    {
        logger.LogWarning("External URL probe (--url) is planned for Phase 3 and is not yet available. Skipping live probe for '{Url}'.", scanOptions.Url);
    }

    // Validate formats
    var supportedFormats = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "md", "json" };
    foreach (var format in scanOptions.Formats)
    {
        if (!supportedFormats.Contains(format))
        {
            logger.LogError("Unsupported report format '{Format}'. Supported formats in this phase: md, json. (SARIF output is scheduled for Phase 3).", format);
            return 1;
        }
    }

    // Determine Git commit SHA if target has git
    string? commitSha = null;
    try
    {
        var gitResult = await processRunner.RunAsync("git", ["rev-parse", "HEAD"], workingDirectory: scanOptions.Target, cancellationToken: cancellationToken);
        if (gitResult.ExitCode == 0 && !string.IsNullOrWhiteSpace(gitResult.StandardOutput))
        {
            commitSha = gitResult.StandardOutput.Trim();
            logger.LogInformation("Git Commit SHA: {CommitSha}", commitSha);
        }
    }
    catch
    {
        // Not a git repository or git not available
    }

    var request = new EvaluationRequest(
        TargetPath: scanOptions.Target,
        Criteria: scanOptions.Criteria,
        OutputPath: scanOptions.OutputPath,
        Formats: scanOptions.Formats,
        CommitSha: commitSha,
        FailOnSeverity: scanOptions.FailOnSeverity,
        Offline: scanOptions.Offline,
        OrgConfigPath: scanOptions.OrgConfigPath,
        BaselinePath: scanOptions.BaselinePath,
        IgnoreFilePath: scanOptions.IgnorePath
    );

    var bundle = await orchestrator.RunEvaluationAsync(request, cancellationToken);
    var manifest = bundle.Manifest;

    // Ensure output directories exist
    var outDir = Path.GetFullPath(scanOptions.OutputPath);
    Directory.CreateDirectory(outDir);
    var evidenceDir = Path.Combine(outDir, "evidence");
    Directory.CreateDirectory(evidenceDir);

    // Save scrubbed evidence artifacts
    foreach (var (filename, bytes) in bundle.RawArtifactBytes)
    {
        var artifactPath = Path.Combine(evidenceDir, filename);
        await File.WriteAllBytesAsync(artifactPath, bytes, cancellationToken);
        logger.LogInformation("Saved scrubbed evidence artifact: {ArtifactPath}", artifactPath);
    }

    // Generate selected report formats
    var reportOutputs = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
    foreach (var format in scanOptions.Formats)
    {
        var reporter = reporterFactory.GetReporter(format);
        if (reporter != null)
        {
            var reportContent = await reporter.RenderAsync(manifest, cancellationToken);
            var reportPath = Path.Combine(outDir, reporter.OutputFileName);
            await File.WriteAllTextAsync(reportPath, reportContent, cancellationToken);
            reportOutputs[reporter.OutputFileName] = reportContent;
            logger.LogInformation("Report generated: {ReportPath}", reportPath);
        }
    }

    // Save raw evidence bundle JSON and standalone manifest.sha256
    var bundleJsonPath = Path.Combine(outDir, "evidence-bundle.json");
    var bundleJson = System.Text.Json.JsonSerializer.Serialize(bundle, new System.Text.Json.JsonSerializerOptions { WriteIndented = true });
    await File.WriteAllTextAsync(bundleJsonPath, bundleJson, cancellationToken);
    logger.LogInformation("Evidence bundle saved: {BundlePath}", bundleJsonPath);

    var bundleBytes = System.Text.Encoding.UTF8.GetBytes(bundleJson);
    var bundleSha256 = System.Convert.ToHexString(System.Security.Cryptography.SHA256.HashData(bundleBytes)).ToLowerInvariant();
    var shaPath = Path.Combine(outDir, "manifest.sha256");
    await File.WriteAllTextAsync(shaPath, $"{bundleSha256}  evidence-bundle.json\n", cancellationToken);
    logger.LogInformation("Evidence bundle checksum saved: {ChecksumPath}", shaPath);

    logger.LogInformation("Evaluation completed. Total findings: {FindingsCount}", manifest.Findings.Count);

    // CI Gating evaluation (--fail-on)
    if (!string.IsNullOrWhiteSpace(scanOptions.FailOnSeverity))
    {
        var rawThreshold = scanOptions.FailOnSeverity.Trim();
        var definedNames = Enum.GetNames<Severity>();
        var matchingName = definedNames.FirstOrDefault(n => n.Equals(rawThreshold, StringComparison.OrdinalIgnoreCase));
        if (matchingName == null || !Enum.TryParse<Severity>(matchingName, ignoreCase: true, out var threshold))
        {
            logger.LogError(
                "Invalid --fail-on severity threshold: '{Threshold}'. Valid values are: {ValidValues}.",
                scanOptions.FailOnSeverity,
                string.Join(", ", definedNames)
            );
            return 1;
        }

        var violatingFindings = manifest.Findings
            .Where(f => f.Status == FindingStatus.Open && f.Severity >= threshold)
            .ToList();

        if (violatingFindings.Count > 0)
        {
            logger.LogError(
                "CI Gate Failed: {Count} actionable open finding(s) met or exceeded the --fail-on threshold of {Threshold}.",
                violatingFindings.Count,
                threshold
            );
            return 2;
        }
    }

    return 0;
});

return await rootCommand.Parse(args).InvokeAsync();