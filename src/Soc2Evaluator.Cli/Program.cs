using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Soc2Evaluator.Adapters;
using Soc2Evaluator.Adapters.Gitleaks;
using Soc2Evaluator.Cli;
using Soc2Evaluator.Core.Adapters;
using Soc2Evaluator.Core.Services;
using Soc2Evaluator.Reporting;

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

// Adapters
services.AddSingleton<IScannerAdapter, GitleaksAdapter>();

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
        Offline: scanOptions.Offline
    );

    var bundle = await orchestrator.RunEvaluationAsync(request, cancellationToken);
    var manifest = bundle.Manifest;

    // Ensure output directories exist
    var outDir = Path.GetFullPath(scanOptions.OutputPath);
    Directory.CreateDirectory(outDir);
    var evidenceDir = Path.Combine(outDir, "evidence");
    Directory.CreateDirectory(evidenceDir);

    // Save raw evidence artifacts
    foreach (var (filename, bytes) in bundle.RawArtifactBytes)
    {
        var artifactFile = Path.Combine(evidenceDir, filename);
        await File.WriteAllBytesAsync(artifactFile, bytes, cancellationToken);
        logger.LogInformation("Saved evidence artifact: {File}", artifactFile);
    }

    // Render requested reports
    foreach (var format in scanOptions.Formats)
    {
        try
        {
            var reporter = reporterFactory.GetReporter(format);
            var reportContent = await reporter.RenderAsync(manifest, cancellationToken);
            var reportPath = Path.Combine(outDir, reporter.OutputFileName);
            await File.WriteAllTextAsync(reportPath, reportContent, cancellationToken);
            logger.LogInformation("Generated report [{Format}]: {Path}", format, reportPath);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "Failed to render report for format: {Format}", format);
        }
    }

    // Always generate manifest evidence-bundle.json
    var bundleReporter = reporterFactory.GetReporter("json");
    var manifestContent = await bundleReporter.RenderAsync(manifest, cancellationToken);
    var manifestPath = Path.Combine(outDir, "evidence-bundle.json");
    await File.WriteAllTextAsync(manifestPath, manifestContent, cancellationToken);
    logger.LogInformation("Saved tamper-evident evidence bundle manifest: {Path}", manifestPath);

    logger.LogInformation("================================================================================");
    logger.LogInformation("Scan completed successfully.");
    logger.LogInformation("Run ID: {RunId}", manifest.RunId);
    logger.LogInformation("Evidence Manifest SHA-256: {Hash}", manifest.ManifestSha256);
    logger.LogInformation("Total findings evaluated: {Count}", manifest.Findings.Count);
    logger.LogInformation("================================================================================");

    return 0;
});

var parseResult = rootCommand.Parse(args);
return await parseResult.InvokeAsync();