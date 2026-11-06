using System.Text;
using System.Text.Json;
using Soc2Evaluator.Adapters.Sarif;
using Soc2Evaluator.Core.Adapters;
using Soc2Evaluator.Core.Models;
using Soc2Evaluator.Core.Services;

namespace Soc2Evaluator.Adapters.Dependencies;

public class DependencyScannerAdapter : IScannerAdapter
{
    private readonly IProcessRunner _processRunner;
    private readonly IEvidenceHasher _hasher;

    public string ToolName => "dependency-scanner";
    public string DefaultRulePrefix => "DEP-001";
    public string InstallGuidance => "Install 'osv-scanner' via 'go install github.com/google/osv-scanner/cmd/osv-scanner@latest' or install the .NET SDK (which includes in-box 'dotnet list package --vulnerable').";

    public DependencyScannerAdapter(IProcessRunner processRunner, IEvidenceHasher hasher)
    {
        _processRunner = processRunner;
        _hasher = hasher;
    }

    public async Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default)
    {
        if (_processRunner.ExistsOnPath("osv-scanner"))
        {
            return true;
        }

        if (_processRunner.ExistsOnPath("dotnet"))
        {
            return true;
        }

        return false;
    }

    public async Task<string?> GetVersionAsync(CancellationToken cancellationToken = default)
    {
        if (_processRunner.ExistsOnPath("osv-scanner"))
        {
            try
            {
                var res = await _processRunner.RunAsync("osv-scanner", ["--version"], cancellationToken: cancellationToken);
                if (res.ExitCode == 0 && !string.IsNullOrWhiteSpace(res.StandardOutput))
                {
                    return res.StandardOutput.Trim();
                }
            }
            catch { /* fallback */ }
        }

        if (_processRunner.ExistsOnPath("dotnet"))
        {
            try
            {
                var res = await _processRunner.RunAsync("dotnet", ["--version"], cancellationToken: cancellationToken);
                if (res.ExitCode == 0 && !string.IsNullOrWhiteSpace(res.StandardOutput))
                {
                    return $"{res.StandardOutput.Trim()} (dotnet-list)";
                }
            }
            catch { /* fallback */ }
        }

        return null;
    }

    public async Task<AdapterExecutionResult> ExecuteAsync(AdapterExecutionContext context, CancellationToken cancellationToken = default)
    {
        var startTime = DateTimeOffset.UtcNow;
        var hasOsv = _processRunner.ExistsOnPath("osv-scanner");
        var hasDotNet = _processRunner.ExistsOnPath("dotnet");

        if (!hasOsv && !hasDotNet)
        {
            var notRunProvenance = new ToolExecutionProvenance(
                ToolName: ToolName,
                ToolVersion: null,
                Arguments: [],
                StartTimeUtc: startTime,
                EndTimeUtc: DateTimeOffset.UtcNow,
                ExitCode: null,
                Status: "NotRun",
                ErrorMessage: $"Neither 'osv-scanner' nor '.NET SDK' is installed or in PATH. {InstallGuidance}"
            );

            return new AdapterExecutionResult(
                Provenance: notRunProvenance,
                Findings: [],
                Artifacts: [],
                RawArtifactBytes: new Dictionary<string, byte[]>()
            );
        }

        if (hasOsv)
        {
            return await ExecuteOsvScannerAsync(context, startTime, cancellationToken);
        }

        return await ExecuteDotNetListAsync(context, startTime, cancellationToken);
    }

    private async Task<AdapterExecutionResult> ExecuteOsvScannerAsync(
        AdapterExecutionContext context,
        DateTimeOffset startTime,
        CancellationToken cancellationToken)
    {
        var version = await GetVersionAsync(cancellationToken);
        var tempReportPath = Path.Combine(Path.GetTempPath(), $"osv-{Guid.NewGuid():N}.sarif");
        var args = new List<string>
        {
            "-r", context.TargetPath,
            "--format", "sarif",
            "--output", tempReportPath
        };

        ProcessResult procResult;
        try
        {
            procResult = await _processRunner.RunAsync("osv-scanner", args, cancellationToken: cancellationToken);
        }
        catch (Exception ex)
        {
            var failedProvenance = new ToolExecutionProvenance(
                ToolName: "osv-scanner",
                ToolVersion: version,
                Arguments: args,
                StartTimeUtc: startTime,
                EndTimeUtc: DateTimeOffset.UtcNow,
                ExitCode: -1,
                Status: "Failed",
                ErrorMessage: ex.Message
            );

            return new AdapterExecutionResult(failedProvenance, [], [], new Dictionary<string, byte[]>());
        }

        var sarifContent = string.Empty;
        if (File.Exists(tempReportPath))
        {
            sarifContent = await File.ReadAllTextAsync(tempReportPath, cancellationToken);
            try { File.Delete(tempReportPath); } catch { /* cleanup */ }
        }

        var (findings, parsedVer) = SarifParser.Parse(sarifContent, "osv-scanner", DefaultRulePrefix, ["CC7.1"]);

        var artifacts = new List<EvidenceArtifact>();
        var artifactMap = new Dictionary<string, byte[]>();

        if (!string.IsNullOrWhiteSpace(sarifContent))
        {
            var scrubbed = SarifParser.ScrubSarif(sarifContent);
            var bytes = Encoding.UTF8.GetBytes(scrubbed);
            var hash = _hasher.ComputeSha256(bytes);
            var name = "osv-scanner.sarif";
            artifacts.Add(new EvidenceArtifact(name, "application/sarif+json", hash, $"evidence/{name}"));
            artifactMap[name] = bytes;
        }

        var provenance = new ToolExecutionProvenance(
            ToolName: "osv-scanner",
            ToolVersion: version ?? parsedVer,
            Arguments: args,
            StartTimeUtc: procResult.StartTimeUtc,
            EndTimeUtc: procResult.EndTimeUtc,
            ExitCode: procResult.ExitCode,
            Status: procResult.ExitCode == 0 ? "Success" : "Failed",
            ErrorMessage: procResult.ExitCode != 0 ? procResult.StandardError : null
        );

        return new AdapterExecutionResult(provenance, findings, artifacts, artifactMap);
    }

    private async Task<AdapterExecutionResult> ExecuteDotNetListAsync(
        AdapterExecutionContext context,
        DateTimeOffset startTime,
        CancellationToken cancellationToken)
    {
        var version = await GetVersionAsync(cancellationToken);
        var targetPath = context.TargetPath;

        var args = new List<string>
        {
            "list", targetPath,
            "package",
            "--vulnerable",
            "--include-transitive",
            "--format", "json"
        };

        ProcessResult procResult;
        try
        {
            procResult = await _processRunner.RunAsync("dotnet", args, workingDirectory: targetPath, cancellationToken: cancellationToken);
        }
        catch (Exception ex)
        {
            var failedProvenance = new ToolExecutionProvenance(
                ToolName: "dotnet-list-package",
                ToolVersion: version,
                Arguments: args,
                StartTimeUtc: startTime,
                EndTimeUtc: DateTimeOffset.UtcNow,
                ExitCode: -1,
                Status: "Failed",
                ErrorMessage: ex.Message
            );

            return new AdapterExecutionResult(failedProvenance, [], [], new Dictionary<string, byte[]>());
        }

        var jsonOutput = procResult.StandardOutput;
        var findings = ParseDotNetVulnerabilities(jsonOutput);

        var artifacts = new List<EvidenceArtifact>();
        var artifactMap = new Dictionary<string, byte[]>();

        if (!string.IsNullOrWhiteSpace(jsonOutput))
        {
            var bytes = Encoding.UTF8.GetBytes(jsonOutput);
            var hash = _hasher.ComputeSha256(bytes);
            var name = "dotnet-vulnerable-packages.json";
            artifacts.Add(new EvidenceArtifact(name, "application/json", hash, $"evidence/{name}"));
            artifactMap[name] = bytes;
        }

        var provenance = new ToolExecutionProvenance(
            ToolName: "dotnet-list-package",
            ToolVersion: version,
            Arguments: args,
            StartTimeUtc: procResult.StartTimeUtc,
            EndTimeUtc: procResult.EndTimeUtc,
            ExitCode: procResult.ExitCode,
            Status: procResult.ExitCode == 0 ? "Success" : "Failed",
            ErrorMessage: procResult.ExitCode != 0 ? procResult.StandardError : null
        );

        return new AdapterExecutionResult(provenance, findings, artifacts, artifactMap);
    }

    public static List<Finding> ParseDotNetVulnerabilities(string json)
    {
        var findings = new List<Finding>();
        if (string.IsNullOrWhiteSpace(json))
        {
            return findings;
        }

        try
        {
            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;

            if (!root.TryGetProperty("projects", out var projects) || projects.ValueKind != JsonValueKind.Array)
            {
                return findings;
            }

            var findingIndex = 1;

            foreach (var project in projects.EnumerateArray())
            {
                var projectPath = project.TryGetProperty("path", out var pProp) ? pProp.GetString() : "project.csproj";

                if (!project.TryGetProperty("frameworks", out var frameworks) || frameworks.ValueKind != JsonValueKind.Array)
                {
                    continue;
                }

                foreach (var framework in frameworks.EnumerateArray())
                {
                    ProcessPackageList(framework, "topLevelPackages", projectPath, ref findingIndex, findings, isTransitive: false);
                    ProcessPackageList(framework, "transitivePackages", projectPath, ref findingIndex, findings, isTransitive: true);
                }
            }
        }
        catch
        {
            // Invalid JSON or no packages found
        }

        return findings;
    }

    private static void ProcessPackageList(
        JsonElement framework,
        string propertyName,
        string? projectPath,
        ref int findingIndex,
        List<Finding> findings,
        bool isTransitive)
    {
        if (!framework.TryGetProperty(propertyName, out var packages) || packages.ValueKind != JsonValueKind.Array)
        {
            return;
        }

        foreach (var pkg in packages.EnumerateArray())
        {
            var id = pkg.TryGetProperty("id", out var idProp) ? idProp.GetString() : "UnknownPackage";
            var resolvedVersion = pkg.TryGetProperty("resolvedVersion", out var verProp) ? verProp.GetString() : "UnknownVersion";

            if (!pkg.TryGetProperty("vulnerabilities", out var vulns) || vulns.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var vuln in vulns.EnumerateArray())
            {
                var severityStr = vuln.TryGetProperty("severity", out var sProp) ? sProp.GetString() : "High";
                var advisoryUrl = vuln.TryGetProperty("advisoryurl", out var aProp) ? aProp.GetString() : "";

                var severity = severityStr?.ToLowerInvariant() switch
                {
                    "critical" => Severity.Critical,
                    "high" => Severity.High,
                    "moderate" or "medium" => Severity.Medium,
                    "low" => Severity.Low,
                    _ => Severity.High
                };

                var packageType = isTransitive ? "Transitive" : "Top-level";
                var location = new FindingLocation(FilePath: projectPath, SettingOrResource: $"{id}@{resolvedVersion}");
                var findingId = $"DEP-001-{findingIndex++}";
                var fingerprint = Finding.ComputeFingerprint("DEP-001", location);

                findings.Add(new Finding(
                    Id: findingId,
                    RuleId: "DEP-001",
                    Title: $"Vulnerable package: {id} {resolvedVersion} ({severityStr})",
                    SourceName: "dotnet-list-package",
                    SourceVersion: null,
                    TscCriteria: ["CC7.1"],
                    OrgControlId: null,
                    Severity: severity,
                    Category: FindingCategory.Configuration,
                    Location: location,
                    RedactedEvidence: $"{packageType} dependency: {id} version {resolvedVersion}\nSeverity: {severityStr}\nAdvisory: {advisoryUrl}".Trim(),
                    RiskExplanation: $"Known security vulnerability identified in dependency {id} ({severityStr}). Unpatched dependencies expose the application to published exploits.",
                    RecommendedFix: $"Update {id} in {Path.GetFileName(projectPath)} to a patched version or replace with a secure alternative.",
                    Effort: EffortEstimate.Low,
                    Confidence: ConfidenceLevel.High,
                    Fingerprint: fingerprint
                ));
            }
        }
    }
}