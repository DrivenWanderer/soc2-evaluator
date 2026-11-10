using System.Text;
using Soc2Evaluator.Adapters.Sarif;
using Soc2Evaluator.Core.Adapters;
using Soc2Evaluator.Core.Models;
using Soc2Evaluator.Core.Services;

namespace Soc2Evaluator.Adapters.Semgrep;

public class SemgrepAdapter : IScannerAdapter
{
    private readonly IProcessRunner _processRunner;
    private readonly IEvidenceHasher _hasher;

    public string ToolName => "semgrep";
    public string DefaultRulePrefix => "SEC-002";
    public string InstallGuidance => "Install semgrep via 'pip install semgrep' or in WSL/Linux/macOS via 'curl -fsSL https://semgrep.dev/get | bash'. On Windows, execute within WSL or ensure semgrep is in PATH.";

    public SemgrepAdapter(IProcessRunner processRunner, IEvidenceHasher hasher)
    {
        _processRunner = processRunner;
        _hasher = hasher;
    }

    public async Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default)
    {
        if (_processRunner.ExistsOnPath("semgrep"))
        {
            try
            {
                var res = await _processRunner.RunAsync("semgrep", ["--version"], cancellationToken: cancellationToken);
                return res.ExitCode == 0;
            }
            catch
            {
                return false;
            }
        }

        return false;
    }

    public async Task<string?> GetVersionAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var res = await _processRunner.RunAsync("semgrep", ["--version"], cancellationToken: cancellationToken);
            if (res.ExitCode == 0 && !string.IsNullOrWhiteSpace(res.StandardOutput))
            {
                return res.StandardOutput.Trim();
            }
        }
        catch
        {
            // Ignore
        }

        return null;
    }

    public async Task<AdapterExecutionResult> ExecuteAsync(AdapterExecutionContext context, CancellationToken cancellationToken = default)
    {
        var startTime = DateTimeOffset.UtcNow;

        if (context.Offline)
        {
            var offlineProvenance = new ToolExecutionProvenance(
                ToolName: ToolName,
                ToolVersion: null,
                Arguments: [],
                StartTimeUtc: startTime,
                EndTimeUtc: DateTimeOffset.UtcNow,
                ExitCode: null,
                Status: "NotRun",
                ErrorMessage: "Skipped in offline mode: Semgrep rule resolution requires network access."
            );

            return new AdapterExecutionResult(
                Provenance: offlineProvenance,
                Findings: [],
                Artifacts: [],
                RawArtifactBytes: new Dictionary<string, byte[]>()
            );
        }

        var isAvailable = await IsAvailableAsync(cancellationToken);
        if (!isAvailable)
        {
            var notRunProvenance = new ToolExecutionProvenance(
                ToolName: ToolName,
                ToolVersion: null,
                Arguments: [],
                StartTimeUtc: startTime,
                EndTimeUtc: DateTimeOffset.UtcNow,
                ExitCode: null,
                Status: "NotRun",
                ErrorMessage: $"Scanner '{ToolName}' is not installed or not in PATH. {InstallGuidance}"
            );

            return new AdapterExecutionResult(
                Provenance: notRunProvenance,
                Findings: [],
                Artifacts: [],
                RawArtifactBytes: new Dictionary<string, byte[]>()
            );
        }

        var version = await GetVersionAsync(cancellationToken);
        var tempReportPath = Path.Combine(Path.GetTempPath(), $"semgrep-{Guid.NewGuid():N}.sarif");
        var args = new List<string>
        {
            "scan",
            "--sarif",
            "--output", tempReportPath,
            "--quiet",
            "--config", "auto",
            context.TargetPath
        };

        ProcessResult procResult;
        try
        {
            procResult = await _processRunner.RunAsync("semgrep", args, cancellationToken: cancellationToken);
        }
        catch (Exception ex)
        {
            var failedProvenance = new ToolExecutionProvenance(
                ToolName: ToolName,
                ToolVersion: version,
                Arguments: args,
                StartTimeUtc: startTime,
                EndTimeUtc: DateTimeOffset.UtcNow,
                ExitCode: -1,
                Status: "Failed",
                ErrorMessage: ex.Message
            );

            return new AdapterExecutionResult(
                Provenance: failedProvenance,
                Findings: [],
                Artifacts: [],
                RawArtifactBytes: new Dictionary<string, byte[]>()
            );
        }

        var sarifContent = string.Empty;
        if (File.Exists(tempReportPath))
        {
            var rawBytes = await File.ReadAllBytesAsync(tempReportPath, cancellationToken);
            sarifContent = Encoding.UTF8.GetString(rawBytes);
            try { File.Delete(tempReportPath); } catch { /* best effort cleanup */ }
        }

        var (findings, parsedVersion) = SarifParser.Parse(
            sarifContent,
            ToolName,
            DefaultRulePrefix,
            ["CC6.1"],
            ruleMapper: MapSemgrepRule
        );

        var scrubbedSarif = SarifParser.ScrubSarif(sarifContent);
        var artifactBytes = Encoding.UTF8.GetBytes(scrubbedSarif);
        var artifactHash = _hasher.ComputeSha256(artifactBytes);

        var artifacts = new List<EvidenceArtifact>();
        var rawArtifactMap = new Dictionary<string, byte[]>();

        if (!string.IsNullOrWhiteSpace(scrubbedSarif))
        {
            var artifactName = "semgrep.sarif";
            artifacts.Add(new EvidenceArtifact(
                Name: artifactName,
                ContentType: "application/sarif+json",
                Sha256Hash: artifactHash,
                RelativePath: $"evidence/{artifactName}"
            ));
            rawArtifactMap[artifactName] = artifactBytes;
        }

        var provenance = new ToolExecutionProvenance(
            ToolName: ToolName,
            ToolVersion: parsedVersion ?? version,
            Arguments: args,
            StartTimeUtc: startTime,
            EndTimeUtc: DateTimeOffset.UtcNow,
            ExitCode: procResult.ExitCode,
            Status: procResult.ExitCode == 0 ? "Success" : "Failed",
            ErrorMessage: procResult.ExitCode == 0 ? null : procResult.StandardError
        );

        return new AdapterExecutionResult(
            Provenance: provenance,
            Findings: findings,
            Artifacts: artifacts,
            RawArtifactBytes: rawArtifactMap
        );
    }

    public static (string RuleId, IReadOnlyList<string> TscCriteria) MapSemgrepRule(string semgrepRuleId)
    {
        var lower = semgrepRuleId.ToLowerInvariant();
        if (lower.Contains("md5") || lower.Contains("sha1") || lower.Contains("des") || lower.Contains("crypto") || lower.Contains("ecb") || lower.Contains("cipher"))
        {
            return ("SEC-002", ["CC6.1", "CC6.7"]);
        }
        if (lower.Contains("authorize") || lower.Contains("allowanonymous") || lower.Contains("auth"))
        {
            return ("SEC-003", ["CC6.1", "CC6.3"]);
        }
        if (lower.Contains("certificate") || lower.Contains("cert-validation") || lower.Contains("tls") || lower.Contains("ssl"))
        {
            return ("SEC-004", ["CC6.7"]);
        }
        if (lower.Contains("sql") || lower.Contains("sqli") || lower.Contains("concatenat"))
        {
            return ("SEC-005", ["CC6.1", "CC7.1"]);
        }
        if (lower.Contains("cors"))
        {
            return ("CFG-005", ["CC6.6"]);
        }

        return (semgrepRuleId, ["CC6.1"]);
    }
}