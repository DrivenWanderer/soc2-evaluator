using System.Text;
using Soc2Evaluator.Adapters.Sarif;
using Soc2Evaluator.Core.Adapters;
using Soc2Evaluator.Core.Models;
using Soc2Evaluator.Core.Services;

namespace Soc2Evaluator.Adapters.Gitleaks;

public class GitleaksAdapter : IScannerAdapter
{
    private readonly IProcessRunner _processRunner;
    private readonly IEvidenceHasher _hasher;

    public string ToolName => "gitleaks";
    public string DefaultRulePrefix => "SEC-001";
    public string InstallGuidance => "Install gitleaks via 'winget install Gitleaks.Gitleaks' or download from https://github.com/gitleaks/gitleaks/releases";

    public GitleaksAdapter(IProcessRunner processRunner, IEvidenceHasher hasher)
    {
        _processRunner = processRunner;
        _hasher = hasher;
    }

    public async Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default)
    {
        if (!_processRunner.ExistsOnPath("gitleaks"))
        {
            return false;
        }

        try
        {
            var res = await _processRunner.RunAsync("gitleaks", ["version"], cancellationToken: cancellationToken);
            return res.ExitCode == 0;
        }
        catch
        {
            return false;
        }
    }

    public async Task<string?> GetVersionAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            var res = await _processRunner.RunAsync("gitleaks", ["version"], cancellationToken: cancellationToken);
            if (res.ExitCode == 0)
            {
                var output = res.StandardOutput.Trim();
                // If output starts with 'v', strip it
                return output.StartsWith('v') ? output[1..] : output;
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
        var tempReportPath = Path.Combine(Path.GetTempPath(), $"gitleaks-{Guid.NewGuid():N}.sarif");
        var args = new List<string>
        {
            "detect",
            "--source", context.TargetPath,
            "--no-git",
            "--report-format", "sarif",
            "--report-path", tempReportPath,
            "--exit-code", "0" // prevents gitleaks from exiting 1 on findings so we distinguish crashes from detections
        };

        ProcessResult procResult;
        try
        {
            procResult = await _processRunner.RunAsync("gitleaks", args, cancellationToken: cancellationToken);
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
        byte[] rawBytes = [];
        if (File.Exists(tempReportPath))
        {
            rawBytes = await File.ReadAllBytesAsync(tempReportPath, cancellationToken);
            sarifContent = Encoding.UTF8.GetString(rawBytes);
            try { File.Delete(tempReportPath); } catch { /* best effort cleanup */ }
        }

        var (findings, parsedVersion) = SarifParser.Parse(
            sarifContent,
            ToolName,
            DefaultRulePrefix,
            ["CC6.1"]
        );

        var finalVersion = version ?? parsedVersion;
        var rawArtifacts = new List<EvidenceArtifact>();
        var artifactMap = new Dictionary<string, byte[]>();

        if (rawBytes.Length > 0)
        {
            var hash = _hasher.ComputeSha256(rawBytes);
            var artifactName = "gitleaks.sarif";
            rawArtifacts.Add(new EvidenceArtifact(
                Name: artifactName,
                ContentType: "application/sarif+json",
                Sha256Hash: hash,
                RelativePath: $"evidence/{artifactName}"
            ));
            artifactMap[artifactName] = rawBytes;
        }

        var provenance = new ToolExecutionProvenance(
            ToolName: ToolName,
            ToolVersion: finalVersion,
            Arguments: args,
            StartTimeUtc: procResult.StartTimeUtc,
            EndTimeUtc: procResult.EndTimeUtc,
            ExitCode: procResult.ExitCode,
            Status: procResult.ExitCode == 0 ? "Success" : "Failed",
            ErrorMessage: procResult.ExitCode != 0 ? procResult.StandardError : null
        );

        return new AdapterExecutionResult(
            Provenance: provenance,
            Findings: findings,
            Artifacts: rawArtifacts,
            RawArtifactBytes: artifactMap
        );
    }
}