using System.Text;
using System.Text.Json;
using Soc2Evaluator.Core.Adapters;
using Soc2Evaluator.Core.Models;
using Soc2Evaluator.Core.Services;

namespace Soc2Evaluator.Rules;

public class RulesScannerAdapter : IScannerAdapter
{
    private readonly IEnumerable<IRuleCheck> _checks;
    private readonly IEvidenceHasher _hasher;

    public string ToolName => "Soc2Evaluator.Rules";
    public string DefaultRulePrefix => "CFG-002";
    public string InstallGuidance => "In-box custom rules engine (no installation required).";

    public RulesScannerAdapter(IEnumerable<IRuleCheck> checks, IEvidenceHasher hasher)
    {
        _checks = checks;
        _hasher = hasher;
    }

    public Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default) => Task.FromResult(true);

    public Task<string?> GetVersionAsync(CancellationToken cancellationToken = default) => Task.FromResult<string?>("0.1.0");

    public async Task<AdapterExecutionResult> ExecuteAsync(AdapterExecutionContext context, CancellationToken cancellationToken = default)
    {
        var startTime = DateTimeOffset.UtcNow;
        var allFindings = new List<Finding>();

        foreach (var check in _checks)
        {
            var findings = await check.EvaluateAsync(context.TargetPath, cancellationToken);
            allFindings.AddRange(findings);
        }

        var endTime = DateTimeOffset.UtcNow;

        var artifacts = new List<EvidenceArtifact>();
        var artifactBytes = new Dictionary<string, byte[]>();

        var summaryJson = JsonSerializer.Serialize(new
        {
            Engine = "Soc2Evaluator.Rules",
            Version = "0.1.0",
            EvaluatedPath = context.TargetPath,
            ChecksRun = _checks.Select(c => c.RuleId).ToList(),
            FindingsCount = allFindings.Count,
            TimestampUtc = endTime
        }, new JsonSerializerOptions { WriteIndented = true });

        var bytes = Encoding.UTF8.GetBytes(summaryJson);
        var hash = _hasher.ComputeSha256(bytes);
        var artifactName = "rules-engine-summary.json";
        artifacts.Add(new EvidenceArtifact(artifactName, "application/json", hash, $"evidence/{artifactName}"));
        artifactBytes[artifactName] = bytes;

        var provenance = new ToolExecutionProvenance(
            ToolName: ToolName,
            ToolVersion: "0.1.0",
            Arguments: ["in-process-rules-evaluation"],
            StartTimeUtc: startTime,
            EndTimeUtc: endTime,
            ExitCode: 0,
            Status: "Success",
            ErrorMessage: null
        );

        return new AdapterExecutionResult(provenance, allFindings, artifacts, artifactBytes);
    }
}