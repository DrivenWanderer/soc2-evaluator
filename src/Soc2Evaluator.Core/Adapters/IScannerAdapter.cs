using Soc2Evaluator.Core.Models;

namespace Soc2Evaluator.Core.Adapters;

public record AdapterExecutionContext(
    string TargetPath,
    IReadOnlyList<string> InScopeCriteria,
    bool Offline = false
);

public record AdapterExecutionResult(
    ToolExecutionProvenance Provenance,
    IReadOnlyList<Finding> Findings,
    IReadOnlyList<EvidenceArtifact> Artifacts,
    IReadOnlyDictionary<string, byte[]> RawArtifactBytes
);

public interface IScannerAdapter
{
    string ToolName { get; }
    string DefaultRulePrefix { get; }
    string InstallGuidance { get; }

    Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default);
    Task<string?> GetVersionAsync(CancellationToken cancellationToken = default);
    Task<AdapterExecutionResult> ExecuteAsync(AdapterExecutionContext context, CancellationToken cancellationToken = default);
}