using Soc2Evaluator.Core.Models;

namespace Soc2Evaluator.Core.Services;

public record EvaluationRequest(
    string TargetPath,
    IReadOnlyList<string> Criteria,
    string OutputPath,
    IReadOnlyList<string> Formats,
    string? CommitSha = null,
    string? FailOnSeverity = null,
    bool Offline = false,
    string? OrgConfigPath = null,
    string? BaselinePath = null,
    string? IgnoreFilePath = null
);

public interface IEvaluationOrchestrator
{
    Task<EvidenceBundle> RunEvaluationAsync(EvaluationRequest request, CancellationToken cancellationToken = default);
}