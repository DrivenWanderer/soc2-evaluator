using Soc2Evaluator.Core.Models;

namespace Soc2Evaluator.Core.Services;

public record SuppressionResult(
    IReadOnlyList<Finding> Findings,
    IReadOnlyList<SuppressionEntry> Suppressions
);

public interface ISuppressionService
{
    IReadOnlyList<SuppressionRule> LoadSuppressions(string? ignoreFilePathOrTargetDirectory);
    IReadOnlyList<SuppressionRule> ParseSuppressionsYaml(string yamlContent);
    SuppressionResult ApplySuppressions(IReadOnlyList<Finding> findings, IReadOnlyList<SuppressionRule> rules, DateTimeOffset? asOfDate = null);
}