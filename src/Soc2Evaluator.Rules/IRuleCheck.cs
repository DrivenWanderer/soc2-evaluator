using Soc2Evaluator.Core.Models;

namespace Soc2Evaluator.Rules;

public interface IRuleCheck
{
    string RuleId { get; }
    string Title { get; }
    IReadOnlyList<string> TscCriteria { get; }
    Task<IReadOnlyList<Finding>> EvaluateAsync(string targetPath, CancellationToken cancellationToken = default);
}