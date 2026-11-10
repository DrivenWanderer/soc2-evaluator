using Soc2Evaluator.Core.Models;

namespace Soc2Evaluator.Core.Services;

public interface IRemediationService
{
    /// <summary>
    /// Retrieves the remediation guidance template for the specified rule ID, if available.
    /// </summary>
    string? GetRemediationTemplate(string ruleId);

    /// <summary>
    /// Enriches a finding with concrete remediation instructions and code/config diffs from the remediation library.
    /// </summary>
    Finding EnrichWithRemediation(Finding finding);
}