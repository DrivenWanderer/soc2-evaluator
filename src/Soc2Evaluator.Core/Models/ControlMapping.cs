namespace Soc2Evaluator.Core.Models;

public record ControlMappingEntry(
    string RuleId,
    IReadOnlyList<string> TscCriteria,
    string? OrgControlId = null,
    string? Description = null,
    bool Enabled = true,
    string? OverrideSeverity = null,
    string? Justification = null
);

public record ControlMappingConfig(
    string OrganizationName,
    string Version,
    IReadOnlyList<ControlMappingEntry> Mappings
);