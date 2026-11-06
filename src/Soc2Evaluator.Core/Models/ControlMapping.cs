namespace Soc2Evaluator.Core.Models;

public record ControlMappingEntry(
    string RuleId,
    IReadOnlyList<string> TscCriteria,
    string? OrgControlId = null,
    string? Title = null,
    string? Description = null,
    FindingCategory? Category = null,
    Severity? DefaultSeverity = null,
    Severity? OverrideSeverity = null,
    bool Enabled = true,
    string? Justification = null,
    string? Notes = null
);

public record ControlMappingConfig(
    string Organization,
    string Version,
    string? Description,
    IReadOnlyList<ControlMappingEntry> Mappings
);