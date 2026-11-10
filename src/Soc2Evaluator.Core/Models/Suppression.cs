namespace Soc2Evaluator.Core.Models;

public record SuppressionRule(
    string? Fingerprint = null,
    string? RuleId = null,
    string? Scope = null,
    string Justification = "",
    string Approver = "",
    string Ticket = "",
    DateTimeOffset ExpiryDate = default
);

public record SuppressionEntry(
    string? Fingerprint,
    string? RuleId,
    string? Scope,
    string Justification,
    string Approver,
    string Ticket,
    DateTimeOffset ExpiryDate,
    bool IsExpired,
    IReadOnlyList<string> MatchedFindingIds
);