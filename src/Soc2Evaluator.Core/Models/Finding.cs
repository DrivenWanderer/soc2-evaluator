using System.Security.Cryptography;
using System.Text;

namespace Soc2Evaluator.Core.Models;

public enum Severity
{
    Informational,
    Low,
    Medium,
    High,
    Critical
}

public enum FindingCategory
{
    Code,
    Configuration,
    Process
}

public enum FindingStatus
{
    Open,
    Suppressed,
    Resolved
}

public enum ConfidenceLevel
{
    Low,
    Medium,
    High
}

public enum EffortEstimate
{
    Low,
    Medium,
    High
}

public record FindingLocation(
    string? FilePath = null,
    int? LineNumber = null,
    int? ColumnNumber = null,
    string? SettingOrResource = null
)
{
    public override string ToString()
    {
        if (!string.IsNullOrWhiteSpace(FilePath))
        {
            return LineNumber.HasValue ? $"{FilePath}:{LineNumber}" : FilePath;
        }

        return SettingOrResource ?? "Unknown";
    }
}

public record Finding(
    string Id,
    string RuleId,
    string Title,
    string SourceName,
    string? SourceVersion,
    IReadOnlyList<string> TscCriteria,
    string? OrgControlId,
    Severity Severity,
    FindingCategory Category,
    FindingLocation? Location,
    string RedactedEvidence,
    string RiskExplanation,
    string RecommendedFix,
    EffortEstimate Effort,
    ConfidenceLevel Confidence,
    string Fingerprint,
    FindingStatus Status = FindingStatus.Open
)
{
    /// <summary>
    /// Computes a stable fingerprint for this finding across runs based on rule and location.
    /// </summary>
    public static string ComputeFingerprint(string ruleId, FindingLocation? location)
    {
        var raw = $"{ruleId}:{location?.FilePath ?? location?.SettingOrResource ?? string.Empty}:{location?.LineNumber ?? 0}";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}