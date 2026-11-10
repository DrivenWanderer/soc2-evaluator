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
            var baseLoc = LineNumber.HasValue ? $"{FilePath}:{LineNumber}" : FilePath;
            return !string.IsNullOrWhiteSpace(SettingOrResource) ? $"{baseLoc} ({SettingOrResource})" : baseLoc;
        }

        return SettingOrResource ?? "Unknown";
    }
}

public record FindingSuppression(
    string Justification,
    string Approver,
    string Ticket,
    DateTimeOffset ExpiryDate,
    bool IsExpired = false
);

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
    FindingStatus Status = FindingStatus.Open,
    FindingSuppression? Suppression = null
)
{
    /// <summary>
    /// Computes a stable fingerprint for this finding across runs based on rule, location, and optional extra identity.
    /// </summary>
    public static string ComputeFingerprint(string ruleId, FindingLocation? location, string? extraIdentity = null)
    {
        var filePath = location?.FilePath;
        var settingOrResource = location?.SettingOrResource;

        var target = string.IsNullOrWhiteSpace(filePath)
            ? (settingOrResource ?? string.Empty)
            : (!string.IsNullOrWhiteSpace(settingOrResource)
                ? $"{filePath}:{settingOrResource}"
                : filePath);

        var extra = !string.IsNullOrWhiteSpace(extraIdentity) ? $":{extraIdentity}" : string.Empty;
        var raw = $"{ruleId}:{target}:{location?.LineNumber ?? 0}{extra}";
        var hash = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(hash).ToLowerInvariant();
    }
}