using System.Globalization;
using System.Text.RegularExpressions;
using Soc2Evaluator.Core.Models;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Soc2Evaluator.Core.Services;

public class SuppressionService : ISuppressionService
{
    private readonly IDeserializer _yamlDeserializer;

    public SuppressionService()
    {
        _yamlDeserializer = new DeserializerBuilder()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();
    }

    public IReadOnlyList<SuppressionRule> LoadSuppressions(string? ignoreFilePathOrTargetDirectory)
    {
        if (string.IsNullOrWhiteSpace(ignoreFilePathOrTargetDirectory))
        {
            return Array.Empty<SuppressionRule>();
        }

        string resolvedPath;
        if (Directory.Exists(ignoreFilePathOrTargetDirectory))
        {
            var yamlPath = Path.Combine(ignoreFilePathOrTargetDirectory, ".soc2ignore.yml");
            if (!File.Exists(yamlPath))
            {
                yamlPath = Path.Combine(ignoreFilePathOrTargetDirectory, ".soc2ignore.yaml");
            }

            if (!File.Exists(yamlPath))
            {
                return Array.Empty<SuppressionRule>();
            }

            resolvedPath = yamlPath;
        }
        else if (File.Exists(ignoreFilePathOrTargetDirectory))
        {
            resolvedPath = ignoreFilePathOrTargetDirectory;
        }
        else
        {
            return Array.Empty<SuppressionRule>();
        }

        var yaml = File.ReadAllText(resolvedPath);
        return ParseSuppressionsYaml(yaml);
    }

    public IReadOnlyList<SuppressionRule> ParseSuppressionsYaml(string yamlContent)
    {
        if (string.IsNullOrWhiteSpace(yamlContent))
        {
            return Array.Empty<SuppressionRule>();
        }

        List<Dictionary<string, object?>> rawEntries = new();

        try
        {
            // Try deserializing as object with suppressions property
            var rootDict = _yamlDeserializer.Deserialize<Dictionary<string, object?>>(yamlContent);
            if (rootDict != null)
            {
                var suppressionsKey = rootDict.Keys.FirstOrDefault(k =>
                    string.Equals(k, "suppressions", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(k, "ignore", StringComparison.OrdinalIgnoreCase));

                if (suppressionsKey != null && rootDict[suppressionsKey] is IEnumerable<object> list)
                {
                    foreach (var item in list)
                    {
                        if (item is Dictionary<object, object> d)
                        {
                            rawEntries.Add(d.ToDictionary(k => k.Key.ToString()!, v => (object?)v.Value));
                        }
                        else if (item is Dictionary<string, object?> sd)
                        {
                            rawEntries.Add(sd);
                        }
                    }
                }
            }
        }
        catch
        {
            // Fallback: try top-level list
            try
            {
                var list = _yamlDeserializer.Deserialize<List<Dictionary<string, object?>>>(yamlContent);
                if (list != null)
                {
                    rawEntries.AddRange(list);
                }
            }
            catch
            {
                // Rethrow or return empty
                throw;
            }
        }

        var results = new List<SuppressionRule>();

        foreach (var entry in rawEntries)
        {
            var rule = ParseRule(entry);
            results.Add(rule);
        }

        return results;
    }

    private static SuppressionRule ParseRule(Dictionary<string, object?> dict)
    {
        string? GetVal(params string[] keys)
        {
            foreach (var k in keys)
            {
                var match = dict.FirstOrDefault(kv => string.Equals(kv.Key, k, StringComparison.OrdinalIgnoreCase));
                if (match.Key != null && match.Value != null)
                {
                    var s = match.Value.ToString()?.Trim();
                    if (!string.IsNullOrWhiteSpace(s))
                    {
                        return s;
                    }
                }
            }
            return null;
        }

        var fingerprint = GetVal("fingerprint", "fp", "hash");
        var ruleId = GetVal("rule_id", "rule", "check_id", "check");
        var scope = GetVal("scope", "path", "file");
        var justification = GetVal("justification", "reason", "rationale");
        var approver = GetVal("approver", "approved_by", "owner");
        var ticket = GetVal("ticket", "ticket_id", "reference", "ref", "issue");
        var expiresRaw = GetVal("expires", "expiry", "expiry_date", "expiration", "valid_until");

        if (string.IsNullOrWhiteSpace(fingerprint) && string.IsNullOrWhiteSpace(ruleId))
        {
            throw new FormatException("A suppression rule must specify either a 'fingerprint' or a 'rule' ID.");
        }

        if (string.IsNullOrWhiteSpace(justification))
        {
            throw new FormatException("A suppression rule must include a non-empty 'justification'.");
        }

        if (string.IsNullOrWhiteSpace(approver))
        {
            throw new FormatException("A suppression rule must include an 'approver'.");
        }

        if (string.IsNullOrWhiteSpace(ticket))
        {
            throw new FormatException("A suppression rule must include a 'ticket' or reference ID.");
        }

        if (string.IsNullOrWhiteSpace(expiresRaw))
        {
            throw new FormatException("A suppression rule must include an 'expires' date.");
        }

        if (!DateTimeOffset.TryParse(expiresRaw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var expiryDate))
        {
            if (!DateTime.TryParse(expiresRaw, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal, out var dt))
            {
                throw new FormatException($"Invalid expiry date format in suppression: '{expiresRaw}'. Expected ISO 8601 date (e.g. YYYY-MM-DD).");
            }
            expiryDate = new DateTimeOffset(dt, TimeSpan.Zero);
        }

        return new SuppressionRule(
            Fingerprint: fingerprint,
            RuleId: ruleId,
            Scope: scope,
            Justification: justification,
            Approver: approver,
            Ticket: ticket,
            ExpiryDate: expiryDate
        );
    }

    public SuppressionResult ApplySuppressions(IReadOnlyList<Finding> findings, IReadOnlyList<SuppressionRule> rules, DateTimeOffset? asOfDate = null)
    {
        var effectiveDate = asOfDate ?? DateTimeOffset.UtcNow;
        var ruleMatchMap = new Dictionary<SuppressionRule, List<string>>();
        foreach (var r in rules)
        {
            ruleMatchMap[r] = new List<string>();
        }

        var processedFindings = new List<Finding>();

        foreach (var finding in findings)
        {
            var matchedRule = rules.FirstOrDefault(r => MatchesFinding(r, finding));

            if (matchedRule != null)
            {
                ruleMatchMap[matchedRule].Add(finding.Id);

                var isExpired = effectiveDate > matchedRule.ExpiryDate;
                if (isExpired)
                {
                    // Expired suppressions re-open the finding automatically
                    var note = $"\n[Suppression expired on {matchedRule.ExpiryDate:yyyy-MM-dd} (Approver: {matchedRule.Approver}, Ticket: {matchedRule.Ticket}); finding re-opened.]";
                    var updatedRisk = finding.RiskExplanation.Contains("[Suppression expired")
                        ? finding.RiskExplanation
                        : finding.RiskExplanation + note;

                    processedFindings.Add(finding with
                    {
                        Status = FindingStatus.Open,
                        RiskExplanation = updatedRisk,
                        Suppression = new FindingSuppression(
                            Justification: matchedRule.Justification,
                            Approver: matchedRule.Approver,
                            Ticket: matchedRule.Ticket,
                            ExpiryDate: matchedRule.ExpiryDate,
                            IsExpired: true
                        )
                    });
                }
                else
                {
                    // Active suppression: accepted risk
                    processedFindings.Add(finding with
                    {
                        Status = FindingStatus.Suppressed,
                        Suppression = new FindingSuppression(
                            Justification: matchedRule.Justification,
                            Approver: matchedRule.Approver,
                            Ticket: matchedRule.Ticket,
                            ExpiryDate: matchedRule.ExpiryDate,
                            IsExpired: false
                        )
                    });
                }
            }
            else
            {
                processedFindings.Add(finding);
            }
        }

        var suppressionEntries = rules.Select(r => new SuppressionEntry(
            Fingerprint: r.Fingerprint,
            RuleId: r.RuleId,
            Scope: r.Scope,
            Justification: r.Justification,
            Approver: r.Approver,
            Ticket: r.Ticket,
            ExpiryDate: r.ExpiryDate,
            IsExpired: effectiveDate > r.ExpiryDate,
            MatchedFindingIds: ruleMatchMap[r]
        )).ToList();

        return new SuppressionResult(processedFindings, suppressionEntries);
    }

    private static bool MatchesFinding(SuppressionRule rule, Finding finding)
    {
        // 1. If fingerprint is specified, it takes priority and must match
        if (!string.IsNullOrWhiteSpace(rule.Fingerprint))
        {
            return string.Equals(rule.Fingerprint.Trim(), finding.Fingerprint.Trim(), StringComparison.OrdinalIgnoreCase);
        }

        // 2. If ruleId is specified, it must match
        if (!string.IsNullOrWhiteSpace(rule.RuleId))
        {
            if (!string.Equals(rule.RuleId.Trim(), finding.RuleId.Trim(), StringComparison.OrdinalIgnoreCase))
            {
                return false;
            }
        }

        // 3. If scope is specified, it must match file path or setting
        if (!string.IsNullOrWhiteSpace(rule.Scope))
        {
            var filePath = finding.Location?.FilePath;
            var setting = finding.Location?.SettingOrResource;

            var matchesFile = !string.IsNullOrWhiteSpace(filePath) && MatchesScope(filePath, rule.Scope);
            var matchesSetting = !string.IsNullOrWhiteSpace(setting) && MatchesScope(setting, rule.Scope);

            if (!matchesFile && !matchesSetting)
            {
                return false;
            }
        }

        return true;
    }

    public static bool MatchesScope(string target, string scope)
    {
        if (string.IsNullOrWhiteSpace(target))
        {
            return false;
        }

        if (string.IsNullOrWhiteSpace(scope) || scope == "*" || scope == "**")
        {
            return true;
        }

        var normalizedTarget = target.Replace('\\', '/').TrimStart('/');
        var normalizedScope = scope.Replace('\\', '/').TrimStart('/');

        if (string.Equals(normalizedTarget, normalizedScope, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // Wildcard glob conversion to regex
        var pattern = "^" + Regex.Escape(normalizedScope)
            .Replace(@"\*\*", ".*")
            .Replace(@"\*", @"[^/]*")
            .Replace(@"\?", ".") + "$";

        if (Regex.IsMatch(normalizedTarget, pattern, RegexOptions.IgnoreCase))
        {
            return true;
        }

        // Match suffix/subdirectory (e.g., target is "tests/fixtures/vulnerable-app/web.config", scope is "web.config")
        if (normalizedTarget.EndsWith("/" + normalizedScope, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        // Match directory prefix (e.g. scope is "tests" or "tests/", target is "tests/clean-app/file.cs")
        var scopePrefix = normalizedScope.TrimEnd('/') + "/";
        if (normalizedTarget.StartsWith(scopePrefix, StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        return false;
    }
}