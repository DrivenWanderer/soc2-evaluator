using System.Text.Json;
using System.Text.Json.Nodes;
using Soc2Evaluator.Core.Models;

namespace Soc2Evaluator.Adapters.Sarif;

public static class SarifParser
{
    public static (IReadOnlyList<Finding> Findings, string? ToolVersion) Parse(
        string sarifJson,
        string toolName,
        string defaultRuleId,
        IReadOnlyList<string> defaultTscCriteria,
        Func<string, (string RuleId, IReadOnlyList<string> TscCriteria)>? ruleMapper = null
    )
    {
        var findings = new List<Finding>();
        string? toolVersion = null;

        if (string.IsNullOrWhiteSpace(sarifJson))
        {
            return (findings, null);
        }

        using var doc = JsonDocument.Parse(sarifJson);
        var root = doc.RootElement;

        if (!root.TryGetProperty("runs", out var runs) || runs.ValueKind != JsonValueKind.Array)
        {
            return (findings, null);
        }

        foreach (var run in runs.EnumerateArray())
        {
            if (run.TryGetProperty("tool", out var tool) &&
                tool.TryGetProperty("driver", out var driver))
            {
                if (driver.TryGetProperty("version", out var verProp))
                {
                    toolVersion = verProp.GetString();
                }
            }

            if (!run.TryGetProperty("results", out var results) || results.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            var index = 1;
            foreach (var result in results.EnumerateArray())
            {
                string? scannerRuleId = null;
                if (result.TryGetProperty("ruleId", out var ruleIdProp) && !string.IsNullOrWhiteSpace(ruleIdProp.GetString()))
                {
                    scannerRuleId = ruleIdProp.GetString();
                }

                string ruleId;
                IReadOnlyList<string> tscCriteria;

                if (ruleMapper != null && !string.IsNullOrWhiteSpace(scannerRuleId))
                {
                    var mapped = ruleMapper(scannerRuleId);
                    ruleId = !string.IsNullOrWhiteSpace(mapped.RuleId) ? mapped.RuleId : defaultRuleId;
                    tscCriteria = mapped.TscCriteria.Count > 0 ? mapped.TscCriteria : defaultTscCriteria;
                }
                else
                {
                    ruleId = !string.IsNullOrWhiteSpace(defaultRuleId)
                        ? defaultRuleId
                        : (scannerRuleId ?? "UNKNOWN");
                    tscCriteria = defaultTscCriteria;
                }

                var message = "Security finding detected";
                if (result.TryGetProperty("message", out var msgProp) && msgProp.TryGetProperty("text", out var textProp))
                {
                    message = textProp.GetString() ?? message;
                }

                var title = !string.IsNullOrWhiteSpace(scannerRuleId) && scannerRuleId != ruleId
                    ? $"{message} ({scannerRuleId})"
                    : message;

                var severity = Severity.Medium;
                if (result.TryGetProperty("level", out var levelProp))
                {
                    severity = levelProp.GetString()?.ToLowerInvariant() switch
                    {
                        "error" => Severity.High,
                        "warning" => Severity.Medium,
                        "note" => Severity.Low,
                        _ => Severity.Medium
                    };
                }

                FindingLocation? location = null;
                var evidenceSnippet = string.Empty;

                if (result.TryGetProperty("locations", out var locations) &&
                    locations.ValueKind == JsonValueKind.Array &&
                    locations.GetArrayLength() > 0)
                {
                    var firstLoc = locations[0];
                    if (firstLoc.TryGetProperty("physicalLocation", out var phys))
                    {
                        string? filePath = null;
                        if (phys.TryGetProperty("artifactLocation", out var art) && art.TryGetProperty("uri", out var uriProp))
                        {
                            filePath = uriProp.GetString();
                        }

                        int? line = null;
                        int? col = null;

                        if (phys.TryGetProperty("region", out var region))
                        {
                            if (region.TryGetProperty("startLine", out var sl))
                            {
                                line = sl.GetInt32();
                            }
                            if (region.TryGetProperty("startColumn", out var sc))
                            {
                                col = sc.GetInt32();
                            }
                            if (region.TryGetProperty("snippet", out var snip) && snip.TryGetProperty("text", out var st))
                            {
                                evidenceSnippet = st.GetString() ?? string.Empty;
                            }
                        }

                        location = new FindingLocation(filePath, line, col);
                    }
                }

                // If snippet is empty or contains raw secret-like patterns, mask appropriately
                var redactedEvidence = RedactSecretSnippet(evidenceSnippet);
                var category = FindingCategory.Code;
                var fingerprint = Finding.ComputeFingerprint(ruleId, location, scannerRuleId);

                findings.Add(new Finding(
                    Id: $"{ruleId}-{index++:D3}",
                    RuleId: ruleId,
                    Title: title,
                    SourceName: toolName,
                    SourceVersion: toolVersion,
                    TscCriteria: tscCriteria,
                    OrgControlId: null,
                    Severity: severity,
                    Category: category,
                    Location: location,
                    RedactedEvidence: redactedEvidence,
                    RiskExplanation: $"Potential security issue identified by {toolName}: {message}",
                    RecommendedFix: "Review the referenced code or configuration, remove any hardcoded sensitive values, and store credentials securely.",
                    Effort: EffortEstimate.Low,
                    Confidence: ConfidenceLevel.High,
                    Fingerprint: fingerprint
                ));
            }
        }

        return (findings, toolVersion);
    }

    /// <summary>
    /// Scrubs raw secrets from SARIF snippet text before persisting as an evidence bundle artifact.
    /// </summary>
    public static string ScrubSarif(string sarifJson)
    {
        if (string.IsNullOrWhiteSpace(sarifJson)) return sarifJson;

        try
        {
            var node = JsonNode.Parse(sarifJson);
            if (node == null) return sarifJson;

            ScrubSnippetsRecursive(node);
            return node.ToJsonString(new JsonSerializerOptions { WriteIndented = true });
        }
        catch
        {
            return sarifJson;
        }
    }

    private static void ScrubSnippetsRecursive(JsonNode node)
    {
        if (node is JsonObject obj)
        {
            if (obj.TryGetPropertyValue("snippet", out var snipNode) && snipNode is JsonObject snipObj)
            {
                if (snipObj.TryGetPropertyValue("text", out var textNode) && textNode != null)
                {
                    var rawText = textNode.GetValue<string>();
                    snipObj["text"] = RedactSecretSnippet(rawText);
                }
            }

            foreach (var kvp in obj)
            {
                if (kvp.Value != null)
                {
                    ScrubSnippetsRecursive(kvp.Value);
                }
            }
        }
        else if (node is JsonArray arr)
        {
            foreach (var item in arr)
            {
                if (item != null)
                {
                    ScrubSnippetsRecursive(item);
                }
            }
        }
    }

    private static string RedactSecretSnippet(string snippet)
    {
        if (string.IsNullOrWhiteSpace(snippet))
        {
            return "[redacted evidence snippet]";
        }

        // Mask secret/password values if matched in key=value patterns
        var masked = System.Text.RegularExpressions.Regex.Replace(
            snippet,
            @"(?i)(password|secret|token|api[_-]?key|client[_-]?secret)\s*[:=]\s*[""']?([^\r\n""';\s]+)[""']?",
            "$1=********"
        );

        return masked;
    }
}