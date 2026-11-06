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
        IReadOnlyList<string> defaultTscCriteria
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

                var ruleId = !string.IsNullOrWhiteSpace(defaultRuleId)
                    ? defaultRuleId
                    : (scannerRuleId ?? "UNKNOWN");

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
                        if (phys.TryGetProperty("region", out var reg))
                        {
                            if (reg.TryGetProperty("startLine", out var sl)) line = sl.GetInt32();
                            if (reg.TryGetProperty("startColumn", out var sc)) col = sc.GetInt32();
                            if (reg.TryGetProperty("snippet", out var snip) && snip.TryGetProperty("text", out var snipText))
                            {
                                evidenceSnippet = snipText.GetString() ?? string.Empty;
                            }
                        }

                        location = new FindingLocation(filePath, line, col);
                    }
                }

                var findingId = $"{ruleId}-{index++}";
                var fingerprint = Finding.ComputeFingerprint(ruleId, location);

                findings.Add(new Finding(
                    Id: findingId,
                    RuleId: ruleId,
                    Title: title.Length > 100 ? title[..97] + "..." : title,
                    SourceName: toolName,
                    SourceVersion: toolVersion,
                    TscCriteria: defaultTscCriteria,
                    OrgControlId: null,
                    Severity: severity,
                    Category: FindingCategory.Code,
                    Location: location,
                    RedactedEvidence: RedactSensitiveContent(evidenceSnippet),
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
                if (snipObj.ContainsKey("text"))
                {
                    snipObj["text"] = "***[REDACTED]***";
                }
            }

            foreach (var property in obj)
            {
                if (property.Value != null)
                {
                    ScrubSnippetsRecursive(property.Value);
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

    private static string RedactSensitiveContent(string snippet)
    {
        if (string.IsNullOrWhiteSpace(snippet))
        {
            return "***[REDACTED]***";
        }

        // If the snippet is short, fully redact
        if (snippet.Length <= 8)
        {
            return "***[REDACTED]***";
        }

        // Keep first 3 chars, mask the rest
        var prefix = snippet[..3];
        return $"{prefix}***[REDACTED]***";
    }
}