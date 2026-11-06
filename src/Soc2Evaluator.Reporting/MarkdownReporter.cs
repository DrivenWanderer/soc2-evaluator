using System.Text;
using Soc2Evaluator.Core.Models;

namespace Soc2Evaluator.Reporting;

public class MarkdownReporter : IReporter
{
    public string FormatName => "md";
    public string OutputFileName => "report.md";

    public Task<string> RenderAsync(EvidenceManifest manifest, CancellationToken cancellationToken = default)
    {
        var sb = new StringBuilder();

        // 1. Header
        sb.AppendLine("# SOC 2 Readiness Assessment Report");
        sb.AppendLine();
        sb.AppendLine("| Parameter | Value |");
        sb.AppendLine("|---|---|");
        sb.AppendLine($"| **Target** | `{MarkdownSanitizer.EscapeTableCell(manifest.Target)}` |");
        sb.AppendLine($"| **Date (UTC)** | `{manifest.TimestampUtc:yyyy-MM-dd HH:mm:ss} UTC` |");
        sb.AppendLine($"| **Tool Version** | `v{MarkdownSanitizer.EscapeTableCell(manifest.ToolVersion)}` |");
        sb.AppendLine($"| **Run ID** | `{MarkdownSanitizer.EscapeTableCell(manifest.RunId)}` |");
        sb.AppendLine($"| **Commit SHA** | `{(string.IsNullOrWhiteSpace(manifest.CommitSha) ? "N/A" : MarkdownSanitizer.EscapeTableCell(manifest.CommitSha))}` |");
        sb.AppendLine($"| **Integrity Checksum (SHA-256)** | `{MarkdownSanitizer.EscapeTableCell(manifest.ManifestSha256 ?? "Unsigned")}` |");
        sb.AppendLine();

        // 2. Disclaimer
        sb.AppendLine("## Disclaimer");
        sb.AppendLine();
        sb.AppendLine("> **IMPORTANT:** SOC 2 is an independent attestation issued exclusively by a licensed CPA firm.");
        sb.AppendLine("> This tool is a **readiness assessment and evidence-gathering aid**. This report does not certify");
        sb.AppendLine("> compliance, nor does it state or imply that any target system is compliant. All items herein represent");
        sb.AppendLine("> automated findings evaluated against an organization-configurable control mapping.");
        sb.AppendLine();

        // 3. Executive Summary
        sb.AppendLine("## Executive Summary");
        sb.AppendLine();
        var findings = manifest.Findings;
        var criticalCount = findings.Count(f => f.Severity == Severity.Critical);
        var highCount = findings.Count(f => f.Severity == Severity.High);
        var mediumCount = findings.Count(f => f.Severity == Severity.Medium);
        var lowCount = findings.Count(f => f.Severity == Severity.Low);
        var infoCount = findings.Count(f => f.Severity == Severity.Informational);

        var codeCount = findings.Count(f => f.Category == FindingCategory.Code);
        var configCount = findings.Count(f => f.Category == FindingCategory.Configuration);
        var processCount = findings.Count(f => f.Category == FindingCategory.Process);

        sb.AppendLine($"**Total Findings:** {findings.Count}");
        sb.AppendLine();
        sb.AppendLine("| Severity | Count | Category | Count |");
        sb.AppendLine("|---|---|---|---|");
        sb.AppendLine($"| Critical | {criticalCount} | Code | {codeCount} |");
        sb.AppendLine($"| High | {highCount} | Configuration | {configCount} |");
        sb.AppendLine($"| Medium | {mediumCount} | Process | {processCount} |");
        sb.AppendLine($"| Low | {lowCount} | - | - |");
        sb.AppendLine($"| Informational | {infoCount} | - | - |");
        sb.AppendLine();

        // 4. Coverage Table
        sb.AppendLine("## Coverage Table");
        sb.AppendLine();
        sb.AppendLine("| Scanner / Source | Criteria in Scope | Status | Coverage Details |");
        sb.AppendLine("|---|---|---|---|");

        if (manifest.ToolProvenance.Count == 0)
        {
            var criteriaStr = manifest.CriteriaInScope.Count > 0 ? string.Join(", ", manifest.CriteriaInScope) : "Security";
            sb.AppendLine($"| Native Evaluator | {MarkdownSanitizer.EscapeTableCell(criteriaStr)} | Evaluated | {findings.Count} finding(s) evaluated |");
        }
        else
        {
            foreach (var prov in manifest.ToolProvenance)
            {
                var toolFindings = findings.Count(f => string.Equals(f.SourceName, prov.ToolName, StringComparison.OrdinalIgnoreCase));
                var criteriaStr = manifest.CriteriaInScope.Count > 0 ? string.Join(", ", manifest.CriteriaInScope) : "CC6.1";

                var statusText = prov.Status switch
                {
                    "Success" => "Evaluated",
                    "NotRun" => "Not Run",
                    "Failed" => "Failed",
                    _ => prov.Status
                };

                var detailText = prov.Status switch
                {
                    "Success" => $"{toolFindings} finding(s) evaluated",
                    "NotRun" => string.IsNullOrWhiteSpace(prov.ErrorMessage) ? "Tool missing or skipped" : prov.ErrorMessage,
                    "Failed" => string.IsNullOrWhiteSpace(prov.ErrorMessage) ? "Tool execution failed" : prov.ErrorMessage,
                    _ => "N/A"
                };

                sb.AppendLine($"| {MarkdownSanitizer.EscapeTableCell(prov.ToolName)} | {MarkdownSanitizer.EscapeTableCell(criteriaStr)} | {MarkdownSanitizer.EscapeTableCell(statusText)} | {MarkdownSanitizer.EscapeTableCell(detailText)} |");
            }
        }
        sb.AppendLine();

        // 5. Findings
        sb.AppendLine("## Findings");
        sb.AppendLine();
        if (findings.Count == 0)
        {
            sb.AppendLine("No findings identified against the evaluated criteria.");
            sb.AppendLine();
        }
        else
        {
            foreach (var finding in findings.OrderByDescending(f => f.Severity))
            {
                var safeTitle = MarkdownSanitizer.EscapeMarkdown(finding.Title);
                var safeId = MarkdownSanitizer.EscapeMarkdown(finding.Id);
                sb.AppendLine($"### [{finding.Severity}] {safeId}: {safeTitle}");
                sb.AppendLine();
                sb.AppendLine($"- **Rule ID:** `{MarkdownSanitizer.EscapeMarkdown(finding.RuleId)}`");
                sb.AppendLine($"- **Category:** `{finding.Category}`");
                sb.AppendLine($"- **TSC Criteria:** {string.Join(", ", finding.TscCriteria.Select(MarkdownSanitizer.EscapeMarkdown))}");
                if (!string.IsNullOrWhiteSpace(finding.OrgControlId))
                {
                    sb.AppendLine($"- **Org Control ID:** `{MarkdownSanitizer.EscapeMarkdown(finding.OrgControlId)}`");
                }
                sb.AppendLine($"- **Source:** {MarkdownSanitizer.EscapeMarkdown(finding.SourceName)} {(string.IsNullOrWhiteSpace(finding.SourceVersion) ? string.Empty : $"v{MarkdownSanitizer.EscapeMarkdown(finding.SourceVersion)}")}");
                sb.AppendLine($"- **Location:** `{MarkdownSanitizer.EscapeMarkdown(finding.Location?.ToString() ?? "N/A")}`");
                sb.AppendLine($"- **Confidence:** {finding.Confidence} | **Effort:** {finding.Effort}");
                sb.AppendLine($"- **Fingerprint:** `{finding.Fingerprint}`");
                sb.AppendLine();
                sb.AppendLine("**Risk Explanation:**");
                sb.AppendLine(MarkdownSanitizer.EscapeMarkdown(finding.RiskExplanation));
                sb.AppendLine();
                if (!string.IsNullOrWhiteSpace(finding.RedactedEvidence))
                {
                    sb.AppendLine("**Redacted Evidence:**");
                    sb.AppendLine("```");
                    // Inside fenced code blocks, avoid triple-backtick escape collisions
                    sb.AppendLine(finding.RedactedEvidence.Replace("```", "'''"));
                    sb.AppendLine("```");
                    sb.AppendLine();
                }
                sb.AppendLine("**Recommended Remediation:**");
                sb.AppendLine(MarkdownSanitizer.EscapeMarkdown(finding.RecommendedFix));
                sb.AppendLine();
                sb.AppendLine("---");
                sb.AppendLine();
            }
        }

        // 6. Tool Provenance Appendix
        sb.AppendLine("## Appendix: Tool Provenance and Execution");
        sb.AppendLine();
        if (manifest.ToolProvenance.Count == 0)
        {
            sb.AppendLine("No external scanner adapters were executed during this run.");
        }
        else
        {
            sb.AppendLine("| Tool | Version | Status | Exit Code | Arguments |");
            sb.AppendLine("|---|---|---|---|---|");
            foreach (var p in manifest.ToolProvenance)
            {
                var argsStr = p.Arguments.Count > 0 ? string.Join(" ", p.Arguments) : "none";
                sb.AppendLine($"| {MarkdownSanitizer.EscapeTableCell(p.ToolName)} | {MarkdownSanitizer.EscapeTableCell(p.ToolVersion ?? "Unknown")} | {MarkdownSanitizer.EscapeTableCell(p.Status)} | {p.ExitCode?.ToString() ?? "N/A"} | `{MarkdownSanitizer.EscapeTableCell(argsStr)}` |");
            }
        }
        sb.AppendLine();

        return Task.FromResult(sb.ToString());
    }
}