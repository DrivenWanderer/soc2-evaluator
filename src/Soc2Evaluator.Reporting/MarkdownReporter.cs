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
        sb.AppendLine($"| **Target** | `{manifest.Target}` |");
        sb.AppendLine($"| **Date (UTC)** | `{manifest.TimestampUtc:yyyy-MM-dd HH:mm:ss} UTC` |");
        sb.AppendLine($"| **Tool Version** | `v{manifest.ToolVersion}` |");
        sb.AppendLine($"| **Run ID** | `{manifest.RunId}` |");
        sb.AppendLine($"| **Commit SHA** | `{(string.IsNullOrWhiteSpace(manifest.CommitSha) ? "N/A" : manifest.CommitSha)}` |");
        sb.AppendLine($"| **Evidence Manifest SHA-256** | `{manifest.ManifestSha256 ?? "Unsigned"}` |");
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
        sb.AppendLine("| Criteria in Scope | Tools Executed | Checks Executed | Status |");
        sb.AppendLine("|---|---|---|---|");
        var toolsSummary = manifest.ToolProvenance.Count > 0
            ? string.Join(", ", manifest.ToolProvenance.Select(p => p.ToolName))
            : "Native Only";
        var criteriaSummary = manifest.CriteriaInScope.Count > 0
            ? string.Join(", ", manifest.CriteriaInScope)
            : "Security (Common Criteria)";
        sb.AppendLine($"| {criteriaSummary} | {toolsSummary} | {findings.Count} findings evaluated | Evaluated |");
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
                sb.AppendLine($"### [{finding.Severity}] {finding.Id}: {finding.Title}");
                sb.AppendLine();
                sb.AppendLine($"- **Rule ID:** `{finding.RuleId}`");
                sb.AppendLine($"- **Category:** `{finding.Category}`");
                sb.AppendLine($"- **TSC Criteria:** {string.Join(", ", finding.TscCriteria)}");
                if (!string.IsNullOrWhiteSpace(finding.OrgControlId))
                {
                    sb.AppendLine($"- **Org Control ID:** `{finding.OrgControlId}`");
                }
                sb.AppendLine($"- **Source:** {finding.SourceName} {(string.IsNullOrWhiteSpace(finding.SourceVersion) ? string.Empty : $"v{finding.SourceVersion}")}");
                sb.AppendLine($"- **Location:** `{finding.Location?.ToString() ?? "N/A"}`");
                sb.AppendLine($"- **Confidence:** {finding.Confidence} | **Effort:** {finding.Effort}");
                sb.AppendLine($"- **Fingerprint:** `{finding.Fingerprint}`");
                sb.AppendLine();
                sb.AppendLine("**Risk Explanation:**");
                sb.AppendLine(finding.RiskExplanation);
                sb.AppendLine();
                if (!string.IsNullOrWhiteSpace(finding.RedactedEvidence))
                {
                    sb.AppendLine("**Redacted Evidence:**");
                    sb.AppendLine("```");
                    sb.AppendLine(finding.RedactedEvidence);
                    sb.AppendLine("```");
                    sb.AppendLine();
                }
                sb.AppendLine("**Recommended Remediation:**");
                sb.AppendLine(finding.RecommendedFix);
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
                sb.AppendLine($"| {p.ToolName} | {p.ToolVersion ?? "Unknown"} | {p.Status} | {p.ExitCode?.ToString() ?? "N/A"} | `{argsStr}` |");
            }
        }
        sb.AppendLine();

        return Task.FromResult(sb.ToString());
    }
}