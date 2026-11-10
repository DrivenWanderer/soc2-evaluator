using Soc2Evaluator.Core.Models;
using Soc2Evaluator.Core.Services;
using Soc2Evaluator.Reporting;
using Xunit;

namespace Soc2Evaluator.Tests;

public class SuppressionTests
{
    private readonly SuppressionService _service = new();

    [Fact]
    public void ParseSuppressionsYaml_ValidYaml_ParsesRulesCorrectly()
    {
        var yaml = """
            suppressions:
              - fingerprint: "abc123456789"
                justification: "Accepted risk for staging test keys"
                approver: "security-lead@example.com"
                ticket: "SEC-101"
                expires: "2027-01-01"
              - rule: "CFG-002"
                scope: "src/LegacyApp/**"
                justification: "Legacy system behind VPN only"
                approver: "ciso@example.com"
                ticket: "GRC-202"
                expires: "2026-12-31"
            """;

        var rules = _service.ParseSuppressionsYaml(yaml);

        Assert.Equal(2, rules.Count);
        Assert.Equal("abc123456789", rules[0].Fingerprint);
        Assert.Equal("Accepted risk for staging test keys", rules[0].Justification);
        Assert.Equal("security-lead@example.com", rules[0].Approver);
        Assert.Equal("SEC-101", rules[0].Ticket);
        Assert.Equal(new DateTimeOffset(2027, 1, 1, 0, 0, 0, TimeSpan.Zero), rules[0].ExpiryDate);

        Assert.Equal("CFG-002", rules[1].RuleId);
        Assert.Equal("src/LegacyApp/**", rules[1].Scope);
    }

    [Theory]
    [InlineData("suppressions:\n  - rule: CFG-002\n    approver: user\n    ticket: T-1\n    expires: 2026-12-31")] // Missing justification
    [InlineData("suppressions:\n  - rule: CFG-002\n    justification: reason\n    ticket: T-1\n    expires: 2026-12-31")] // Missing approver
    [InlineData("suppressions:\n  - rule: CFG-002\n    justification: reason\n    approver: user\n    expires: 2026-12-31")] // Missing ticket
    [InlineData("suppressions:\n  - rule: CFG-002\n    justification: reason\n    approver: user\n    ticket: T-1")] // Missing expires
    [InlineData("suppressions:\n  - justification: reason\n    approver: user\n    ticket: T-1\n    expires: 2026-12-31")] // Missing both rule and fingerprint
    public void ParseSuppressionsYaml_MissingRequiredFields_ThrowsFormatException(string invalidYaml)
    {
        Assert.Throws<FormatException>(() => _service.ParseSuppressionsYaml(invalidYaml));
    }

    [Fact]
    public void ApplySuppressions_ActiveSuppressionByFingerprint_SetsStatusSuppressed()
    {
        var finding = CreateTestFinding("F-1", "SEC-001", "fp-target-1", "src/App/Program.cs");
        var rule = new SuppressionRule(
            Fingerprint: "fp-target-1",
            Justification: "Test credential",
            Approver: "sec-eng@example.com",
            Ticket: "SEC-999",
            ExpiryDate: DateTimeOffset.UtcNow.AddDays(30)
        );

        var result = _service.ApplySuppressions([finding], [rule]);

        Assert.Single(result.Findings);
        var suppressed = result.Findings[0];
        Assert.Equal(FindingStatus.Suppressed, suppressed.Status);
        Assert.NotNull(suppressed.Suppression);
        Assert.False(suppressed.Suppression.IsExpired);
        Assert.Equal("sec-eng@example.com", suppressed.Suppression.Approver);

        Assert.Single(result.Suppressions);
        Assert.False(result.Suppressions[0].IsExpired);
        Assert.Contains("F-1", result.Suppressions[0].MatchedFindingIds);
    }

    [Fact]
    public void ApplySuppressions_ActiveSuppressionByRuleAndScope_SetsStatusSuppressed()
    {
        var finding1 = CreateTestFinding("F-1", "CFG-002", "fp-1", "tests/fixtures/web.config");
        var finding2 = CreateTestFinding("F-2", "CFG-002", "fp-2", "src/Core/web.config");

        var rule = new SuppressionRule(
            RuleId: "CFG-002",
            Scope: "tests/**",
            Justification: "Test fixture allows debug",
            Approver: "lead@example.com",
            Ticket: "QA-42",
            ExpiryDate: DateTimeOffset.UtcNow.AddDays(60)
        );

        var result = _service.ApplySuppressions([finding1, finding2], [rule]);

        Assert.Equal(2, result.Findings.Count);
        Assert.Equal(FindingStatus.Suppressed, result.Findings[0].Status);
        Assert.Equal(FindingStatus.Open, result.Findings[1].Status);

        Assert.Single(result.Suppressions[0].MatchedFindingIds);
        Assert.Equal("F-1", result.Suppressions[0].MatchedFindingIds[0]);
    }

    [Fact]
    public void ApplySuppressions_ExpiredSuppression_ReopensFindingAsOpen()
    {
        var finding = CreateTestFinding("F-1", "SEC-001", "fp-expired", "src/App/Program.cs");
        var pastDate = DateTimeOffset.UtcNow.AddDays(-5);
        var rule = new SuppressionRule(
            Fingerprint: "fp-expired",
            Justification: "Temporary exception during migration",
            Approver: "sec-team@example.com",
            Ticket: "MIG-500",
            ExpiryDate: pastDate
        );

        var result = _service.ApplySuppressions([finding], [rule]);

        Assert.Single(result.Findings);
        var reopened = result.Findings[0];
        Assert.Equal(FindingStatus.Open, reopened.Status);
        Assert.NotNull(reopened.Suppression);
        Assert.True(reopened.Suppression.IsExpired);
        Assert.Contains("expired", reopened.RiskExplanation, StringComparison.OrdinalIgnoreCase);

        Assert.Single(result.Suppressions);
        Assert.True(result.Suppressions[0].IsExpired);
        Assert.Contains("F-1", result.Suppressions[0].MatchedFindingIds);
    }

    [Fact]
    public async Task MarkdownReporter_RendersSuppressionsAppendix()
    {
        var manifest = new EvidenceManifest(
            RunId: "test-run",
            TimestampUtc: DateTimeOffset.UtcNow,
            ToolVersion: "0.1.0",
            Target: "C:/Projects/Sample",
            CommitSha: "abc1234",
            CriteriaInScope: ["CC6.1"],
            ToolProvenance: [],
            Artifacts: [],
            Findings:
            [
                CreateTestFinding("F-1", "SEC-001", "fp-1", "src/App/file.cs") with
                {
                    Status = FindingStatus.Suppressed,
                    Suppression = new FindingSuppression("Accepted risk", "approver@example.com", "SEC-1", DateTimeOffset.UtcNow.AddDays(10), false)
                }
            ],
            Suppressions:
            [
                new SuppressionEntry("fp-1", "SEC-001", "src/**", "Accepted risk", "approver@example.com", "SEC-1", DateTimeOffset.UtcNow.AddDays(10), false, ["F-1"])
            ]
        );

        var reporter = new MarkdownReporter();
        var md = await reporter.RenderAsync(manifest);

        Assert.Contains("## Appendix: Suppressions (Accepted Risk)", md);
        Assert.Contains("SEC-001", md);
        Assert.Contains("src/**", md);
        Assert.Contains("approver@example.com", md);
        Assert.Contains("SEC-1", md);
        Assert.Contains("Active", md);
    }

    private static Finding CreateTestFinding(string id, string ruleId, string fingerprint, string filePath)
    {
        return new Finding(
            Id: id,
            RuleId: ruleId,
            Title: "Test Finding",
            SourceName: "TestScanner",
            SourceVersion: "1.0.0",
            TscCriteria: ["CC6.1"],
            OrgControlId: null,
            Severity: Severity.High,
            Category: FindingCategory.Code,
            Location: new FindingLocation(FilePath: filePath, LineNumber: 10),
            RedactedEvidence: "evidence",
            RiskExplanation: "Risk of exposure",
            RecommendedFix: "Fix it",
            Effort: EffortEstimate.Low,
            Confidence: ConfidenceLevel.High,
            Fingerprint: fingerprint,
            Status: FindingStatus.Open
        );
    }
}