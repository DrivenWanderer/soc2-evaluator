using Soc2Evaluator.Core.Models;
using Soc2Evaluator.Core.Services;
using Xunit;

namespace Soc2Evaluator.Tests;

public class RemediationTests
{
    [Fact]
    public void RemediationService_LoadsTemplatesForCoreRules()
    {
        var service = new RemediationService();

        var sec001 = service.GetRemediationTemplate("SEC-001");
        Assert.NotNull(sec001);
        Assert.Contains("Revoke and Rotate", sec001);
        Assert.Contains("appsettings.json", sec001);

        var dep001 = service.GetRemediationTemplate("DEP-001");
        Assert.NotNull(dep001);
        Assert.Contains("dotnet add package", dep001);

        var cfg002 = service.GetRemediationTemplate("CFG-002");
        Assert.NotNull(cfg002);
        Assert.Contains("customErrors mode=\"RemoteOnly\"", cfg002);
        Assert.Contains("compilation debug=\"false\"", cfg002);
    }

    [Fact]
    public void RemediationService_EnrichesFindingWithAuthoritativeTemplate()
    {
        var service = new RemediationService();
        var finding = new Finding(
            Id: "SEC-001-1",
            RuleId: "SEC-001",
            Title: "Generic API Key detected",
            SourceName: "gitleaks",
            SourceVersion: "8.18.2",
            TscCriteria: ["CC6.1"],
            OrgControlId: null,
            Severity: Severity.High,
            Category: FindingCategory.Code,
            Location: new FindingLocation("appsettings.json", 10, 1),
            RedactedEvidence: "***[REDACTED]***",
            RiskExplanation: "Hardcoded secret",
            RecommendedFix: "Generic initial fix text",
            Effort: EffortEstimate.Low,
            Confidence: ConfidenceLevel.High,
            Fingerprint: "fingerprint-123"
        );

        var enriched = service.EnrichWithRemediation(finding);

        Assert.NotEqual("Generic initial fix text", enriched.RecommendedFix);
        Assert.Contains("Revoke and Rotate", enriched.RecommendedFix);
    }

    [Fact]
    public void RemediationService_UnknownRule_LeavesRecommendedFixIntact()
    {
        var service = new RemediationService();
        var finding = new Finding(
            Id: "UNKNOWN-1",
            RuleId: "UNKNOWN-999",
            Title: "Unknown issue",
            SourceName: "custom",
            SourceVersion: "1.0",
            TscCriteria: ["CC1.1"],
            OrgControlId: null,
            Severity: Severity.Low,
            Category: FindingCategory.Process,
            Location: null,
            RedactedEvidence: "",
            RiskExplanation: "None",
            RecommendedFix: "Original fix text",
            Effort: EffortEstimate.Low,
            Confidence: ConfidenceLevel.Low,
            Fingerprint: "unknown-123"
        );

        var enriched = service.EnrichWithRemediation(finding);

        Assert.Equal("Original fix text", enriched.RecommendedFix);
    }
}