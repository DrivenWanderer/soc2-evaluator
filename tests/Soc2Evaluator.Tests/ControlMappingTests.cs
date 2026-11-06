using Soc2Evaluator.Core.Models;
using Soc2Evaluator.Core.Services;
using Xunit;

namespace Soc2Evaluator.Tests;

public class ControlMappingTests : IDisposable
{
    private readonly List<string> _tempFiles = [];

    public void Dispose()
    {
        foreach (var file in _tempFiles)
        {
            if (File.Exists(file))
            {
                try { File.Delete(file); } catch { /* ignore */ }
            }
        }
    }

    [Fact]
    public void ControlMapping_LoadsEmbeddedDefaultsSuccessfully()
    {
        var service = new ControlMappingService();
        var config = service.CurrentConfig;

        Assert.NotNull(config);
        Assert.Equal("Default", config.Organization);
        Assert.Equal("1.0", config.Version);

        var sec001 = service.GetMapping("SEC-001");
        Assert.NotNull(sec001);
        Assert.Contains("CC6.1", sec001.TscCriteria);
        Assert.Equal(Severity.High, sec001.DefaultSeverity);
        Assert.Equal(FindingCategory.Code, sec001.Category);
        Assert.True(sec001.Enabled);
        Assert.Contains("Default mapping, confirm with auditor", sec001.Notes);

        var dep001 = service.GetMapping("DEP-001");
        Assert.NotNull(dep001);
        Assert.Contains("CC7.1", dep001.TscCriteria);
        Assert.Equal(Severity.High, dep001.DefaultSeverity);
        Assert.Equal(FindingCategory.Configuration, dep001.Category);

        var cfg002 = service.GetMapping("CFG-002");
        Assert.NotNull(cfg002);
        Assert.Contains("CC6.1", cfg002.TscCriteria);
        Assert.Contains("CC7.2", cfg002.TscCriteria);
        Assert.Equal(Severity.Medium, cfg002.DefaultSeverity);
        Assert.Equal(FindingCategory.Configuration, cfg002.Category);
    }

    [Fact]
    public void ControlMapping_WithOrgOverrides_AppliesCustomControlIdsAndSeverities()
    {
        var orgYaml = """
        organization: "Acme Corporation"
        version: "2.0"
        mappings:
          - rule_id: "SEC-001"
            org_control_id: "ACME-SEC-01"
            override_severity: "Critical"
          - rule_id: "CFG-002"
            org_control_id: "ACME-OPS-03"
            enabled: false
            justification: "Handled at edge gateway"
        """;

        var tempOrgFile = Path.GetTempFileName() + ".yml";
        File.WriteAllText(tempOrgFile, orgYaml);
        _tempFiles.Add(tempOrgFile);

        var service = new ControlMappingService(tempOrgFile);

        Assert.Equal("Acme Corporation", service.CurrentConfig.Organization);
        Assert.Equal("2.0", service.CurrentConfig.Version);

        var sec001 = service.GetMapping("SEC-001");
        Assert.NotNull(sec001);
        Assert.Equal("ACME-SEC-01", sec001.OrgControlId);
        Assert.Equal(Severity.Critical, sec001.OverrideSeverity);
        Assert.True(sec001.Enabled);

        var cfg002 = service.GetMapping("CFG-002");
        Assert.NotNull(cfg002);
        Assert.Equal("ACME-OPS-03", cfg002.OrgControlId);
        Assert.False(cfg002.Enabled);
        Assert.Equal("Handled at edge gateway", cfg002.Justification);
    }

    [Fact]
    public void ControlMapping_EnrichFinding_AppliesMappingAttributes()
    {
        var orgYaml = """
        organization: "Acme Corporation"
        mappings:
          - rule_id: "SEC-001"
            org_control_id: "ACME-SEC-01"
            override_severity: "Critical"
        """;

        var tempOrgFile = Path.GetTempFileName() + ".yml";
        File.WriteAllText(tempOrgFile, orgYaml);
        _tempFiles.Add(tempOrgFile);

        var service = new ControlMappingService(tempOrgFile);

        var rawFinding = new Finding(
            Id: "finding-001",
            RuleId: "SEC-001",
            Title: "Generic Secret Finding",
            SourceName: "gitleaks",
            SourceVersion: "8.18.2",
            TscCriteria: [],
            OrgControlId: null,
            Severity: Severity.Low,
            Category: FindingCategory.Code,
            Location: new FindingLocation("appsettings.json", 10, 1),
            RedactedEvidence: "***[REDACTED]***",
            RiskExplanation: "Exposed API key in configuration",
            RecommendedFix: "Move secret to Azure Key Vault or environment variable",
            Effort: EffortEstimate.Low,
            Confidence: ConfidenceLevel.High,
            Fingerprint: Finding.ComputeFingerprint("SEC-001", new FindingLocation("appsettings.json", 10, 1))
        );

        var enriched = service.EnrichFinding(rawFinding);

        Assert.Equal(Severity.Critical, enriched.Severity);
        Assert.Equal("ACME-SEC-01", enriched.OrgControlId);
        Assert.Contains("CC6.1", enriched.TscCriteria);
        Assert.Equal(FindingStatus.Open, enriched.Status);
    }

    [Fact]
    public void ControlMapping_EnrichFinding_WhenRuleDisabled_MarksSuppressedWithJustification()
    {
        var orgYaml = """
        organization: "Acme Corporation"
        mappings:
          - rule_id: "CFG-002"
            enabled: false
            justification: "Handled at edge reverse proxy"
        """;

        var tempOrgFile = Path.GetTempFileName() + ".yml";
        File.WriteAllText(tempOrgFile, orgYaml);
        _tempFiles.Add(tempOrgFile);

        var service = new ControlMappingService(tempOrgFile);

        var rawFinding = new Finding(
            Id: "cfg-001",
            RuleId: "CFG-002",
            Title: "Detailed Errors Enabled",
            SourceName: "Soc2Evaluator.Rules",
            SourceVersion: "0.1.0",
            TscCriteria: ["CC6.1", "CC7.2"],
            OrgControlId: null,
            Severity: Severity.Medium,
            Category: FindingCategory.Configuration,
            Location: new FindingLocation("web.config", 15, 2),
            RedactedEvidence: "<customErrors mode=\"Off\" />",
            RiskExplanation: "Stack traces can be returned to untrusted clients.",
            RecommendedFix: "Set customErrors mode=\"RemoteOnly\" or \"On\"",
            Effort: EffortEstimate.Low,
            Confidence: ConfidenceLevel.High,
            Fingerprint: Finding.ComputeFingerprint("CFG-002", new FindingLocation("web.config", 15, 2))
        );

        var enriched = service.EnrichFinding(rawFinding);

        Assert.Equal(FindingStatus.Suppressed, enriched.Status);
        Assert.Contains("Handled at edge reverse proxy", enriched.RiskExplanation);
    }

    [Fact]
    public void ControlMapping_NonExistentOrgConfig_ThrowsFileNotFoundException()
    {
        Assert.Throws<FileNotFoundException>(() => new ControlMappingService("non_existent_org_config.yml"));
    }

    [Fact]
    public void ControlMapping_UnknownRuleId_ReturnsUnchanged()
    {
        var service = new ControlMappingService();
        var rawFinding = new Finding(
            Id: "custom-001",
            RuleId: "CUSTOM-999",
            Title: "Custom Finding",
            SourceName: "custom",
            SourceVersion: "1.0",
            TscCriteria: ["CC9.9"],
            OrgControlId: null,
            Severity: Severity.Low,
            Category: FindingCategory.Process,
            Location: null,
            RedactedEvidence: "",
            RiskExplanation: "Custom risk",
            RecommendedFix: "Custom fix",
            Effort: EffortEstimate.Low,
            Confidence: ConfidenceLevel.Low,
            Fingerprint: "custom-999"
        );

        var enriched = service.EnrichFinding(rawFinding);

        Assert.Equal(rawFinding, enriched);
    }
}