using System.Text.Json;
using Soc2Evaluator.Core.Models;
using Soc2Evaluator.Core.Services;
using Soc2Evaluator.Reporting;
using Xunit;

namespace Soc2Evaluator.Tests;

public class ReporterTests
{
    private readonly EvidenceHasher _hasher = new();

    [Fact]
    public async Task JsonReporter_RendersValidJsonMatchingManifest()
    {
        var manifest = CreateTestManifest();
        var reporter = new JsonReporter();

        var json = await reporter.RenderAsync(manifest);

        Assert.False(string.IsNullOrWhiteSpace(json));
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        Assert.Equal(manifest.RunId, root.GetProperty("runId").GetString());
        Assert.Equal(manifest.ManifestSha256, root.GetProperty("manifestSha256").GetString());
        Assert.Equal(1, root.GetProperty("findings").GetArrayLength());
        Assert.Equal("SEC-001-1", root.GetProperty("findings")[0].GetProperty("id").GetString());
    }

    [Fact]
    public async Task MarkdownReporter_RendersRequiredSectionsAndDisclaimer()
    {
        var manifest = CreateTestManifest();
        var reporter = new MarkdownReporter();

        var md = await reporter.RenderAsync(manifest);

        // Required sections and disclaimer checks
        Assert.Contains("# SOC 2 Readiness Assessment Report", md);
        Assert.Contains("## Disclaimer", md);
        Assert.Contains("readiness assessment and evidence-gathering aid", md);
        Assert.Contains("does not certify", md);
        Assert.Contains("## Executive Summary", md);
        Assert.Contains("## Coverage Table", md);
        Assert.Contains("## Findings", md);
        Assert.Contains("## Appendix: Tool Provenance and Execution", md);

        // Content checks
        Assert.Contains(manifest.RunId, md);
        Assert.Contains(manifest.ManifestSha256!, md);
        Assert.Contains("SEC-001-1", md);
        Assert.Contains("Hardcoded credential detected in connection string", md);
        Assert.Contains("gitleaks", md);
        Assert.Contains("appsettings.json:14", md);
    }

    [Fact]
    public async Task MarkdownReporter_EscapesUntrustedScannerOutputAndHtmlTags()
    {
        var maliciousFinding = new Finding(
            Id: "SEC-INJECT-1",
            RuleId: "SEC-INJECT",
            Title: "Malicious <script>alert(1)</script> & | pipes | in title",
            SourceName: "untrusted-scanner",
            SourceVersion: "1.0.0",
            TscCriteria: ["CC6.1"],
            OrgControlId: null,
            Severity: Severity.Medium,
            Category: FindingCategory.Code,
            Location: new FindingLocation("<bad/path>|file.cs", 1, 1),
            RedactedEvidence: "secret```injection",
            RiskExplanation: "Risk with <b>HTML</b> and | pipes |",
            RecommendedFix: "Fix with <script> and | pipes |",
            Effort: EffortEstimate.Low,
            Confidence: ConfidenceLevel.High,
            Fingerprint: "fp123"
        );

        var manifest = new EvidenceManifest(
            RunId: "test-run-escaping",
            TimestampUtc: DateTimeOffset.UtcNow,
            ToolVersion: "0.1.0",
            Target: "C:/Projects/<script>",
            CommitSha: "abc",
            CriteriaInScope: ["CC6.1"],
            ToolProvenance: [],
            Artifacts: [],
            Findings: [maliciousFinding],
            ManifestSha256: "dummyhash"
        );

        var reporter = new MarkdownReporter();
        var md = await reporter.RenderAsync(manifest);

        // Verify HTML tags are escaped
        Assert.DoesNotContain("<script>", md);
        Assert.Contains("&lt;script&gt;", md);
        Assert.DoesNotContain("<b>HTML</b>", md);
        Assert.Contains("&lt;b&gt;HTML&lt;/b&gt;", md);

        // Fenced code block injection prevention
        Assert.DoesNotContain("secret```injection", md);
        Assert.Contains("secret'''injection", md);
    }

    [Fact]
    public async Task MarkdownReporter_DerivesCoverageStatusAccuratelyWhenToolNotRun()
    {
        var provenance = new ToolExecutionProvenance(
            ToolName: "gitleaks",
            ToolVersion: null,
            Arguments: [],
            StartTimeUtc: DateTimeOffset.UtcNow,
            EndTimeUtc: DateTimeOffset.UtcNow,
            ExitCode: null,
            Status: "NotRun",
            ErrorMessage: "Scanner 'gitleaks' is not installed or not in PATH."
        );

        var manifest = new EvidenceManifest(
            RunId: "test-coverage-notrun",
            TimestampUtc: DateTimeOffset.UtcNow,
            ToolVersion: "0.1.0",
            Target: "C:/Projects/Sample",
            CommitSha: null,
            CriteriaInScope: ["CC6.1"],
            ToolProvenance: [provenance],
            Artifacts: [],
            Findings: [],
            ManifestSha256: "hash"
        );

        var reporter = new MarkdownReporter();
        var md = await reporter.RenderAsync(manifest);

        // Must show Not Run, and must not claim Evaluated
        Assert.Contains("| gitleaks | CC6.1 | Not Run |", md);
        Assert.Contains("Scanner 'gitleaks' is not installed", md);
    }

    [Fact]
    public void ReporterFactory_ResolvesSupportedReporters()
    {
        var factory = new ReporterFactory([new MarkdownReporter(), new JsonReporter()]);

        var md = factory.GetReporter("md");
        var json = factory.GetReporter("json");

        Assert.IsType<MarkdownReporter>(md);
        Assert.IsType<JsonReporter>(json);
        Assert.Throws<ArgumentException>(() => factory.GetReporter("html"));
    }

    private EvidenceManifest CreateTestManifest()
    {
        var finding = new Finding(
            Id: "SEC-001-1",
            RuleId: "SEC-001",
            Title: "Hardcoded credential detected in connection string",
            SourceName: "gitleaks",
            SourceVersion: "8.18.2",
            TscCriteria: ["CC6.1"],
            OrgControlId: "ACME-AC-04",
            Severity: Severity.High,
            Category: FindingCategory.Code,
            Location: new FindingLocation("appsettings.json", 14, 5),
            RedactedEvidence: "Server=myServerAddress;Database=myDataBase;Uid=myUsername;Pwd=***",
            RiskExplanation: "Hardcoded credentials can be extracted from source control and leaked.",
            RecommendedFix: "Move credentials to Azure Key Vault or environment variables.",
            Effort: EffortEstimate.Low,
            Confidence: ConfidenceLevel.High,
            Fingerprint: Finding.ComputeFingerprint("SEC-001", new FindingLocation("appsettings.json", 14, 5))
        );

        var provenance = new ToolExecutionProvenance(
            ToolName: "gitleaks",
            ToolVersion: "8.18.2",
            Arguments: ["detect", "--no-git", "--report-format", "sarif"],
            StartTimeUtc: DateTimeOffset.UtcNow.AddSeconds(-2),
            EndTimeUtc: DateTimeOffset.UtcNow,
            ExitCode: 0,
            Status: "Success"
        );

        var rawManifest = new EvidenceManifest(
            RunId: "test-run-001",
            TimestampUtc: DateTimeOffset.UtcNow,
            ToolVersion: "0.1.0",
            Target: "C:/Projects/SampleProject",
            CommitSha: "deadbeef1234567890",
            CriteriaInScope: ["CC6.1"],
            ToolProvenance: [provenance],
            Artifacts: [],
            Findings: [finding]
        );

        return _hasher.AttachManifestChecksum(rawManifest);
    }
}