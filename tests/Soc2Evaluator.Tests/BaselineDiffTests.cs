using System.Text.Json;
using Soc2Evaluator.Core.Models;
using Soc2Evaluator.Core.Services;
using Soc2Evaluator.Reporting;
using Xunit;

namespace Soc2Evaluator.Tests;

public class BaselineDiffTests : IDisposable
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
    public void BaselineDiff_CategorizesNewPersistingAndResolvedFindings()
    {
        var baselineFindingA = CreateFinding("SEC-001", "appsettings.json", 10, "Secret A");
        var baselineFindingB = CreateFinding("DEP-001", "app.csproj", 5, "Vulnerable Package B");

        var currentFindingB = CreateFinding("DEP-001", "app.csproj", 5, "Vulnerable Package B");
        var currentFindingC = CreateFinding("CFG-002", "web.config", 15, "Debug Enabled C");

        var baselineJson = JsonSerializer.Serialize(new[] { baselineFindingA, baselineFindingB });
        var tempFile = Path.GetTempFileName() + ".json";
        File.WriteAllText(tempFile, baselineJson);
        _tempFiles.Add(tempFile);

        var diffService = new BaselineDiffService();
        var delta = diffService.ComputeDelta([currentFindingB, currentFindingC], tempFile);

        Assert.NotNull(delta);
        Assert.Equal(1, delta.NewCount);
        Assert.Equal(1, delta.PersistingCount);
        Assert.Equal(1, delta.ResolvedCount);

        Assert.Equal(currentFindingC.Fingerprint, delta.NewFindings[0].Fingerprint);
        Assert.Equal(currentFindingB.Fingerprint, delta.PersistingFindings[0].Fingerprint);
        Assert.Equal(baselineFindingA.Fingerprint, delta.ResolvedFindings[0].Fingerprint);
        Assert.Equal(FindingStatus.Resolved, delta.ResolvedFindings[0].Status);
    }

    [Fact]
    public void BaselineDiff_LoadsFromEvidenceBundleJson()
    {
        var findingA = CreateFinding("SEC-001", "secrets.json", 2, "API Key A");

        var manifest = new EvidenceManifest(
            RunId: "run-baseline-001",
            TimestampUtc: DateTimeOffset.UtcNow.AddDays(-7),
            ToolVersion: "0.1.0",
            Target: "C:/Projects/App",
            CommitSha: "abc1234",
            CriteriaInScope: ["CC6.1"],
            ToolProvenance: [],
            Artifacts: [],
            Findings: [findingA],
            ManifestSha256: "dummyhash"
        );

        var bundle = new EvidenceBundle(manifest, new Dictionary<string, byte[]>());
        var bundleJson = JsonSerializer.Serialize(bundle, new JsonSerializerOptions { WriteIndented = true });

        var tempBundleFile = Path.GetTempFileName() + ".json";
        File.WriteAllText(tempBundleFile, bundleJson);
        _tempFiles.Add(tempBundleFile);

        var diffService = new BaselineDiffService();
        var loadedFindings = diffService.LoadBaselineFindings(tempBundleFile);

        Assert.Single(loadedFindings);
        Assert.Equal("SEC-001", loadedFindings[0].RuleId);
        Assert.Equal(findingA.Fingerprint, loadedFindings[0].Fingerprint);
    }

    [Fact]
    public void BaselineDiff_EmptyArray_ReturnsEmptyList()
    {
        var tempFile = Path.GetTempFileName() + ".json";
        File.WriteAllText(tempFile, "[]");
        _tempFiles.Add(tempFile);

        var diffService = new BaselineDiffService();
        var loadedFindings = diffService.LoadBaselineFindings(tempFile);

        Assert.Empty(loadedFindings);
    }

    [Fact]
    public void BaselineDiff_InvalidJsonShape_ThrowsFormatException()
    {
        var tempFile = Path.GetTempFileName() + ".json";
        File.WriteAllText(tempFile, """{ "unrelated": true, "message": "hello" }""");
        _tempFiles.Add(tempFile);

        var diffService = new BaselineDiffService();
        Assert.Throws<FormatException>(() => diffService.LoadBaselineFindings(tempFile));
    }

    [Fact]
    public void BaselineDiff_NonExistentFile_ThrowsFileNotFoundException()
    {
        var diffService = new BaselineDiffService();
        Assert.Throws<FileNotFoundException>(() => diffService.ComputeDelta([], "non_existent_baseline.json"));
    }

    [Fact]
    public async Task MarkdownReporter_WithBaselineDelta_RendersDeltaSection()
    {
        var findingA = CreateFinding("SEC-001", "old.json", 1, "Old Key");
        var findingB = CreateFinding("DEP-001", "app.csproj", 2, "Vuln Pkg");

        var delta = new BaselineDelta(
            BaselinePath: "prev/findings.json",
            NewFindings: [findingB],
            PersistingFindings: [],
            ResolvedFindings: [findingA with { Status = FindingStatus.Resolved }]
        );

        var manifest = new EvidenceManifest(
            RunId: "run-current-002",
            TimestampUtc: DateTimeOffset.UtcNow,
            ToolVersion: "0.1.0",
            Target: "C:/Projects/App",
            CommitSha: "def5678",
            CriteriaInScope: ["CC6.1", "CC7.1"],
            ToolProvenance: [],
            Artifacts: [],
            Findings: [findingB],
            ManifestSha256: "hash123",
            BaselineDelta: delta
        );

        var reporter = new MarkdownReporter();
        var md = await reporter.RenderAsync(manifest);

        Assert.Contains("## Delta vs. Baseline", md);
        Assert.Contains("- **Baseline Source:** `prev/findings.json`", md);
        Assert.Contains("- **New Findings:** 1", md);
        Assert.Contains("- **Persisting Findings:** 0", md);
        Assert.Contains("- **Resolved Findings:** 1", md);
        Assert.Contains("[RESOLVED]", md);
        Assert.Contains("SEC-001", md);
    }

    private static Finding CreateFinding(string ruleId, string filePath, int line, string title)
    {
        var location = new FindingLocation(filePath, line, null);
        var fp = Finding.ComputeFingerprint(ruleId, location);

        return new Finding(
            Id: $"{ruleId}-1",
            RuleId: ruleId,
            Title: title,
            SourceName: "test",
            SourceVersion: "1.0",
            TscCriteria: ["CC6.1"],
            OrgControlId: null,
            Severity: Severity.Medium,
            Category: FindingCategory.Code,
            Location: location,
            RedactedEvidence: "***[REDACTED]***",
            RiskExplanation: "Risk description",
            RecommendedFix: "Fix description",
            Effort: EffortEstimate.Low,
            Confidence: ConfidenceLevel.High,
            Fingerprint: fp
        );
    }
}