using Soc2Evaluator.Core.Models;
using Soc2Evaluator.Core.Services;
using Soc2Evaluator.Reporting;
using Soc2Evaluator.Rules;
using Soc2Evaluator.Rules.Checks;
using Xunit;

namespace Soc2Evaluator.Tests;

public class Phase1IntegrationTests
{
    private readonly IEvidenceHasher _hasher = new EvidenceHasher();
    private readonly IControlMappingService _mappingService = new ControlMappingService();
    private readonly IRemediationService _remediationService = new RemediationService();
    private readonly IBaselineDiffService _baselineDiffService = new BaselineDiffService();

    [Fact]
    public async Task Phase1_EndToEnd_VulnerableAndCleanBaselineWorkflow()
    {
        var vulnerableFixture = GetFixturePath("vulnerable-app");
        var cleanFixture = GetFixturePath("clean-app");

        // 1. Setup Orchestrator with Rules adapter
        var rulesCheck = new VerboseErrorsCheck();
        var rulesAdapter = new RulesScannerAdapter([rulesCheck], _hasher);

        var orchestrator = new EvaluationOrchestrator(
            adapters: [rulesAdapter],
            hasher: _hasher,
            mappingService: _mappingService,
            remediationService: _remediationService,
            baselineDiffService: _baselineDiffService
        );

        // 2. Run scan against vulnerable app
        var vulnerableRequest = new EvaluationRequest(
            TargetPath: vulnerableFixture,
            Criteria: ["CC6.1", "CC7.2"],
            OutputPath: "./test-out/vulnerable",
            Formats: ["md", "json"]
        );

        var vulnerableBundle = await orchestrator.RunEvaluationAsync(vulnerableRequest);
        var vulnManifest = vulnerableBundle.Manifest;

        Assert.Equal(2, vulnManifest.Findings.Count);
        Assert.All(vulnManifest.Findings, f =>
        {
            Assert.Equal("CFG-002", f.RuleId);
            Assert.Contains("CC6.1", f.TscCriteria);
            Assert.Contains("CC7.2", f.TscCriteria);
            Assert.Contains("customErrors mode=\"RemoteOnly\"", f.RecommendedFix);
        });

        Assert.Single(vulnManifest.Artifacts);
        Assert.True(_hasher.VerifyArtifacts(vulnManifest, vulnerableBundle.RawArtifactBytes));
        Assert.True(_hasher.VerifyManifestChecksum(vulnManifest));

        // 3. Serialize vulnerable findings to a temporary baseline file
        var tempBaseline = Path.GetTempFileName() + ".json";
        try
        {
            var jsonReporter = new JsonReporter();
            var jsonContent = await jsonReporter.RenderAsync(vulnManifest);
            File.WriteAllText(tempBaseline, jsonContent);

            // 4. Run scan against clean app using vulnerable run as baseline
            var cleanRequest = new EvaluationRequest(
                TargetPath: cleanFixture,
                Criteria: ["CC6.1", "CC7.2"],
                OutputPath: "./test-out/clean",
                Formats: ["md", "json"],
                BaselinePath: tempBaseline
            );

            var cleanBundle = await orchestrator.RunEvaluationAsync(cleanRequest);
            var cleanManifest = cleanBundle.Manifest;

            Assert.Empty(cleanManifest.Findings);
            Assert.NotNull(cleanManifest.BaselineDelta);
            Assert.Equal(0, cleanManifest.BaselineDelta.NewCount);
            Assert.Equal(0, cleanManifest.BaselineDelta.PersistingCount);
            Assert.Equal(2, cleanManifest.BaselineDelta.ResolvedCount);

            // 5. Render Markdown report and verify Delta vs Baseline section
            var mdReporter = new MarkdownReporter();
            var mdReport = await mdReporter.RenderAsync(cleanManifest);

            Assert.Contains("## Delta vs. Baseline", mdReport);
            Assert.Contains("- **Resolved Findings:** 2", mdReport);
            Assert.Contains("[RESOLVED]", mdReport);
        }
        finally
        {
            if (File.Exists(tempBaseline)) File.Delete(tempBaseline);
        }
    }

    private static string GetFixturePath(string fixtureName)
    {
        var candidates = new[]
        {
            Path.Combine(AppContext.BaseDirectory, $"../../../../fixtures/{fixtureName}"),
            Path.Combine(AppContext.BaseDirectory, $"../../../fixtures/{fixtureName}"),
            Path.Combine(Directory.GetCurrentDirectory(), $"tests/fixtures/{fixtureName}"),
            Path.Combine(Directory.GetCurrentDirectory(), $"fixtures/{fixtureName}")
        };

        foreach (var c in candidates)
        {
            var full = Path.GetFullPath(c);
            if (Directory.Exists(full)) return full;
        }

        throw new DirectoryNotFoundException($"Could not locate fixture '{fixtureName}'");
    }
}