using Soc2Evaluator.Adapters;
using Soc2Evaluator.Adapters.Gitleaks;
using Soc2Evaluator.Core.Adapters;
using Soc2Evaluator.Core.Services;
using Xunit;

namespace Soc2Evaluator.Tests;

public class OrchestratorTests
{
    private readonly IEvidenceHasher _hasher = new EvidenceHasher();

    [Fact]
    public async Task Orchestrator_GeneratesSignedManifestAndArtifacts()
    {
        var mockRunner = new MockRunner();
        var gitleaksAdapter = new GitleaksAdapter(mockRunner, _hasher);
        var orchestrator = new EvaluationOrchestrator([gitleaksAdapter], _hasher);

        var request = new EvaluationRequest(
            TargetPath: ".",
            Criteria: ["CC6.1"],
            OutputPath: "./test-reports",
            Formats: ["md", "json"]
        );

        var bundle = await orchestrator.RunEvaluationAsync(request);

        Assert.NotNull(bundle);
        Assert.NotNull(bundle.Manifest);
        Assert.NotEmpty(bundle.Manifest.RunId);
        Assert.NotNull(bundle.Manifest.ManifestSha256);
        Assert.True(_hasher.VerifyManifest(bundle.Manifest));
        Assert.NotEmpty(bundle.Manifest.Findings);
        Assert.Single(bundle.Manifest.ToolProvenance);
        Assert.Equal("gitleaks", bundle.Manifest.ToolProvenance[0].ToolName);
    }

    private class MockRunner : IProcessRunner
    {
        public bool ExistsOnPath(string executableName) => false;

        public Task<ProcessResult> RunAsync(
            string fileName,
            IReadOnlyList<string> arguments,
            string? workingDirectory = null,
            IReadOnlyDictionary<string, string>? environmentVariables = null,
            CancellationToken cancellationToken = default
        )
        {
            return Task.FromResult(new ProcessResult(0, "", "", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow));
        }
    }
}