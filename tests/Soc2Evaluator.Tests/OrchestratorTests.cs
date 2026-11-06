using Soc2Evaluator.Adapters;
using Soc2Evaluator.Adapters.Gitleaks;
using Soc2Evaluator.Core.Adapters;
using Soc2Evaluator.Core.Services;
using Xunit;

namespace Soc2Evaluator.Tests;

public class OrchestratorTests
{
    private readonly IEvidenceHasher _hasher = new EvidenceHasher();
    private readonly IControlMappingService _mappingService = new ControlMappingService();

    [Fact]
    public async Task Orchestrator_CleanScan_DoesNotInjectFakeFindings()
    {
        var mockRunner = new MockRunner(exists: false);
        var gitleaksAdapter = new GitleaksAdapter(mockRunner, _hasher);
        var orchestrator = new EvaluationOrchestrator([gitleaksAdapter], _hasher, _mappingService);

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
        Assert.True(_hasher.VerifyManifestChecksum(bundle.Manifest));

        // Must NOT inject fake findings into clean scans!
        Assert.Empty(bundle.Manifest.Findings);
        Assert.Single(bundle.Manifest.ToolProvenance);
        Assert.Equal("gitleaks", bundle.Manifest.ToolProvenance[0].ToolName);
        Assert.Equal("NotRun", bundle.Manifest.ToolProvenance[0].Status);
    }

    [Fact]
    public async Task Orchestrator_WithAdapterArtifacts_VerifiesArtifactChecksums()
    {
        const string sampleSarif = """
        {
          "version": "2.1.0",
          "runs": [
            {
              "tool": { "driver": { "name": "gitleaks", "version": "8.18.2" } },
              "results": []
            }
          ]
        }
        """;

        var mockRunner = new MockRunner(exists: true)
        {
            OnRun = (args) =>
            {
                var reportPathIndex = args.ToList().IndexOf("--report-path");
                if (reportPathIndex >= 0 && reportPathIndex + 1 < args.Count)
                {
                    File.WriteAllText(args[reportPathIndex + 1], sampleSarif);
                }
                return new ProcessResult(0, "success", "", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);
            }
        };

        var gitleaksAdapter = new GitleaksAdapter(mockRunner, _hasher);
        var orchestrator = new EvaluationOrchestrator([gitleaksAdapter], _hasher, _mappingService);

        var request = new EvaluationRequest(
            TargetPath: ".",
            Criteria: ["CC6.1"],
            OutputPath: "./test-reports",
            Formats: ["md", "json"]
        );

        var bundle = await orchestrator.RunEvaluationAsync(request);

        Assert.NotNull(bundle.Manifest.ManifestSha256);
        Assert.True(_hasher.VerifyManifestChecksum(bundle.Manifest));
        Assert.Single(bundle.Manifest.Artifacts);
        Assert.True(_hasher.VerifyArtifacts(bundle.Manifest, bundle.RawArtifactBytes));
    }

    private class MockRunner : IProcessRunner
    {
        private readonly bool _exists;
        public Func<IReadOnlyList<string>, ProcessResult>? OnRun { get; set; }

        public MockRunner(bool exists)
        {
            _exists = exists;
        }

        public bool ExistsOnPath(string executableName) => _exists;

        public Task<ProcessResult> RunAsync(
            string fileName,
            IReadOnlyList<string> arguments,
            string? workingDirectory = null,
            IReadOnlyDictionary<string, string>? environmentVariables = null,
            CancellationToken cancellationToken = default
        )
        {
            if (arguments.Count == 1 && arguments[0] == "version")
            {
                return Task.FromResult(new ProcessResult(0, "8.18.2", "", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow));
            }

            if (OnRun != null)
            {
                return Task.FromResult(OnRun(arguments));
            }

            return Task.FromResult(new ProcessResult(0, "", "", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow));
        }
    }
}