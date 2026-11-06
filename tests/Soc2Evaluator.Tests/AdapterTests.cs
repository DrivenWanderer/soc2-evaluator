using System.Text;
using Soc2Evaluator.Adapters;
using Soc2Evaluator.Adapters.Gitleaks;
using Soc2Evaluator.Adapters.Sarif;
using Soc2Evaluator.Core.Adapters;
using Soc2Evaluator.Core.Models;
using Soc2Evaluator.Core.Services;
using Xunit;

namespace Soc2Evaluator.Tests;

public class AdapterTests
{
    private readonly EvidenceHasher _hasher = new();

    private const string SampleSarif = """
    {
      "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
      "version": "2.1.0",
      "runs": [
        {
          "tool": {
            "driver": {
              "name": "gitleaks",
              "version": "8.18.2"
            }
          },
          "results": [
            {
              "ruleId": "generic-api-key",
              "level": "error",
              "message": {
                "text": "Generic API Key detected"
              },
              "locations": [
                {
                  "physicalLocation": {
                    "artifactLocation": {
                      "uri": "config/secrets.json"
                    },
                    "region": {
                      "startLine": 12,
                      "startColumn": 15,
                      "snippet": {
                        "text": "AKIAIOSFODNN7EXAMPLE"
                      }
                    }
                  }
                }
              ]
            }
          ]
        }
      ]
    }
    """;

    [Fact]
    public void SarifParser_NormalizesFindingsAndRedactsEvidence()
    {
        var (findings, version) = SarifParser.Parse(SampleSarif, "gitleaks", "SEC-001", ["CC6.1"]);

        Assert.Equal("8.18.2", version);
        Assert.Single(findings);

        var finding = findings[0];
        Assert.Equal("generic-api-key", finding.RuleId);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Equal(FindingCategory.Code, finding.Category);
        Assert.Equal("config/secrets.json", finding.Location?.FilePath);
        Assert.Equal(12, finding.Location?.LineNumber);
        Assert.Equal("gitleaks", finding.SourceName);
        Assert.Equal("8.18.2", finding.SourceVersion);
        Assert.Contains("***[REDACTED]***", finding.RedactedEvidence);
        Assert.DoesNotContain("AKIAIOSFODNN7EXAMPLE", finding.RedactedEvidence);
        Assert.NotNull(finding.Fingerprint);
    }

    [Fact]
    public async Task GitleaksAdapter_WhenToolMissing_DegradesGracefullyWithNotRunStatus()
    {
        var mockRunner = new MockProcessRunner(exists: false);
        var adapter = new GitleaksAdapter(mockRunner, _hasher);

        var isAvailable = await adapter.IsAvailableAsync();
        Assert.False(isAvailable);

        var result = await adapter.ExecuteAsync(new AdapterExecutionContext(".", ["CC6.1"]));

        Assert.NotNull(result);
        Assert.Equal("NotRun", result.Provenance.Status);
        Assert.Null(result.Provenance.ExitCode);
        Assert.Contains("not installed", result.Provenance.ErrorMessage);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task GitleaksAdapter_WhenToolExecutes_CapturesProvenanceAndArtifacts()
    {
        var mockRunner = new MockProcessRunner(exists: true)
        {
            VersionOutput = "v8.18.2",
            OnRun = (args) =>
            {
                // find --report-path argument and write the sample SARIF to it
                var reportPathIndex = args.ToList().IndexOf("--report-path");
                if (reportPathIndex >= 0 && reportPathIndex + 1 < args.Count)
                {
                    var targetFile = args[reportPathIndex + 1];
                    File.WriteAllText(targetFile, SampleSarif);
                }
                return new ProcessResult(0, "scan completed", "", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);
            }
        };

        var adapter = new GitleaksAdapter(mockRunner, _hasher);
        var result = await adapter.ExecuteAsync(new AdapterExecutionContext("C:/TestProject", ["CC6.1"]));

        Assert.NotNull(result);
        Assert.Equal("Success", result.Provenance.Status);
        Assert.Equal(0, result.Provenance.ExitCode);
        Assert.Equal("8.18.2", result.Provenance.ToolVersion);
        Assert.Single(result.Findings);
        Assert.Single(result.Artifacts);
        Assert.Equal("gitleaks.sarif", result.Artifacts[0].Name);
        Assert.NotNull(result.Artifacts[0].Sha256Hash);
    }

    private class MockProcessRunner : IProcessRunner
    {
        private readonly bool _exists;
        public string VersionOutput { get; set; } = "8.18.2";
        public Func<IReadOnlyList<string>, ProcessResult>? OnRun { get; set; }

        public MockProcessRunner(bool exists)
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
            if (!_exists)
            {
                throw new FileNotFoundException($"Executable {fileName} not found");
            }

            if (arguments.Count == 1 && arguments[0] == "version")
            {
                return Task.FromResult(new ProcessResult(0, VersionOutput, "", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow));
            }

            if (OnRun != null)
            {
                return Task.FromResult(OnRun(arguments));
            }

            return Task.FromResult(new ProcessResult(0, "", "", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow));
        }
    }
}