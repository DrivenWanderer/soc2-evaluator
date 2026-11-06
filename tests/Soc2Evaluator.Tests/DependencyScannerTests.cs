using System.Text;
using Soc2Evaluator.Adapters;
using Soc2Evaluator.Adapters.Dependencies;
using Soc2Evaluator.Core.Adapters;
using Soc2Evaluator.Core.Models;
using Soc2Evaluator.Core.Services;
using Xunit;

namespace Soc2Evaluator.Tests;

public class DependencyScannerTests
{
    private readonly EvidenceHasher _hasher = new();

    private const string SampleDotNetListJson = """
    {
      "version": 1,
      "parameters": "--vulnerable --include-transitive",
      "projects": [
        {
          "path": "C:/Projects/SampleApp/SampleApp.csproj",
          "frameworks": [
            {
              "framework": "net8.0",
              "topLevelPackages": [
                {
                  "id": "Newtonsoft.Json",
                  "requestedVersion": "12.0.1",
                  "resolvedVersion": "12.0.1",
                  "vulnerabilities": [
                    {
                      "severity": "High",
                      "advisoryurl": "https://github.com/advisories/GHSA-5crp-9r3c-p9vr"
                    }
                  ]
                }
              ],
              "transitivePackages": [
                {
                  "id": "System.Text.Encodings.Web",
                  "resolvedVersion": "4.5.0",
                  "vulnerabilities": [
                    {
                      "severity": "Moderate",
                      "advisoryurl": "https://github.com/advisories/GHSA-q7cg-xrv7-xv6v"
                    }
                  ]
                }
              ]
            }
          ]
        }
      ]
    }
    """;

    [Fact]
    public void ParseDotNetVulnerabilities_ParsesTopLevelAndTransitivePackages()
    {
        var findings = DependencyScannerAdapter.ParseDotNetVulnerabilities(SampleDotNetListJson);

        Assert.Equal(2, findings.Count);

        var topLevel = findings[0];
        Assert.Equal("DEP-001", topLevel.RuleId);
        Assert.Contains("Newtonsoft.Json", topLevel.Title);
        Assert.Contains("12.0.1", topLevel.Title);
        Assert.Equal(Severity.High, topLevel.Severity);
        Assert.Equal(FindingCategory.Configuration, topLevel.Category);
        Assert.Contains("CC7.1", topLevel.TscCriteria);
        Assert.Equal("C:/Projects/SampleApp/SampleApp.csproj", topLevel.Location?.FilePath);
        Assert.Equal("Newtonsoft.Json@12.0.1", topLevel.Location?.SettingOrResource);
        Assert.Contains("Top-level dependency", topLevel.RedactedEvidence);

        var transitive = findings[1];
        Assert.Equal("DEP-001", transitive.RuleId);
        Assert.Contains("System.Text.Encodings.Web", transitive.Title);
        Assert.Equal(Severity.Medium, transitive.Severity);
        Assert.Contains("Transitive dependency", transitive.RedactedEvidence);
    }

    [Fact]
    public async Task DependencyScanner_WhenOsvMissing_FallsBackToDotNetList()
    {
        var mockRunner = new MockProcessRunner(hasOsv: false, hasDotNet: true)
        {
            OnDotNetRun = (args) => new ProcessResult(0, SampleDotNetListJson, "", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow)
        };

        var adapter = new DependencyScannerAdapter(mockRunner, _hasher);
        var result = await adapter.ExecuteAsync(new AdapterExecutionContext("C:/Projects/SampleApp", ["CC7.1"]));

        Assert.NotNull(result);
        Assert.Equal("Success", result.Provenance.Status);
        Assert.Equal("dotnet-list-package", result.Provenance.ToolName);
        Assert.Equal(2, result.Findings.Count);
        Assert.Single(result.Artifacts);
        Assert.Equal("dotnet-vulnerable-packages.json", result.Artifacts[0].Name);
        Assert.True(result.RawArtifactBytes.ContainsKey("dotnet-vulnerable-packages.json"));
    }

    [Fact]
    public async Task DependencyScanner_WhenOsvAvailable_ExecutesOsvScanner()
    {
        const string sampleOsvSarif = """
        {
          "version": "2.1.0",
          "runs": [
            {
              "tool": { "driver": { "name": "osv-scanner", "version": "1.7.0" } },
              "results": [
                {
                  "ruleId": "GHSA-1234",
                  "level": "error",
                  "message": { "text": "Vulnerability in dependency" },
                  "locations": [
                    {
                      "physicalLocation": {
                        "artifactLocation": { "uri": "packages.lock.json" },
                        "region": { "startLine": 5, "snippet": { "text": "vulnerable-pkg" } }
                      }
                    }
                  ]
                }
              ]
            }
          ]
        }
        """;

        var mockRunner = new MockProcessRunner(hasOsv: true, hasDotNet: true)
        {
            OnOsvRun = (args) =>
            {
                var outputIndex = args.ToList().IndexOf("--output");
                if (outputIndex >= 0 && outputIndex + 1 < args.Count)
                {
                    File.WriteAllText(args[outputIndex + 1], sampleOsvSarif);
                }
                return new ProcessResult(0, "", "", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);
            }
        };

        var adapter = new DependencyScannerAdapter(mockRunner, _hasher);
        var result = await adapter.ExecuteAsync(new AdapterExecutionContext("C:/Projects/SampleApp", ["CC7.1"]));

        Assert.NotNull(result);
        Assert.Equal("Success", result.Provenance.Status);
        Assert.Equal("osv-scanner", result.Provenance.ToolName);
        Assert.Single(result.Findings);
        Assert.Equal("DEP-001", result.Findings[0].RuleId);
        Assert.Single(result.Artifacts);
        Assert.Equal("osv-scanner.sarif", result.Artifacts[0].Name);
    }

    [Fact]
    public async Task DependencyScanner_WhenBothMissing_DegradesGracefullyWithNotRun()
    {
        var mockRunner = new MockProcessRunner(hasOsv: false, hasDotNet: false);
        var adapter = new DependencyScannerAdapter(mockRunner, _hasher);

        var isAvailable = await adapter.IsAvailableAsync();
        Assert.False(isAvailable);

        var result = await adapter.ExecuteAsync(new AdapterExecutionContext(".", ["CC7.1"]));

        Assert.Equal("NotRun", result.Provenance.Status);
        Assert.Empty(result.Findings);
        Assert.Contains("Neither 'osv-scanner' nor '.NET SDK' is installed", result.Provenance.ErrorMessage);
    }

    private class MockProcessRunner : IProcessRunner
    {
        private readonly bool _hasOsv;
        private readonly bool _hasDotNet;

        public Func<IReadOnlyList<string>, ProcessResult>? OnOsvRun { get; set; }
        public Func<IReadOnlyList<string>, ProcessResult>? OnDotNetRun { get; set; }

        public MockProcessRunner(bool hasOsv, bool hasDotNet)
        {
            _hasOsv = hasOsv;
            _hasDotNet = hasDotNet;
        }

        public bool ExistsOnPath(string executableName)
        {
            if (executableName.Equals("osv-scanner", StringComparison.OrdinalIgnoreCase)) return _hasOsv;
            if (executableName.Equals("dotnet", StringComparison.OrdinalIgnoreCase)) return _hasDotNet;
            return false;
        }

        public Task<ProcessResult> RunAsync(
            string fileName,
            IReadOnlyList<string> arguments,
            string? workingDirectory = null,
            IReadOnlyDictionary<string, string>? environmentVariables = null,
            CancellationToken cancellationToken = default)
        {
            if (fileName.Equals("osv-scanner", StringComparison.OrdinalIgnoreCase))
            {
                if (!_hasOsv) throw new FileNotFoundException("osv-scanner not found");
                if (arguments.Count == 1 && arguments[0] == "--version")
                {
                    return Task.FromResult(new ProcessResult(0, "1.7.0", "", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow));
                }
                if (OnOsvRun != null) return Task.FromResult(OnOsvRun(arguments));
            }

            if (fileName.Equals("dotnet", StringComparison.OrdinalIgnoreCase))
            {
                if (!_hasDotNet) throw new FileNotFoundException("dotnet not found");
                if (arguments.Count == 1 && arguments[0] == "--version")
                {
                    return Task.FromResult(new ProcessResult(0, "10.0.403", "", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow));
                }
                if (OnDotNetRun != null) return Task.FromResult(OnDotNetRun(arguments));
            }

            return Task.FromResult(new ProcessResult(0, "", "", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow));
        }
    }
}