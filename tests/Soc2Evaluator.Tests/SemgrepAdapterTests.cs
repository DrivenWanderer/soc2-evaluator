using Soc2Evaluator.Adapters;
using Soc2Evaluator.Adapters.Semgrep;
using Soc2Evaluator.Core.Adapters;
using Soc2Evaluator.Core.Models;
using Soc2Evaluator.Core.Services;
using Soc2Evaluator.Tests.TestHelpers;
using Xunit;

namespace Soc2Evaluator.Tests;

public class SemgrepAdapterTests
{
    private readonly IEvidenceHasher _hasher = new EvidenceHasher();

    [Fact]
    public async Task SemgrepAdapter_WhenToolMissing_DegradesGracefullyWithNotRun()
    {
        var mockRunner = new MockProcessRunner(isToolAvailable: false);
        var adapter = new SemgrepAdapter(mockRunner, _hasher);

        var context = new AdapterExecutionContext("C:/some/repo", ["CC6.1"], Offline: false);
        var result = await adapter.ExecuteAsync(context);

        Assert.Equal("NotRun", result.Provenance.Status);
        Assert.Contains("not installed", result.Provenance.ErrorMessage);
        Assert.Contains("pip install semgrep", result.Provenance.ErrorMessage);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task SemgrepAdapter_WhenOffline_SkipsWithNotRunStatus()
    {
        var mockRunner = new MockProcessRunner(isToolAvailable: true);
        var adapter = new SemgrepAdapter(mockRunner, _hasher);

        var context = new AdapterExecutionContext("C:/some/repo", ["CC6.1"], Offline: true);
        var result = await adapter.ExecuteAsync(context);

        Assert.Equal("NotRun", result.Provenance.Status);
        Assert.Contains("offline", result.Provenance.ErrorMessage, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task SemgrepAdapter_WhenToolExecutes_NormalizesSarifAndMapsRuleIds()
    {
        var sampleSarif = """
            {
              "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
              "version": "2.1.0",
              "runs": [
                {
                  "tool": {
                    "driver": {
                      "name": "semgrep",
                      "version": "1.80.0"
                    }
                  },
                  "results": [
                    {
                      "ruleId": "csharp.lang.security.weak-crypto.md5",
                      "level": "error",
                      "message": { "text": "Weak cryptographic algorithm MD5 detected" },
                      "locations": [
                        {
                          "physicalLocation": {
                            "artifactLocation": { "uri": "src/App/CryptoService.cs" },
                            "region": { "startLine": 25, "snippet": { "text": "MD5.Create()" } }
                          }
                        }
                      ]
                    },
                    {
                      "ruleId": "csharp.aspnet.missing-authorize",
                      "level": "warning",
                      "message": { "text": "Endpoint allows anonymous access without auth attribute" },
                      "locations": [
                        {
                          "physicalLocation": {
                            "artifactLocation": { "uri": "src/App/Controllers/AdminController.cs" },
                            "region": { "startLine": 14, "snippet": { "text": "public IActionResult GetSecrets()" } }
                          }
                        }
                      ]
                    },
                    {
                      "ruleId": "csharp.lang.security.disabled-cert-validation",
                      "level": "error",
                      "message": { "text": "ServerCertificateCustomValidationCallback always returns true" },
                      "locations": [
                        {
                          "physicalLocation": {
                            "artifactLocation": { "uri": "src/App/HttpClientConfig.cs" },
                            "region": { "startLine": 30, "snippet": { "text": "callback = (msg, cert, chain, err) => true" } }
                          }
                        }
                      ]
                    },
                    {
                      "ruleId": "csharp.lang.security.sqli.concatenation",
                      "level": "error",
                      "message": { "text": "SQL query formed by string concatenation" },
                      "locations": [
                        {
                          "physicalLocation": {
                            "artifactLocation": { "uri": "src/App/UserRepository.cs" },
                            "region": { "startLine": 45, "snippet": { "text": "var sql = \"SELECT * FROM Users WHERE id = \" + id;" } }
                          }
                        }
                      ]
                    },
                    {
                      "ruleId": "csharp.cors.permissive-cors-policy",
                      "level": "warning",
                      "message": { "text": "CORS policy allows AnyOrigin with credentials" },
                      "locations": [
                        {
                          "physicalLocation": {
                            "artifactLocation": { "uri": "src/App/Program.cs" },
                            "region": { "startLine": 20, "snippet": { "text": "builder.AllowAnyOrigin()" } }
                          }
                        }
                      ]
                    }
                  ]
                }
              ]
            }
            """;

        var mockRunner = new MockProcessRunner(
            isToolAvailable: true,
            versionOutput: "1.80.0",
            onRun: (cmd, args) =>
            {
                var outputIndex = -1;
                for (var i = 0; i < args.Count; i++)
                {
                    if (args[i] == "--output")
                    {
                        outputIndex = i;
                        break;
                    }
                }

                if (outputIndex >= 0 && outputIndex + 1 < args.Count)
                {
                    File.WriteAllText(args[outputIndex + 1], sampleSarif);
                }
                return new ProcessResult(0, "Scan completed", string.Empty, DateTimeOffset.UtcNow, DateTimeOffset.UtcNow);
            }
        );

        var adapter = new SemgrepAdapter(mockRunner, _hasher);
        var context = new AdapterExecutionContext("C:/test/repo", ["CC6.1"], Offline: false);

        var result = await adapter.ExecuteAsync(context);

        Assert.Equal("Success", result.Provenance.Status);
        Assert.Equal("1.80.0", result.Provenance.ToolVersion);
        Assert.Equal(5, result.Findings.Count);

        // Verify mapped rules and TSC criteria
        var sec002 = result.Findings.First(f => f.RuleId == "SEC-002");
        Assert.Contains("CC6.1", sec002.TscCriteria);
        Assert.Contains("CC6.7", sec002.TscCriteria);
        Assert.Equal(Severity.High, sec002.Severity);
        Assert.Equal("src/App/CryptoService.cs", sec002.Location?.FilePath);

        var sec003 = result.Findings.First(f => f.RuleId == "SEC-003");
        Assert.Contains("CC6.1", sec003.TscCriteria);
        Assert.Contains("CC6.3", sec003.TscCriteria);

        var sec004 = result.Findings.First(f => f.RuleId == "SEC-004");
        Assert.Contains("CC6.7", sec004.TscCriteria);

        var sec005 = result.Findings.First(f => f.RuleId == "SEC-005");
        Assert.Contains("CC6.1", sec005.TscCriteria);
        Assert.Contains("CC7.1", sec005.TscCriteria);

        var cfg005 = result.Findings.First(f => f.RuleId == "CFG-005");
        Assert.Contains("CC6.6", cfg005.TscCriteria);

        // Verify evidence artifact hashing
        Assert.Single(result.Artifacts);
        var artifact = result.Artifacts[0];
        Assert.Equal("semgrep.sarif", artifact.Name);
        Assert.True(_hasher.VerifyArtifacts(
            new EvidenceManifest("r1", DateTimeOffset.UtcNow, "1.0", "t", null, [], [], result.Artifacts, []),
            result.RawArtifactBytes
        ));
    }
}