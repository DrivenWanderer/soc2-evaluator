using System.Net;
using System.Text;
using Soc2Evaluator.Collectors.AzureDevOps;
using Soc2Evaluator.Core.Adapters;
using Soc2Evaluator.Core.Models;
using Soc2Evaluator.Core.Services;
using Soc2Evaluator.Tests.TestHelpers;
using Xunit;

namespace Soc2Evaluator.Tests;

public class AzureDevOpsCollectorTests : IDisposable
{
    private readonly string _tempDir;
    private readonly IEvidenceHasher _hasher = new EvidenceHasher();

    public AzureDevOpsCollectorTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"soc2-ado-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
            {
                Directory.Delete(_tempDir, true);
            }
        }
        catch
        {
            // Best effort
        }
    }

    [Fact]
    public async Task AzureDevOpsCollector_WhenOffline_SkipsWithNotRunStatus()
    {
        var env = new MockEnvironmentProvider(new() { ["AZURE_DEVOPS_PAT"] = "fake-pat" });
        var collector = new AzureDevOpsCollector(hasher: _hasher, env: env);

        var context = new AdapterExecutionContext(_tempDir, ["CC8.1"], Offline: true);
        var result = await collector.ExecuteAsync(context);

        Assert.Equal("NotRun", result.Provenance.Status);
        Assert.Contains("offline", result.Provenance.ErrorMessage, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task AzureDevOpsCollector_WhenTokenMissing_DegradesWithNotRunAndScopeDocumentation()
    {
        var env = new MockEnvironmentProvider(new()
        {
            ["SYSTEM_TEAMFOUNDATIONCOLLECTIONURI"] = "https://dev.azure.com/myorg",
            ["SYSTEM_TEAMPROJECT"] = "myproj",
            ["BUILD_REPOSITORY_NAME"] = "myrepo"
        });
        var collector = new AzureDevOpsCollector(hasher: _hasher, env: env);

        var context = new AdapterExecutionContext(_tempDir, ["CC8.1"], Offline: false);
        var result = await collector.ExecuteAsync(context);

        Assert.Equal("NotRun", result.Provenance.Status);
        Assert.Contains("AZURE_DEVOPS_PAT", result.Provenance.ErrorMessage);
        Assert.Contains("Code (Read)", result.Provenance.ErrorMessage);
    }

    [Fact]
    public async Task AzureDevOpsCollector_WhenNotAzureDevOpsRepo_ReturnsNotRun()
    {
        var env = new MockEnvironmentProvider(new() { ["AZURE_DEVOPS_PAT"] = "fake-pat" });
        var collector = new AzureDevOpsCollector(hasher: _hasher, env: env);

        var context = new AdapterExecutionContext(_tempDir, ["CC8.1"], Offline: false);
        var result = await collector.ExecuteAsync(context);

        Assert.Equal("NotRun", result.Provenance.Status);
        Assert.Contains("not identified as an Azure DevOps repository", result.Provenance.ErrorMessage);
    }

    [Fact]
    public async Task AzureDevOpsCollector_MissingPoliciesAndApprovals_DetectsFindings()
    {
        var env = new MockEnvironmentProvider(new()
        {
            ["AZURE_DEVOPS_PAT"] = "fake-pat",
            ["SYSTEM_TEAMFOUNDATIONCOLLECTIONURI"] = "https://dev.azure.com/myorg",
            ["SYSTEM_TEAMPROJECT"] = "myproj",
            ["BUILD_REPOSITORY_NAME"] = "myrepo"
        });

        var handler = new MockHttpMessageHandler(req =>
        {
            var path = req.RequestUri?.AbsolutePath ?? "";
            if (path.Contains("_apis/policy/configurations"))
            {
                var json = """{ "count": 0, "value": [] }""";
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
            }
            if (path.Contains("/checks"))
            {
                var json = """{ "count": 0, "value": [] }""";
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
            }
            if (path.Contains("_apis/pipelines/environments"))
            {
                var json = """
                    {
                      "count": 1,
                      "value": [
                        { "id": 10, "name": "production" }
                      ]
                    }
                    """;
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var client = new HttpClient(handler);
        var collector = new AzureDevOpsCollector(httpClient: client, hasher: _hasher, env: env);

        var context = new AdapterExecutionContext(_tempDir, ["CC8.1"], Offline: false);
        var result = await collector.ExecuteAsync(context);

        Assert.Equal("Success", result.Provenance.Status);
        Assert.Equal(2, result.Findings.Count);

        var cicd001 = result.Findings.First(f => f.RuleId == "CICD-001");
        Assert.Equal(FindingCategory.Process, cicd001.Category);
        Assert.Contains("CC8.1", cicd001.TscCriteria);
        Assert.Contains("Minimum number of reviewers", cicd001.RecommendedFix);

        var cicd003 = result.Findings.First(f => f.RuleId == "CICD-003");
        Assert.Equal(FindingCategory.Process, cicd003.Category);
        Assert.Contains("CC8.1", cicd003.TscCriteria);
        Assert.Contains("production", cicd003.Title);

        // Verify evidence artifact
        Assert.Single(result.Artifacts);
        Assert.Equal("azure-devops-posture.json", result.Artifacts[0].Name);
        Assert.True(_hasher.VerifyArtifacts(
            new EvidenceManifest("r1", DateTimeOffset.UtcNow, "1.0", "t", null, [], [], result.Artifacts, []),
            result.RawArtifactBytes
        ));
    }

    [Fact]
    public async Task AzureDevOpsCollector_PipelineFileWithHardcodedSecret_DetectsVulnerabilityAndRedactsEvidence()
    {
        var pipelineContent = """
            trigger:
              - main
            steps:
              - script: echo "Deploying"
                env:
                  token: secret_pat_token_value_98765
            """;

        await File.WriteAllTextAsync(Path.Combine(_tempDir, "azure-pipelines.yml"), pipelineContent);

        var env = new MockEnvironmentProvider(new()
        {
            ["AZURE_DEVOPS_PAT"] = "fake-pat",
            ["SYSTEM_TEAMFOUNDATIONCOLLECTIONURI"] = "https://dev.azure.com/myorg",
            ["SYSTEM_TEAMPROJECT"] = "myproj",
            ["BUILD_REPOSITORY_NAME"] = "myrepo"
        });

        var handler = new MockHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound));
        var client = new HttpClient(handler);
        var collector = new AzureDevOpsCollector(httpClient: client, hasher: _hasher, env: env);

        var context = new AdapterExecutionContext(_tempDir, ["CC6.1"], Offline: false);
        var result = await collector.ExecuteAsync(context);

        var secretFinding = result.Findings.FirstOrDefault(f => f.RuleId == "CICD-002");
        Assert.NotNull(secretFinding);
        Assert.DoesNotContain("secret_pat_token_value_98765", secretFinding.RedactedEvidence);
        Assert.Contains("token: ********", secretFinding.RedactedEvidence);
    }
}