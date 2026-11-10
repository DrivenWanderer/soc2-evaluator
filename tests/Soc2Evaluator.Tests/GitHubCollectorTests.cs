using System.Net;
using System.Text;
using Soc2Evaluator.Collectors.GitHub;
using Soc2Evaluator.Core.Adapters;
using Soc2Evaluator.Core.Models;
using Soc2Evaluator.Core.Services;
using Soc2Evaluator.Tests.TestHelpers;
using Xunit;

namespace Soc2Evaluator.Tests;

public class GitHubCollectorTests : IDisposable
{
    private readonly string _tempDir;
    private readonly IEvidenceHasher _hasher = new EvidenceHasher();

    public GitHubCollectorTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"soc2-github-test-{Guid.NewGuid():N}");
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
    public async Task GitHubCollector_WhenOffline_SkipsWithNotRunStatus()
    {
        var env = new MockEnvironmentProvider(new() { ["GITHUB_TOKEN"] = "fake-token" });
        var collector = new GitHubCollector(hasher: _hasher, env: env);

        var context = new AdapterExecutionContext(_tempDir, ["CC8.1"], Offline: true);
        var result = await collector.ExecuteAsync(context);

        Assert.Equal("NotRun", result.Provenance.Status);
        Assert.Contains("offline", result.Provenance.ErrorMessage, StringComparison.OrdinalIgnoreCase);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task GitHubCollector_WhenTokenMissing_DegradesWithNotRunAndScopeDocumentation()
    {
        var env = new MockEnvironmentProvider(new() { ["GITHUB_REPOSITORY"] = "acme/web" });
        var collector = new GitHubCollector(hasher: _hasher, env: env);

        var context = new AdapterExecutionContext(_tempDir, ["CC8.1"], Offline: false);
        var result = await collector.ExecuteAsync(context);

        Assert.Equal("NotRun", result.Provenance.Status);
        Assert.Contains("GITHUB_TOKEN", result.Provenance.ErrorMessage);
        Assert.Contains("Administration", result.Provenance.ErrorMessage);
        Assert.Contains("read-only", result.Provenance.ErrorMessage, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task GitHubCollector_WhenNotGitHubRepo_ReturnsNotRun()
    {
        var env = new MockEnvironmentProvider(new() { ["GITHUB_TOKEN"] = "fake-token" });
        var collector = new GitHubCollector(hasher: _hasher, env: env);

        var context = new AdapterExecutionContext(_tempDir, ["CC8.1"], Offline: false);
        var result = await collector.ExecuteAsync(context);

        Assert.Equal("NotRun", result.Provenance.Status);
        Assert.Contains("not identified as a GitHub repository", result.Provenance.ErrorMessage);
    }

    [Fact]
    public async Task GitHubCollector_UnprotectedBranchAndDisabledSecretScanning_DetectsFindings()
    {
        var env = new MockEnvironmentProvider(new()
        {
            ["GITHUB_TOKEN"] = "fake-token",
            ["GITHUB_REPOSITORY"] = "acme/web"
        });

        var handler = new MockHttpMessageHandler(req =>
        {
            var path = req.RequestUri?.AbsolutePath ?? "";
            if (path.Equals("/repos/acme/web", StringComparison.OrdinalIgnoreCase))
            {
                var json = """
                    {
                      "default_branch": "main",
                      "private": true,
                      "security_and_analysis": {
                        "secret_scanning": { "status": "disabled" }
                      }
                    }
                    """;
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
            }
            if (path.Equals("/repos/acme/web/branches/main/protection", StringComparison.OrdinalIgnoreCase))
            {
                return new HttpResponseMessage(HttpStatusCode.NotFound);
            }
            if (path.Equals("/repos/acme/web/environments", StringComparison.OrdinalIgnoreCase))
            {
                var json = """
                    {
                      "environments": [
                        { "name": "production", "protection_rules": [] }
                      ]
                    }
                    """;
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var client = new HttpClient(handler);
        var collector = new GitHubCollector(httpClient: client, hasher: _hasher, env: env);

        var context = new AdapterExecutionContext(_tempDir, ["CC6.1", "CC8.1"], Offline: false);
        var result = await collector.ExecuteAsync(context);

        Assert.Equal("Success", result.Provenance.Status);
        Assert.Equal(3, result.Findings.Count);

        var cicd001 = result.Findings.First(f => f.RuleId == "CICD-001");
        Assert.Equal(FindingCategory.Process, cicd001.Category);
        Assert.Contains("CC8.1", cicd001.TscCriteria);
        Assert.Contains("No branch protection", cicd001.Title);

        var cicd002 = result.Findings.First(f => f.RuleId == "CICD-002");
        Assert.Equal(FindingCategory.Configuration, cicd002.Category);
        Assert.Contains("CC6.1", cicd002.TscCriteria);
        Assert.Contains("Secret Scanning", cicd002.Title);

        var cicd003 = result.Findings.First(f => f.RuleId == "CICD-003");
        Assert.Equal(FindingCategory.Process, cicd003.Category);
        Assert.Contains("CC8.1", cicd003.TscCriteria);
        Assert.Contains("approval gate", cicd003.Title, StringComparison.OrdinalIgnoreCase);

        // Verify evidence artifact
        Assert.Single(result.Artifacts);
        Assert.Equal("github-posture.json", result.Artifacts[0].Name);
        Assert.True(_hasher.VerifyArtifacts(
            new EvidenceManifest("r1", DateTimeOffset.UtcNow, "1.0", "t", null, [], [], result.Artifacts, []),
            result.RawArtifactBytes
        ));
    }

    [Fact]
    public async Task GitHubCollector_ProtectedBranchAndCleanSecrets_ProducesZeroFindings()
    {
        var env = new MockEnvironmentProvider(new()
        {
            ["GITHUB_TOKEN"] = "fake-token",
            ["GITHUB_REPOSITORY"] = "acme/web"
        });

        var handler = new MockHttpMessageHandler(req =>
        {
            var path = req.RequestUri?.AbsolutePath ?? "";
            if (path.Equals("/repos/acme/web", StringComparison.OrdinalIgnoreCase))
            {
                var json = """
                    {
                      "default_branch": "main",
                      "private": true,
                      "security_and_analysis": {
                        "secret_scanning": { "status": "enabled" }
                      }
                    }
                    """;
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
            }
            if (path.Equals("/repos/acme/web/branches/main/protection", StringComparison.OrdinalIgnoreCase))
            {
                var json = """
                    {
                      "required_pull_request_reviews": {
                        "required_approving_review_count": 2
                      }
                    }
                    """;
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
            }
            if (path.Equals("/repos/acme/web/environments", StringComparison.OrdinalIgnoreCase))
            {
                var json = """
                    {
                      "environments": [
                        {
                          "name": "production",
                          "protection_rules": [
                            { "type": "required_reviewers", "reviewers": [ { "id": 1 } ] }
                          ]
                        }
                      ]
                    }
                    """;
                return new HttpResponseMessage(HttpStatusCode.OK) { Content = new StringContent(json, Encoding.UTF8, "application/json") };
            }

            return new HttpResponseMessage(HttpStatusCode.NotFound);
        });

        var client = new HttpClient(handler);
        var collector = new GitHubCollector(httpClient: client, hasher: _hasher, env: env);

        var context = new AdapterExecutionContext(_tempDir, ["CC6.1", "CC8.1"], Offline: false);
        var result = await collector.ExecuteAsync(context);

        Assert.Equal("Success", result.Provenance.Status);
        Assert.Empty(result.Findings);
    }

    [Fact]
    public async Task GitHubCollector_WorkflowFileWithHardcodedSecret_DetectsVulnerabilityAndRedactsEvidence()
    {
        var workflowsDir = Path.Combine(_tempDir, ".github", "workflows");
        Directory.CreateDirectory(workflowsDir);

        var workflowContent = """
            name: Deploy
            on: [push]
            jobs:
              deploy:
                runs-on: ubuntu-latest
                steps:
                  - run: echo "Deploying"
                    env:
                      api_key: test_dummy_token_value_12345
            """;

        await File.WriteAllTextAsync(Path.Combine(workflowsDir, "deploy.yml"), workflowContent);

        var env = new MockEnvironmentProvider(new()
        {
            ["GITHUB_TOKEN"] = "fake-token",
            ["GITHUB_REPOSITORY"] = "acme/web"
        });

        var handler = new MockHttpMessageHandler(_ => new HttpResponseMessage(HttpStatusCode.NotFound));
        var client = new HttpClient(handler);
        var collector = new GitHubCollector(httpClient: client, hasher: _hasher, env: env);

        var context = new AdapterExecutionContext(_tempDir, ["CC6.1"], Offline: false);
        var result = await collector.ExecuteAsync(context);

        var secretFinding = result.Findings.FirstOrDefault(f => f.RuleId == "CICD-002" && f.Title.Contains("workflow"));
        Assert.NotNull(secretFinding);
        Assert.DoesNotContain("test_dummy_token_value_12345", secretFinding.RedactedEvidence);
        Assert.Contains("api_key: ********", secretFinding.RedactedEvidence);
    }
}