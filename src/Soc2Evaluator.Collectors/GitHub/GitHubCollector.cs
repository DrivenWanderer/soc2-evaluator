using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Soc2Evaluator.Core.Adapters;
using Soc2Evaluator.Core.Models;
using Soc2Evaluator.Core.Services;

namespace Soc2Evaluator.Collectors.GitHub;

public class GitHubCollector : IScannerAdapter
{
    private readonly HttpClient _httpClient;
    private readonly IEvidenceHasher _hasher;
    private readonly IEnvironmentProvider _env;

    public string ToolName => "github-collector";
    public string DefaultRulePrefix => "CICD";
    public string InstallGuidance => "Set the GITHUB_TOKEN or GH_TOKEN environment variable with read-only scopes: Administration (read-only), Metadata (read-only), Environments (read-only).";

    public GitHubCollector(
        HttpClient? httpClient = null,
        IEvidenceHasher? hasher = null,
        IEnvironmentProvider? env = null)
    {
        _httpClient = httpClient ?? new HttpClient();
        _hasher = hasher ?? new EvidenceHasher();
        _env = env ?? new SystemEnvironmentProvider();
    }

    public Task<bool> IsAvailableAsync(CancellationToken cancellationToken = default)
    {
        var token = GetToken();
        return Task.FromResult(!string.IsNullOrWhiteSpace(token));
    }

    public Task<string?> GetVersionAsync(CancellationToken cancellationToken = default)
    {
        return Task.FromResult<string?>("1.0.0");
    }

    private string? GetToken()
    {
        return _env.GetEnvironmentVariable("GITHUB_TOKEN") ??
               _env.GetEnvironmentVariable("GH_TOKEN");
    }

    public async Task<AdapterExecutionResult> ExecuteAsync(AdapterExecutionContext context, CancellationToken cancellationToken = default)
    {
        var startTime = DateTimeOffset.UtcNow;
        var findings = new List<Finding>();
        var artifacts = new List<EvidenceArtifact>();
        var rawArtifactBytes = new Dictionary<string, byte[]>();

        if (context.Offline)
        {
            var offlineProv = new ToolExecutionProvenance(
                ToolName: ToolName,
                ToolVersion: "1.0.0",
                Arguments: [],
                StartTimeUtc: startTime,
                EndTimeUtc: DateTimeOffset.UtcNow,
                ExitCode: null,
                Status: "NotRun",
                ErrorMessage: "Skipped in offline mode: GitHub collector requires network access."
            );

            return new AdapterExecutionResult(offlineProv, findings, artifacts, rawArtifactBytes);
        }

        var repoIdentifier = ResolveGitHubRepository(context.TargetPath);
        if (string.IsNullOrWhiteSpace(repoIdentifier))
        {
            var notRunProv = new ToolExecutionProvenance(
                ToolName: ToolName,
                ToolVersion: "1.0.0",
                Arguments: [],
                StartTimeUtc: startTime,
                EndTimeUtc: DateTimeOffset.UtcNow,
                ExitCode: null,
                Status: "NotRun",
                ErrorMessage: "Target is not identified as a GitHub repository (no GitHub remote URL or GITHUB_REPOSITORY variable found)."
            );

            return new AdapterExecutionResult(notRunProv, findings, artifacts, rawArtifactBytes);
        }

        var token = GetToken();
        if (string.IsNullOrWhiteSpace(token))
        {
            var missingTokenProv = new ToolExecutionProvenance(
                ToolName: ToolName,
                ToolVersion: "1.0.0",
                Arguments: [],
                StartTimeUtc: startTime,
                EndTimeUtc: DateTimeOffset.UtcNow,
                ExitCode: null,
                Status: "NotRun",
                ErrorMessage: "GITHUB_TOKEN or GH_TOKEN environment variable is not configured. Required read-only scopes: Administration (read-only for branch protection & secret scanning), Metadata (read-only), Environments (read-only)."
            );

            return new AdapterExecutionResult(missingTokenProv, findings, artifacts, rawArtifactBytes);
        }

        // 1. Inspect local workflow files for hardcoded secrets (CICD-002)
        InspectLocalWorkflowFiles(context.TargetPath, findings);

        // Prepare GitHub API request context
        var postureData = new Dictionary<string, object?>();
        postureData["repository"] = repoIdentifier;

        try
        {
            using var repoRequest = CreateApiRequest(HttpMethod.Get, $"https://api.github.com/repos/{repoIdentifier}", token);
            using var repoResponse = await _httpClient.SendAsync(repoRequest, cancellationToken);

            if (!repoResponse.IsSuccessStatusCode)
            {
                var errBody = await repoResponse.Content.ReadAsStringAsync(cancellationToken);
                var failProv = new ToolExecutionProvenance(
                    ToolName: ToolName,
                    ToolVersion: "1.0.0",
                    Arguments: ["GET", $"repos/{repoIdentifier}"],
                    StartTimeUtc: startTime,
                    EndTimeUtc: DateTimeOffset.UtcNow,
                    ExitCode: (int)repoResponse.StatusCode,
                    Status: "Failed",
                    ErrorMessage: $"GitHub API returned {(int)repoResponse.StatusCode} ({repoResponse.ReasonPhrase}): {errBody}"
                );

                return new AdapterExecutionResult(failProv, findings, artifacts, rawArtifactBytes);
            }

            var repoJson = await repoResponse.Content.ReadAsStringAsync(cancellationToken);
            using var repoDoc = JsonDocument.Parse(repoJson);
            var repoRoot = repoDoc.RootElement;

            var defaultBranch = repoRoot.TryGetProperty("default_branch", out var dbProp) ? dbProp.GetString() ?? "main" : "main";
            var isPrivate = repoRoot.TryGetProperty("private", out var privProp) && privProp.GetBoolean();
            postureData["default_branch"] = defaultBranch;
            postureData["is_private"] = isPrivate;

            // Check Secret Scanning status (CICD-002)
            var secretScanningStatus = "disabled";
            if (repoRoot.TryGetProperty("security_and_analysis", out var secAnalysis) &&
                secAnalysis.TryGetProperty("secret_scanning", out var secScan) &&
                secScan.TryGetProperty("status", out var statusProp))
            {
                secretScanningStatus = statusProp.GetString() ?? "disabled";
            }
            postureData["secret_scanning_status"] = secretScanningStatus;

            if (!string.Equals(secretScanningStatus, "enabled", StringComparison.OrdinalIgnoreCase))
            {
                var loc = new FindingLocation(SettingOrResource: $"{repoIdentifier}/security_and_analysis.secret_scanning");
                var fp = Finding.ComputeFingerprint("CICD-002", loc, "secret-scanning-disabled");

                findings.Add(new Finding(
                    Id: "CICD-002-001",
                    RuleId: "CICD-002",
                    Title: "GitHub Secret Scanning is not enabled on repository",
                    SourceName: ToolName,
                    SourceVersion: "1.0.0",
                    TscCriteria: ["CC6.1"],
                    OrgControlId: null,
                    Severity: Severity.High,
                    Category: FindingCategory.Configuration,
                    Location: loc,
                    RedactedEvidence: $"Repository {repoIdentifier} has secret_scanning: {secretScanningStatus}",
                    RiskExplanation: "Automated secret scanning is not enabled on this repository. Accidentally committed credentials or API tokens will not be automatically detected and revoked, increasing the risk of credential exposure and lateral compromise (SOC 2 CC6.1).",
                    RecommendedFix: "Navigate to Repository Settings > Code security and analysis and enable 'Secret scanning' (and 'Push protection' where available).",
                    Effort: EffortEstimate.Low,
                    Confidence: ConfidenceLevel.High,
                    Fingerprint: fp
                ));
            }

            // 2. Check Branch Protection on default branch (CICD-001)
            using var bpRequest = CreateApiRequest(HttpMethod.Get, $"https://api.github.com/repos/{repoIdentifier}/branches/{defaultBranch}/protection", token);
            using var bpResponse = await _httpClient.SendAsync(bpRequest, cancellationToken);

            if (bpResponse.StatusCode == System.Net.HttpStatusCode.NotFound)
            {
                postureData["branch_protection_enabled"] = false;
                var loc = new FindingLocation(SettingOrResource: $"{repoIdentifier}/branches/{defaultBranch}/protection");
                var fp = Finding.ComputeFingerprint("CICD-001", loc, "no-branch-protection");

                findings.Add(new Finding(
                    Id: "CICD-001-001",
                    RuleId: "CICD-001",
                    Title: $"No branch protection configured on default branch '{defaultBranch}'",
                    SourceName: ToolName,
                    SourceVersion: "1.0.0",
                    TscCriteria: ["CC8.1"],
                    OrgControlId: null,
                    Severity: Severity.High,
                    Category: FindingCategory.Process,
                    Location: loc,
                    RedactedEvidence: $"GET /repos/{repoIdentifier}/branches/{defaultBranch}/protection returned 404 (Unprotected)",
                    RiskExplanation: $"The default branch '{defaultBranch}' lacks branch protection rules. Any developer with write access can push code directly or bypass peer review, violating SOC 2 CC8.1 change management controls.",
                    RecommendedFix: $"Enable branch protection rules for '{defaultBranch}' requiring pull request reviews prior to merging and blocking direct pushes.",
                    Effort: EffortEstimate.Low,
                    Confidence: ConfidenceLevel.High,
                    Fingerprint: fp
                ));
            }
            else if (bpResponse.IsSuccessStatusCode)
            {
                postureData["branch_protection_enabled"] = true;
                var bpJson = await bpResponse.Content.ReadAsStringAsync(cancellationToken);
                using var bpDoc = JsonDocument.Parse(bpJson);
                var bpRoot = bpDoc.RootElement;

                var requiredReviews = 0;
                if (bpRoot.TryGetProperty("required_pull_request_reviews", out var prReviews) &&
                    prReviews.TryGetProperty("required_approving_review_count", out var revCountProp))
                {
                    requiredReviews = revCountProp.GetInt32();
                }
                postureData["required_approving_review_count"] = requiredReviews;

                if (requiredReviews < 1)
                {
                    var loc = new FindingLocation(SettingOrResource: $"{repoIdentifier}/branches/{defaultBranch}/protection/required_pull_request_reviews");
                    var fp = Finding.ComputeFingerprint("CICD-001", loc, "zero-required-reviews");

                    findings.Add(new Finding(
                        Id: "CICD-001-002",
                        RuleId: "CICD-001",
                        Title: $"Branch protection on '{defaultBranch}' does not require pull request reviews",
                        SourceName: ToolName,
                        SourceVersion: "1.0.0",
                        TscCriteria: ["CC8.1"],
                        OrgControlId: null,
                        Severity: Severity.High,
                        Category: FindingCategory.Process,
                        Location: loc,
                        RedactedEvidence: $"required_approving_review_count: {requiredReviews}",
                        RiskExplanation: $"Pull request reviews are not required (count: {requiredReviews}) before merging to '{defaultBranch}'. Peer code review is a fundamental change management control under SOC 2 CC8.1.",
                        RecommendedFix: "Update branch protection rules to require at least 1 approving review from a peer or code owner before merging.",
                        Effort: EffortEstimate.Low,
                        Confidence: ConfidenceLevel.High,
                        Fingerprint: fp
                    ));
                }
            }

            // 3. Check Production Environments & Approval Gates (CICD-003)
            using var envRequest = CreateApiRequest(HttpMethod.Get, $"https://api.github.com/repos/{repoIdentifier}/environments", token);
            using var envResponse = await _httpClient.SendAsync(envRequest, cancellationToken);

            if (envResponse.IsSuccessStatusCode)
            {
                var envJson = await envResponse.Content.ReadAsStringAsync(cancellationToken);
                using var envDoc = JsonDocument.Parse(envJson);
                var envRoot = envDoc.RootElement;

                if (envRoot.TryGetProperty("environments", out var envList) && envList.ValueKind == JsonValueKind.Array)
                {
                    var envCount = envList.GetArrayLength();
                    postureData["environment_count"] = envCount;

                    foreach (var envItem in envList.EnumerateArray())
                    {
                        var envName = envItem.TryGetProperty("name", out var nameProp) ? nameProp.GetString() ?? "" : "";
                        var isProd = Regex.IsMatch(envName, @"(?i)(prod|production|release|live)");

                        if (isProd)
                        {
                            var hasReviewers = false;
                            if (envItem.TryGetProperty("protection_rules", out var protRules) && protRules.ValueKind == JsonValueKind.Array)
                            {
                                foreach (var rule in protRules.EnumerateArray())
                                {
                                    var type = rule.TryGetProperty("type", out var tProp) ? tProp.GetString() : "";
                                    if (string.Equals(type, "required_reviewers", StringComparison.OrdinalIgnoreCase))
                                    {
                                        if (rule.TryGetProperty("reviewers", out var reviewers) && reviewers.GetArrayLength() > 0)
                                        {
                                            hasReviewers = true;
                                        }
                                    }
                                }
                            }

                            if (!hasReviewers)
                            {
                                var loc = new FindingLocation(SettingOrResource: $"{repoIdentifier}/environments/{envName}");
                                var fp = Finding.ComputeFingerprint("CICD-003", loc, $"env-{envName}-no-approval-gate");

                                findings.Add(new Finding(
                                    Id: $"CICD-003-{envName}",
                                    RuleId: "CICD-003",
                                    Title: $"Production deployment environment '{envName}' lacks required approval gate",
                                    SourceName: ToolName,
                                    SourceVersion: "1.0.0",
                                    TscCriteria: ["CC8.1"],
                                    OrgControlId: null,
                                    Severity: Severity.High,
                                    Category: FindingCategory.Process,
                                    Location: loc,
                                    RedactedEvidence: $"Environment '{envName}' has no required_reviewers protection rule configured.",
                                    RiskExplanation: $"Environment '{envName}' is configured without deployment approval gates or required reviewers. Automated deployments to production without authorized sign-off violate SOC 2 CC8.1 change control gates.",
                                    RecommendedFix: $"Configure environment protection rules for '{envName}' requiring designated approvers prior to deployment execution.",
                                    Effort: EffortEstimate.Low,
                                    Confidence: ConfidenceLevel.High,
                                    Fingerprint: fp
                                ));
                            }
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            var failProv = new ToolExecutionProvenance(
                ToolName: ToolName,
                ToolVersion: "1.0.0",
                Arguments: ["GET", $"repos/{repoIdentifier}"],
                StartTimeUtc: startTime,
                EndTimeUtc: DateTimeOffset.UtcNow,
                ExitCode: -1,
                Status: "Failed",
                ErrorMessage: $"Exception communicating with GitHub API: {ex.Message}"
            );

            return new AdapterExecutionResult(failProv, findings, artifacts, rawArtifactBytes);
        }

        // Persist posture evidence artifact
        var postureJson = JsonSerializer.Serialize(postureData, new JsonSerializerOptions { WriteIndented = true });
        var artifactBytes = Encoding.UTF8.GetBytes(postureJson);
        var artifactHash = _hasher.ComputeSha256(artifactBytes);
        var artifactName = "github-posture.json";

        artifacts.Add(new EvidenceArtifact(
            Name: artifactName,
            ContentType: "application/json",
            Sha256Hash: artifactHash,
            RelativePath: $"evidence/{artifactName}"
        ));
        rawArtifactBytes[artifactName] = artifactBytes;

        var successProv = new ToolExecutionProvenance(
            ToolName: ToolName,
            ToolVersion: "1.0.0",
            Arguments: ["GET", $"repos/{repoIdentifier}/*"],
            StartTimeUtc: startTime,
            EndTimeUtc: DateTimeOffset.UtcNow,
            ExitCode: 0,
            Status: "Success"
        );

        return new AdapterExecutionResult(successProv, findings, artifacts, rawArtifactBytes);
    }

    private static HttpRequestMessage CreateApiRequest(HttpMethod method, string url, string token)
    {
        var request = new HttpRequestMessage(method, url);
        request.Headers.UserAgent.Add(new ProductInfoHeaderValue("soc2evaluator", "0.1.0"));
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/vnd.github+json"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        return request;
    }

    private string? ResolveGitHubRepository(string targetPath)
    {
        // 1. Env variable
        var envRepo = _env.GetEnvironmentVariable("GITHUB_REPOSITORY");
        if (!string.IsNullOrWhiteSpace(envRepo)) return envRepo.Trim();

        // 2. URL target
        if (targetPath.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
            targetPath.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
        {
            var match = Regex.Match(targetPath, @"github\.com/(?<owner>[^/]+)/(?<repo>[^/.]+)", RegexOptions.IgnoreCase);
            if (match.Success)
            {
                return $"{match.Groups["owner"].Value}/{match.Groups["repo"].Value}";
            }
        }

        // 3. Local git config
        var gitConfigPath = Path.Combine(targetPath, ".git", "config");
        if (File.Exists(gitConfigPath))
        {
            try
            {
                var text = File.ReadAllText(gitConfigPath);
                var match = Regex.Match(text, @"github\.com[:/](?<owner>[^/]+)/(?<repo>[^/.\s]+)", RegexOptions.IgnoreCase);
                if (match.Success)
                {
                    return $"{match.Groups["owner"].Value}/{match.Groups["repo"].Value}";
                }
            }
            catch
            {
                // Best effort
            }
        }

        return null;
    }

    private static void InspectLocalWorkflowFiles(string targetPath, List<Finding> findings)
    {
        var workflowsDir = Path.Combine(targetPath, ".github", "workflows");
        if (!Directory.Exists(workflowsDir)) return;

        var files = Directory.GetFiles(workflowsDir, "*.yml", SearchOption.AllDirectories)
            .Concat(Directory.GetFiles(workflowsDir, "*.yaml", SearchOption.AllDirectories));

        var secretRegex = new Regex(
            @"(?i)(password|token|secret|api[_-]?key)\s*:\s*(?!['""]?\$\{\{\s*secrets\.)['""]?([a-zA-Z0-9_\-\.]{12,})['""]?",
            RegexOptions.Compiled
        );

        var findingIndex = 1;

        foreach (var file in files)
        {
            try
            {
                var lines = File.ReadAllLines(file);
                for (var i = 0; i < lines.Length; i++)
                {
                    var line = lines[i];
                    var trimmed = line.Trim();
                    if (trimmed.StartsWith("#")) continue;

                    var match = secretRegex.Match(line);
                    if (match.Success)
                    {
                        var relPath = Path.GetRelativePath(targetPath, file).Replace('\\', '/');
                        var loc = new FindingLocation(relPath, i + 1, match.Index + 1);
                        var fp = Finding.ComputeFingerprint("CICD-002", loc, "hardcoded-pipeline-secret");

                        findings.Add(new Finding(
                            Id: $"CICD-002-WF-{findingIndex++:D3}",
                            RuleId: "CICD-002",
                            Title: "Potentially hardcoded secret in GitHub Actions workflow file",
                            SourceName: "github-collector",
                            SourceVersion: "1.0.0",
                            TscCriteria: ["CC6.1"],
                            OrgControlId: null,
                            Severity: Severity.High,
                            Category: FindingCategory.Configuration,
                            Location: loc,
                            RedactedEvidence: Regex.Replace(line.Trim(), @"(?i)(password|token|secret|api[_-]?key)\s*:\s*.*", "$1: ********"),
                            RiskExplanation: "Hardcoded credentials or API tokens in CI workflow definition files risk credential exposure to anyone with repository read access (SOC 2 CC6.1).",
                            RecommendedFix: "Move secret values to GitHub Repository Secrets and reference them via '${{ secrets.YOUR_SECRET_NAME }}'.",
                            Effort: EffortEstimate.Low,
                            Confidence: ConfidenceLevel.High,
                            Fingerprint: fp
                        ));
                    }
                }
            }
            catch
            {
                // Best effort
            }
        }
    }
}