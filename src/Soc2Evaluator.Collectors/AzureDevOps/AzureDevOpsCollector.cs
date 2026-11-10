using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using Soc2Evaluator.Core.Adapters;
using Soc2Evaluator.Core.Models;
using Soc2Evaluator.Core.Services;

namespace Soc2Evaluator.Collectors.AzureDevOps;

public class AzureDevOpsCollector : IScannerAdapter
{
    private readonly HttpClient _httpClient;
    private readonly IEvidenceHasher _hasher;
    private readonly IEnvironmentProvider _env;

    public string ToolName => "azure-devops-collector";
    public string DefaultRulePrefix => "CICD";
    public string InstallGuidance => "Set the AZURE_DEVOPS_PAT or SYSTEM_ACCESSTOKEN environment variable with read-only scopes: Code (Read), Release/Pipelines (Read).";

    public AzureDevOpsCollector(
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
        return _env.GetEnvironmentVariable("AZURE_DEVOPS_PAT") ??
               _env.GetEnvironmentVariable("SYSTEM_ACCESSTOKEN");
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
                ErrorMessage: "Skipped in offline mode: Azure DevOps collector requires network access."
            );

            return new AdapterExecutionResult(offlineProv, findings, artifacts, rawArtifactBytes);
        }

        var (org, project, repo) = ResolveAzureDevOpsRepository(context.TargetPath);
        if (string.IsNullOrWhiteSpace(org) || string.IsNullOrWhiteSpace(project) || string.IsNullOrWhiteSpace(repo))
        {
            var notRunProv = new ToolExecutionProvenance(
                ToolName: ToolName,
                ToolVersion: "1.0.0",
                Arguments: [],
                StartTimeUtc: startTime,
                EndTimeUtc: DateTimeOffset.UtcNow,
                ExitCode: null,
                Status: "NotRun",
                ErrorMessage: "Target is not identified as an Azure DevOps repository (no Azure DevOps remote URL or SYSTEM_TEAMPROJECT variable found)."
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
                ErrorMessage: "AZURE_DEVOPS_PAT or SYSTEM_ACCESSTOKEN environment variable is not configured. Required read-only scopes: Code (Read), Release/Pipelines (Read)."
            );

            return new AdapterExecutionResult(missingTokenProv, findings, artifacts, rawArtifactBytes);
        }

        // 1. Inspect local pipeline files for hardcoded secrets (CICD-002)
        InspectLocalPipelineFiles(context.TargetPath, findings);

        var postureData = new Dictionary<string, object?>();
        postureData["organization"] = org;
        postureData["project"] = project;
        postureData["repository"] = repo;

        try
        {
            // 2. Query branch policies on repository (CICD-001)
            var policyUrl = $"https://dev.azure.com/{org}/{project}/_apis/policy/configurations?api-version=7.1";
            using var policyRequest = CreateApiRequest(HttpMethod.Get, policyUrl, token);
            using var policyResponse = await _httpClient.SendAsync(policyRequest, cancellationToken);

            if (policyResponse.IsSuccessStatusCode)
            {
                var policyJson = await policyResponse.Content.ReadAsStringAsync(cancellationToken);
                using var policyDoc = JsonDocument.Parse(policyJson);
                var policyRoot = policyDoc.RootElement;

                var hasReviewPolicy = false;
                var minReviewers = 0;

                if (policyRoot.TryGetProperty("value", out var policies) && policies.ValueKind == JsonValueKind.Array)
                {
                    foreach (var p in policies.EnumerateArray())
                    {
                        var isEnabled = p.TryGetProperty("isEnabled", out var enProp) && enProp.GetBoolean();
                        if (isEnabled && p.TryGetProperty("settings", out var settings))
                        {
                            if (settings.TryGetProperty("minimumApproverCount", out var countProp))
                            {
                                minReviewers = countProp.GetInt32();
                                hasReviewPolicy = minReviewers >= 1;
                            }
                        }
                    }
                }

                postureData["minimum_approver_count"] = minReviewers;
                postureData["branch_policy_enabled"] = hasReviewPolicy;

                if (!hasReviewPolicy)
                {
                    var loc = new FindingLocation(SettingOrResource: $"{org}/{project}/{repo}/branchPolicies");
                    var fp = Finding.ComputeFingerprint("CICD-001", loc, "ado-no-minimum-reviewers");

                    findings.Add(new Finding(
                        Id: "CICD-001-ADO-001",
                        RuleId: "CICD-001",
                        Title: "Azure DevOps branch policy does not enforce minimum required reviewers",
                        SourceName: ToolName,
                        SourceVersion: "1.0.0",
                        TscCriteria: ["CC8.1"],
                        OrgControlId: null,
                        Severity: Severity.High,
                        Category: FindingCategory.Process,
                        Location: loc,
                        RedactedEvidence: $"Branch policy minimumApproverCount: {minReviewers}",
                        RiskExplanation: "Azure DevOps branch policies on default branches do not enforce at least 1 mandatory approving reviewer. Code can be merged without peer review, violating SOC 2 CC8.1 change control principles.",
                        RecommendedFix: "Navigate to Project Settings > Repositories > Policies and configure a 'Minimum number of reviewers' policy (at least 1 approver) on the default branch.",
                        Effort: EffortEstimate.Low,
                        Confidence: ConfidenceLevel.High,
                        Fingerprint: fp
                    ));
                }
            }

            // 3. Query environments for approval checks (CICD-003)
            var envsUrl = $"https://dev.azure.com/{org}/{project}/_apis/pipelines/environments?api-version=7.1-preview.1";
            using var envsRequest = CreateApiRequest(HttpMethod.Get, envsUrl, token);
            using var envsResponse = await _httpClient.SendAsync(envsRequest, cancellationToken);

            if (envsResponse.IsSuccessStatusCode)
            {
                var envsJson = await envsResponse.Content.ReadAsStringAsync(cancellationToken);
                using var envsDoc = JsonDocument.Parse(envsJson);
                var envsRoot = envsDoc.RootElement;

                if (envsRoot.TryGetProperty("value", out var envList) && envList.ValueKind == JsonValueKind.Array)
                {
                    postureData["environment_count"] = envList.GetArrayLength();
                    foreach (var envItem in envList.EnumerateArray())
                    {
                        var envName = envItem.TryGetProperty("name", out var np) ? np.GetString() ?? "" : "";
                        var isProd = Regex.IsMatch(envName, @"(?i)(prod|production|release|live)");

                        if (isProd)
                        {
                            var hasApproval = false;
                            var envId = envItem.TryGetProperty("id", out var idProp) ? idProp.GetInt32() : 0;

                            // Query environment checks
                            if (envId > 0)
                            {
                                var checksUrl = $"https://dev.azure.com/{org}/{project}/_apis/pipelines/environments/{envId}/checks?api-version=7.1-preview.1";
                                using var checksReq = CreateApiRequest(HttpMethod.Get, checksUrl, token);
                                using var checksResp = await _httpClient.SendAsync(checksReq, cancellationToken);

                                if (checksResp.IsSuccessStatusCode)
                                {
                                    var checksJson = await checksResp.Content.ReadAsStringAsync(cancellationToken);
                                    using var checksDoc = JsonDocument.Parse(checksJson);
                                    if (checksDoc.RootElement.TryGetProperty("value", out var cVal) && cVal.GetArrayLength() > 0)
                                    {
                                        hasApproval = true;
                                    }
                                }
                            }

                            if (!hasApproval)
                            {
                                var loc = new FindingLocation(SettingOrResource: $"{org}/{project}/environments/{envName}");
                                var fp = Finding.ComputeFingerprint("CICD-003", loc, $"ado-env-{envName}-no-approval");

                                findings.Add(new Finding(
                                    Id: $"CICD-003-ADO-{envName}",
                                    RuleId: "CICD-003",
                                    Title: $"Azure DevOps production environment '{envName}' lacks required approval gate",
                                    SourceName: ToolName,
                                    SourceVersion: "1.0.0",
                                    TscCriteria: ["CC8.1"],
                                    OrgControlId: null,
                                    Severity: Severity.High,
                                    Category: FindingCategory.Process,
                                    Location: loc,
                                    RedactedEvidence: $"Azure DevOps Environment '{envName}' has 0 configured approval checks.",
                                    RiskExplanation: $"Environment '{envName}' is deployed without pre-deployment approval checks. Direct automated deployments without designated approval violate SOC 2 CC8.1 change management gates.",
                                    RecommendedFix: $"In Azure Pipelines > Environments > '{envName}' > Approvals and checks, add an 'Approvals' check specifying designated approvers.",
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
                Arguments: ["GET", $"dev.azure.com/{org}/{project}/*"],
                StartTimeUtc: startTime,
                EndTimeUtc: DateTimeOffset.UtcNow,
                ExitCode: -1,
                Status: "Failed",
                ErrorMessage: $"Exception communicating with Azure DevOps API: {ex.Message}"
            );

            return new AdapterExecutionResult(failProv, findings, artifacts, rawArtifactBytes);
        }

        var postureJson = JsonSerializer.Serialize(postureData, new JsonSerializerOptions { WriteIndented = true });
        var artifactBytes = Encoding.UTF8.GetBytes(postureJson);
        var artifactHash = _hasher.ComputeSha256(artifactBytes);
        var artifactName = "azure-devops-posture.json";

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
            Arguments: ["GET", $"dev.azure.com/{org}/{project}/*"],
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
        request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
        var basicAuth = Convert.ToBase64String(Encoding.ASCII.GetBytes($":{token}"));
        request.Headers.Authorization = new AuthenticationHeaderValue("Basic", basicAuth);
        return request;
    }

    private (string? Org, string? Project, string? Repo) ResolveAzureDevOpsRepository(string targetPath)
    {
        var envOrg = _env.GetEnvironmentVariable("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI");
        var envProj = _env.GetEnvironmentVariable("SYSTEM_TEAMPROJECT");
        var envRepo = _env.GetEnvironmentVariable("BUILD_REPOSITORY_NAME");

        if (!string.IsNullOrWhiteSpace(envOrg) && !string.IsNullOrWhiteSpace(envProj) && !string.IsNullOrWhiteSpace(envRepo))
        {
            var orgClean = envOrg.TrimEnd('/').Split('/').Last();
            return (orgClean, envProj.Trim(), envRepo.Trim());
        }

        // Local git config
        var gitConfigPath = Path.Combine(targetPath, ".git", "config");
        if (File.Exists(gitConfigPath))
        {
            try
            {
                var text = File.ReadAllText(gitConfigPath);
                var match = Regex.Match(text, @"dev\.azure\.com/(?<org>[^/]+)/(?<proj>[^/]+)/_git/(?<repo>[^/.\s]+)", RegexOptions.IgnoreCase);
                if (match.Success)
                {
                    return (match.Groups["org"].Value, match.Groups["proj"].Value, match.Groups["repo"].Value);
                }

                var sshMatch = Regex.Match(text, @"vs-ssh\.visualstudio\.com:v3/(?<org>[^/]+)/(?<proj>[^/]+)/(?<repo>[^/.\s]+)", RegexOptions.IgnoreCase);
                if (sshMatch.Success)
                {
                    return (sshMatch.Groups["org"].Value, sshMatch.Groups["proj"].Value, sshMatch.Groups["repo"].Value);
                }
            }
            catch
            {
                // Best effort
            }
        }

        return (null, null, null);
    }

    private static void InspectLocalPipelineFiles(string targetPath, List<Finding> findings)
    {
        if (!Directory.Exists(targetPath)) return;

        var files = Directory.GetFiles(targetPath, "azure-pipelines*.yml", SearchOption.AllDirectories)
            .Concat(Directory.GetFiles(targetPath, "azure-pipelines*.yaml", SearchOption.AllDirectories))
            .ToList();

        var secretRegex = new Regex(
            @"(?i)(password|token|secret|api[_-]?key)\s*:\s*(?!['""]?\$\(\s*[a-zA-Z0-9_\.]+\s*\))['""]?([a-zA-Z0-9_\-\.]{12,})['""]?",
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
                        var fp = Finding.ComputeFingerprint("CICD-002", loc, "ado-pipeline-secret");

                        findings.Add(new Finding(
                            Id: $"CICD-002-ADO-WF-{findingIndex++:D3}",
                            RuleId: "CICD-002",
                            Title: "Potentially hardcoded secret in Azure Pipelines file",
                            SourceName: "azure-devops-collector",
                            SourceVersion: "1.0.0",
                            TscCriteria: ["CC6.1"],
                            OrgControlId: null,
                            Severity: Severity.High,
                            Category: FindingCategory.Configuration,
                            Location: loc,
                            RedactedEvidence: Regex.Replace(line.Trim(), @"(?i)(password|token|secret|api[_-]?key)\s*:\s*.*", "$1: ********"),
                            RiskExplanation: "Hardcoded credentials in Azure Pipelines files expose secrets to anyone with repository read permissions (SOC 2 CC6.1).",
                            RecommendedFix: "Move sensitive values to Azure DevOps Pipeline Secrets or Azure Key Vault task bindings.",
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