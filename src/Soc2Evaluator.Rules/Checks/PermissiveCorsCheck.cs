using System.Text.RegularExpressions;
using Soc2Evaluator.Core.Models;

namespace Soc2Evaluator.Rules.Checks;

public class PermissiveCorsCheck : IRuleCheck
{
    public string RuleId => "CFG-005";
    public string Title => "Overly permissive CORS policy";
    public IReadOnlyList<string> TscCriteria => ["CC6.6"];

    private static readonly Regex PermissiveCorsPattern = new(
        @"(SetIsOriginAllowed\s*\(\s*(?:_|\w+)\s*=>\s*true\s*\))|(WithOrigins\s*\(\s*""\*""\s*\))|(AllowAnyOrigin\s*\(\s*\)\s*\.\s*AllowCredentials\s*\(\s*\))|(AllowCredentials\s*\(\s*\)\s*\.\s*AllowAnyOrigin\s*\(\s*\))",
        RegexOptions.Compiled | RegexOptions.IgnoreCase
    );

    public Task<IReadOnlyList<Finding>> EvaluateAsync(string targetPath, CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();
        var files = SourceFileHelper.FindSourceFiles(targetPath, "*.cs");
        var findingIndex = 1;

        foreach (var file in files)
        {
            if (cancellationToken.IsCancellationRequested) break;

            try
            {
                var lines = File.ReadAllLines(file);
                for (var i = 0; i < lines.Length; i++)
                {
                    var line = lines[i];
                    var trimmed = line.Trim();
                    if (trimmed.StartsWith("//") || trimmed.StartsWith("/*") || trimmed.StartsWith("*"))
                    {
                        continue;
                    }

                    var match = PermissiveCorsPattern.Match(line);
                    if (match.Success)
                    {
                        var relativePath = Path.GetRelativePath(targetPath, file).Replace('\\', '/');
                        var location = new FindingLocation(relativePath, i + 1, match.Index + 1);
                        var fingerprint = Finding.ComputeFingerprint(RuleId, location, match.Value);

                        findings.Add(new Finding(
                            Id: $"{RuleId}-{findingIndex++:D3}",
                            RuleId: RuleId,
                            Title: "Permissive CORS policy detected (wildcard origin or unrestricted origin validator)",
                            SourceName: "NativeRules",
                            SourceVersion: "0.1.0",
                            TscCriteria: TscCriteria,
                            OrgControlId: null,
                            Severity: Severity.Medium,
                            Category: FindingCategory.Configuration,
                            Location: location,
                            RedactedEvidence: line.Trim(),
                            RiskExplanation: "Allowing arbitrary cross-origin requests via wildcard origins or unrestricted origin validation lambdas allows malicious third-party websites to issue authenticated cross-origin requests, risking customer data exposure and cross-site scripting/forgery exploitation (SOC 2 CC6.6).",
                            RecommendedFix: "Specify explicit trusted origins in CORS policies using WithOrigins(\"https://app.example.com\"). Avoid wildcard origins and avoid SetIsOriginAllowed(_ => true).",
                            Effort: EffortEstimate.Low,
                            Confidence: ConfidenceLevel.High,
                            Fingerprint: fingerprint
                        ));
                    }
                }
            }
            catch
            {
                // Best effort
            }
        }

        return Task.FromResult<IReadOnlyList<Finding>>(findings);
    }
}