using System.Text.RegularExpressions;
using Soc2Evaluator.Core.Models;

namespace Soc2Evaluator.Rules.Checks;

public class DisabledCertValidationCheck : IRuleCheck
{
    public string RuleId => "SEC-004";
    public string Title => "TLS certificate validation disabled";
    public IReadOnlyList<string> TscCriteria => ["CC6.7"];

    private static readonly Regex DisabledCertPattern = new(
        @"(ServerCertificateCustomValidationCallback\s*=\s*(?:HttpClientHandler\.)?DangerousAcceptAnyServerCertificateValidator)|(ServerCertificateCustomValidationCallback\s*=\s*\(.*?\)\s*=>\s*true)|(ServerCertificateValidationCallback\s*\+?=\s*\(.*?\)\s*=>\s*true)|(CheckValidationResult\s*=\s*\(.*?\)\s*=>\s*true)",
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

                    var match = DisabledCertPattern.Match(line);
                    if (match.Success)
                    {
                        var relativePath = Path.GetRelativePath(targetPath, file).Replace('\\', '/');
                        var location = new FindingLocation(relativePath, i + 1, match.Index + 1);
                        var fingerprint = Finding.ComputeFingerprint(RuleId, location, match.Value);

                        findings.Add(new Finding(
                            Id: $"{RuleId}-{findingIndex++:D3}",
                            RuleId: RuleId,
                            Title: "TLS certificate validation callback disabled or bypassed",
                            SourceName: "NativeRules",
                            SourceVersion: "0.1.0",
                            TscCriteria: TscCriteria,
                            OrgControlId: null,
                            Severity: Severity.Critical,
                            Category: FindingCategory.Code,
                            Location: location,
                            RedactedEvidence: line.Trim(),
                            RiskExplanation: "Disabling TLS certificate validation permits man-in-the-middle (MitM) attacks, allowing network adversaries to intercept, decrypt, and tamper with transmitted sensitive customer data in violation of SOC 2 CC6.7 encryption in transit requirements.",
                            RecommendedFix: "Remove custom certificate validation callbacks that return unconditional true. Rely on standard OS root certificate authority validation, or validate specific trusted certificate thumbprints securely.",
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