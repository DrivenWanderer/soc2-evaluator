using System.Text.RegularExpressions;
using Soc2Evaluator.Core.Models;

namespace Soc2Evaluator.Rules.Checks;

public class WeakCryptoCheck : IRuleCheck
{
    public string RuleId => "SEC-002";
    public string Title => "Weak or deprecated cryptographic algorithm (MD5, SHA1, DES, ECB)";
    public IReadOnlyList<string> TscCriteria => ["CC6.1", "CC6.7"];

    private static readonly Regex WeakCryptoPattern = new(
        @"\b(MD5(\.Create\(\)|\.HashData|CryptoServiceProvider)?|SHA1(\.Create\(\)|\.HashData|CryptoServiceProvider|Managed)?|DES(\.Create\(\)|CryptoServiceProvider)?|TripleDESCryptoServiceProvider|CipherMode\.ECB)\b",
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

                    var match = WeakCryptoPattern.Match(line);
                    if (match.Success)
                    {
                        var relativePath = Path.GetRelativePath(targetPath, file).Replace('\\', '/');
                        var location = new FindingLocation(relativePath, i + 1, match.Index + 1);
                        var fingerprint = Finding.ComputeFingerprint(RuleId, location, match.Value);

                        findings.Add(new Finding(
                            Id: $"{RuleId}-{findingIndex++:D3}",
                            RuleId: RuleId,
                            Title: $"Weak or deprecated cryptographic algorithm: {match.Value}",
                            SourceName: "NativeRules",
                            SourceVersion: "0.1.0",
                            TscCriteria: TscCriteria,
                            OrgControlId: null,
                            Severity: Severity.High,
                            Category: FindingCategory.Code,
                            Location: location,
                            RedactedEvidence: line.Trim(),
                            RiskExplanation: "Weak or deprecated cryptographic algorithms (such as MD5, SHA-1, DES, 3DES, or ECB cipher mode) are vulnerable to collision, practical brute-force, or structural cryptographic attacks. Use of broken algorithms undermines data integrity and confidentiality requirements of SOC 2 CC6.1 and CC6.7.",
                            RecommendedFix: "Replace MD5 and SHA-1 with SHA-256 (SHA256.Create()) or SHA-512 for integrity hashes. Replace DES/3DES with AES (Aes.Create()) using secure modes such as CBC or GCM. Avoid CipherMode.ECB.",
                            Effort: EffortEstimate.Medium,
                            Confidence: ConfidenceLevel.High,
                            Fingerprint: fingerprint
                        ));
                    }
                }
            }
            catch
            {
                // Best effort file read
            }
        }

        return Task.FromResult<IReadOnlyList<Finding>>(findings);
    }
}