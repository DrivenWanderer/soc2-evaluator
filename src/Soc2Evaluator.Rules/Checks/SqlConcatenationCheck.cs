using System.Text.RegularExpressions;
using Soc2Evaluator.Core.Models;

namespace Soc2Evaluator.Rules.Checks;

public class SqlConcatenationCheck : IRuleCheck
{
    public string RuleId => "SEC-005";
    public string Title => "SQL query built via string concatenation";
    public IReadOnlyList<string> TscCriteria => ["CC6.1", "CC7.1"];

    private static readonly Regex SqlConcatenationPattern = new(
        @"(new\s+SqlCommand\s*\(\s*("".*?""\s*\+|\$""|.*?\+\s*\w+))|" +
        @"(FromSqlRaw\s*\(\s*("".*?""\s*\+|\$""))|" +
        @"(ExecuteSqlRaw\s*\(\s*("".*?""\s*\+|\$""))|" +
        @"(CommandText\s*=\s*("".*?""\s*\+|\$""))|" +
        @"(""(?:SELECT|INSERT|UPDATE|DELETE)\b.*?""\s*\+\s*\w+)|" +
        @"(\$""(?:SELECT|INSERT|UPDATE|DELETE)\b.*?\{)",
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

                    var match = SqlConcatenationPattern.Match(line);
                    if (match.Success)
                    {
                        var relativePath = Path.GetRelativePath(targetPath, file).Replace('\\', '/');
                        var location = new FindingLocation(relativePath, i + 1, match.Index + 1);
                        var fingerprint = Finding.ComputeFingerprint(RuleId, location, match.Value);

                        findings.Add(new Finding(
                            Id: $"{RuleId}-{findingIndex++:D3}",
                            RuleId: RuleId,
                            Title: "SQL query constructed via dynamic string concatenation or interpolation",
                            SourceName: "NativeRules",
                            SourceVersion: "0.1.0",
                            TscCriteria: TscCriteria,
                            OrgControlId: null,
                            Severity: Severity.High,
                            Category: FindingCategory.Code,
                            Location: location,
                            RedactedEvidence: line.Trim(),
                            RiskExplanation: "Constructing SQL queries via string concatenation or unparameterized string interpolation exposes the application to SQL injection attacks, risking data exfiltration, database corruption, or administrative compromise (SOC 2 CC6.1 and CC7.1).",
                            RecommendedFix: "Use parameterized queries with SqlParameter objects or ORM parameterization methods (such as EF Core FromSqlInterpolated or LINQ queries) rather than raw string concatenation.",
                            Effort: EffortEstimate.Medium,
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