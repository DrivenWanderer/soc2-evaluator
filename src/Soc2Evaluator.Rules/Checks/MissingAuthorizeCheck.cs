using System.Text.RegularExpressions;
using Soc2Evaluator.Core.Models;

namespace Soc2Evaluator.Rules.Checks;

public class MissingAuthorizeCheck : IRuleCheck
{
    public string RuleId => "SEC-003";
    public string Title => "Missing [Authorize] or risky [AllowAnonymous] on controller endpoint";
    public IReadOnlyList<string> TscCriteria => ["CC6.1", "CC6.3"];

    private static readonly Regex ControllerClassPattern = new(
        @"\bclass\s+(?<name>\w+Controller)\b(?:\s*:\s*(?:ControllerBase|Controller|\w+Controller))?",
        RegexOptions.Compiled
    );

    private static readonly Regex ActionMethodPattern = new(
        @"\bpublic\s+(?:async\s+)?(?:IActionResult|ActionResult|Task<IActionResult>|Task<ActionResult>|string|IResult)\s+(?<action>\w+)\s*\(",
        RegexOptions.Compiled
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
                var content = File.ReadAllText(file);
                if (!content.Contains("Controller")) continue;

                var lines = File.ReadAllLines(file);
                var classMatch = ControllerClassPattern.Match(content);
                if (!classMatch.Success) continue;

                var controllerName = classMatch.Groups["name"].Value;
                var classIndex = GetLineIndex(lines, classMatch.Index);

                // Check if class has [Authorize]
                var hasClassAuthorize = false;
                for (var i = 0; i < classIndex; i++)
                {
                    if (lines[i].Contains("[Authorize") || lines[i].Contains("[Authorize]"))
                    {
                        hasClassAuthorize = true;
                        break;
                    }
                }

                if (!hasClassAuthorize)
                {
                    // Scan methods in controller
                    for (var i = classIndex; i < lines.Length; i++)
                    {
                        var line = lines[i];
                        var methodMatch = ActionMethodPattern.Match(line);
                        if (methodMatch.Success)
                        {
                            var actionName = methodMatch.Groups["action"].Value;
                            var hasMethodAuthorize = false;

                            // Look back up to 5 lines for [Authorize] attribute
                            for (var k = Math.Max(0, i - 5); k < i; k++)
                            {
                                if (lines[k].Contains("[Authorize") || lines[k].Contains("[Authorize]"))
                                {
                                    hasMethodAuthorize = true;
                                    break;
                                }
                            }

                            if (!hasMethodAuthorize)
                            {
                                var relativePath = Path.GetRelativePath(targetPath, file).Replace('\\', '/');
                                var location = new FindingLocation(relativePath, i + 1, methodMatch.Index + 1);
                                var fingerprint = Finding.ComputeFingerprint(RuleId, location, $"{controllerName}.{actionName}");

                                findings.Add(new Finding(
                                    Id: $"{RuleId}-{findingIndex++:D3}",
                                    RuleId: RuleId,
                                    Title: $"Action method '{controllerName}.{actionName}' missing [Authorize] attribute",
                                    SourceName: "NativeRules",
                                    SourceVersion: "0.1.0",
                                    TscCriteria: TscCriteria,
                                    OrgControlId: null,
                                    Severity: Severity.High,
                                    Category: FindingCategory.Code,
                                    Location: location,
                                    RedactedEvidence: line.Trim(),
                                    RiskExplanation: $"Endpoint '{controllerName}.{actionName}' does not enforce authentication or authorization attributes, permitting anonymous access to application endpoints in violation of SOC 2 CC6.1 and CC6.3 logical access requirements.",
                                    RecommendedFix: $"Decorate the controller '{controllerName}' or action method '{actionName}' with [Authorize]. If public anonymous access is explicitly required, annotate with [AllowAnonymous] and document the business justification.",
                                    Effort: EffortEstimate.Low,
                                    Confidence: ConfidenceLevel.High,
                                    Fingerprint: fingerprint
                                ));
                            }
                        }
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

    private static int GetLineIndex(string[] lines, int charOffset)
    {
        var current = 0;
        for (var i = 0; i < lines.Length; i++)
        {
            current += lines[i].Length + 1; // + newline
            if (current >= charOffset) return i;
        }
        return 0;
    }
}