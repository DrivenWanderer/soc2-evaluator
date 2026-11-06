using System.Text.Json;
using System.Xml;
using System.Xml.Linq;
using Soc2Evaluator.Core.Models;

namespace Soc2Evaluator.Rules.Checks;

public class VerboseErrorsCheck : IRuleCheck
{
    public string RuleId => "CFG-002";
    public string Title => "Verbose errors / debug enabled in production config";
    public IReadOnlyList<string> TscCriteria => ["CC6.1", "CC7.2"];

    public Task<IReadOnlyList<Finding>> EvaluateAsync(string targetPath, CancellationToken cancellationToken = default)
    {
        var findings = new List<Finding>();
        if (!Directory.Exists(targetPath) && !File.Exists(targetPath))
        {
            return Task.FromResult<IReadOnlyList<Finding>>(findings);
        }

        var dirPath = Directory.Exists(targetPath)
            ? targetPath
            : Path.GetDirectoryName(targetPath) ?? ".";

        var files = GetCandidateConfigFiles(dirPath);
        var findingIndex = 1;

        foreach (var file in files)
        {
            if (cancellationToken.IsCancellationRequested) break;

            var fileName = Path.GetFileName(file);
            if (fileName.Equals("web.config", StringComparison.OrdinalIgnoreCase))
            {
                InspectWebConfig(file, dirPath, ref findingIndex, findings);
            }
            else if (fileName.StartsWith("appsettings", StringComparison.OrdinalIgnoreCase) && fileName.EndsWith(".json", StringComparison.OrdinalIgnoreCase))
            {
                // Exclude local development settings
                if (!fileName.Equals("appsettings.Development.json", StringComparison.OrdinalIgnoreCase))
                {
                    InspectAppSettingsJson(file, dirPath, ref findingIndex, findings);
                }
            }
        }

        return Task.FromResult<IReadOnlyList<Finding>>(findings);
    }

    private static void InspectWebConfig(string filePath, string rootPath, ref int findingIndex, List<Finding> findings)
    {
        try
        {
            using var stream = File.OpenRead(filePath);
            var doc = XDocument.Load(stream, LoadOptions.SetLineInfo);
            var relativePath = Path.GetRelativePath(rootPath, filePath).Replace('\\', '/');

            // 1. Check system.web/compilation/@debug == "true"
            var compilation = doc.Descendants("compilation").FirstOrDefault();
            if (compilation != null)
            {
                var debugAttr = compilation.Attribute("debug");
                if (debugAttr != null && debugAttr.Value.Equals("true", StringComparison.OrdinalIgnoreCase))
                {
                    var lineInfo = (IXmlLineInfo)compilation;
                    var line = lineInfo.HasLineInfo() ? lineInfo.LineNumber : (int?)null;
                    var location = new FindingLocation(relativePath, line, null, "system.web/compilation/@debug");
                    var fingerprint = Finding.ComputeFingerprint("CFG-002", location);

                    findings.Add(new Finding(
                        Id: $"CFG-002-{findingIndex++}",
                        RuleId: "CFG-002",
                        Title: "Debug compilation enabled in web.config",
                        SourceName: "Soc2Evaluator.Rules",
                        SourceVersion: "0.1.0",
                        TscCriteria: ["CC6.1", "CC7.2"],
                        OrgControlId: null,
                        Severity: Severity.Medium,
                        Category: FindingCategory.Configuration,
                        Location: location,
                        RedactedEvidence: compilation.ToString(),
                        RiskExplanation: "Enabling debug compilation (compilation debug=\"true\") weakens system performance, increases memory overhead, exposes internal code details in errors, and prevents code minification in production.",
                        RecommendedFix: "Set <compilation debug=\"false\" /> in production web.config or apply a Release config transform.",
                        Effort: EffortEstimate.Low,
                        Confidence: ConfidenceLevel.High,
                        Fingerprint: fingerprint
                    ));
                }
            }

            // 2. Check system.web/customErrors/@mode == "Off"
            var customErrors = doc.Descendants("customErrors").FirstOrDefault();
            if (customErrors != null)
            {
                var modeAttr = customErrors.Attribute("mode");
                if (modeAttr != null && modeAttr.Value.Equals("Off", StringComparison.OrdinalIgnoreCase))
                {
                    var lineInfo = (IXmlLineInfo)customErrors;
                    var line = lineInfo.HasLineInfo() ? lineInfo.LineNumber : (int?)null;
                    var location = new FindingLocation(relativePath, line, null, "system.web/customErrors/@mode");
                    var fingerprint = Finding.ComputeFingerprint("CFG-002", location);

                    findings.Add(new Finding(
                        Id: $"CFG-002-{findingIndex++}",
                        RuleId: "CFG-002",
                        Title: "Custom errors disabled (mode=\"Off\") in web.config",
                        SourceName: "Soc2Evaluator.Rules",
                        SourceVersion: "0.1.0",
                        TscCriteria: ["CC6.1", "CC7.2"],
                        OrgControlId: null,
                        Severity: Severity.Medium,
                        Category: FindingCategory.Configuration,
                        Location: location,
                        RedactedEvidence: customErrors.ToString(),
                        RiskExplanation: "Disabling custom error handling (customErrors mode=\"Off\") discloses unhandled exception stack traces and server internals directly to untrusted clients, violating data protection (CC6.1) and error anomaly isolation (CC7.2).",
                        RecommendedFix: "Set <customErrors mode=\"RemoteOnly\" /> or <customErrors mode=\"On\" /> in web.config.",
                        Effort: EffortEstimate.Low,
                        Confidence: ConfidenceLevel.High,
                        Fingerprint: fingerprint
                    ));
                }
            }
        }
        catch
        {
            // Best effort; XML malformed or permission error
        }
    }

    private static void InspectAppSettingsJson(string filePath, string rootPath, ref int findingIndex, List<Finding> findings)
    {
        try
        {
            var content = File.ReadAllText(filePath);
            var relativePath = Path.GetRelativePath(rootPath, filePath).Replace('\\', '/');

            using var doc = JsonDocument.Parse(content);
            var root = doc.RootElement;

            // Check for DetailedErrors: true
            if (root.TryGetProperty("DetailedErrors", out var detailedErrorsProp) &&
                detailedErrorsProp.ValueKind == JsonValueKind.True)
            {
                var line = FindLineNumber(content, "DetailedErrors");
                var location = new FindingLocation(relativePath, line, null, "DetailedErrors");
                var fingerprint = Finding.ComputeFingerprint("CFG-002", location);

                findings.Add(new Finding(
                    Id: $"CFG-002-{findingIndex++}",
                    RuleId: "CFG-002",
                    Title: "DetailedErrors enabled in ASP.NET Core configuration",
                    SourceName: "Soc2Evaluator.Rules",
                    SourceVersion: "0.1.0",
                    TscCriteria: ["CC6.1", "CC7.2"],
                    OrgControlId: null,
                    Severity: Severity.Medium,
                    Category: FindingCategory.Configuration,
                    Location: location,
                    RedactedEvidence: "\"DetailedErrors\": true",
                    RiskExplanation: "DetailedErrors enabled in production discloses diagnostic exception information and internal application state to end users.",
                    RecommendedFix: "Set \"DetailedErrors\": false or configure UseDeveloperExceptionPage() only in Development environments.",
                    Effort: EffortEstimate.Low,
                    Confidence: ConfidenceLevel.High,
                    Fingerprint: fingerprint
                ));
            }
        }
        catch
        {
            // JSON parsing error or access issue
        }
    }

    private static int? FindLineNumber(string content, string keyword)
    {
        var lines = content.Split('\n');
        for (var i = 0; i < lines.Length; i++)
        {
            if (lines[i].Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                return i + 1;
            }
        }
        return null;
    }

    private static List<string> GetCandidateConfigFiles(string directory)
    {
        var result = new List<string>();
        try
        {
            var allFiles = Directory.EnumerateFiles(directory, "*.*", SearchOption.AllDirectories);
            foreach (var file in allFiles)
            {
                var norm = file.Replace('\\', '/');
                if (norm.Contains("/bin/", StringComparison.OrdinalIgnoreCase) ||
                    norm.Contains("/obj/", StringComparison.OrdinalIgnoreCase) ||
                    norm.Contains("/.git/", StringComparison.OrdinalIgnoreCase) ||
                    norm.Contains("/node_modules/", StringComparison.OrdinalIgnoreCase))
                {
                    continue;
                }

                var name = Path.GetFileName(file);
                if (name.Equals("web.config", StringComparison.OrdinalIgnoreCase) ||
                    (name.StartsWith("appsettings", StringComparison.OrdinalIgnoreCase) && name.EndsWith(".json", StringComparison.OrdinalIgnoreCase)))
                {
                    result.Add(file);
                }
            }
        }
        catch
        {
            // Best effort
        }

        return result;
    }
}