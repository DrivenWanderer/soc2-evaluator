using System.Xml;
using System.Xml.Linq;
using Soc2Evaluator.Core.Models;

namespace Soc2Evaluator.Rules.Checks;

public class LockfilePinningCheck : IRuleCheck
{
    public string RuleId => "DEP-002";
    public string Title => "No lockfile / unpinned dependencies";
    public IReadOnlyList<string> TscCriteria => ["CC8.1"];

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

        var findingIndex = 1;

        // Check if root or solution-level Directory.Build.props enables RestorePackagesWithLockFile
        var globalLockfileEnabled = CheckGlobalLockfileEnabled(dirPath);

        // Find .NET project files and Directory.Packages.props
        var projectFiles = SourceFileHelper.FindSourceFiles(dirPath, "*.csproj")
            .Concat(SourceFileHelper.FindSourceFiles(dirPath, "*.fsproj"))
            .Concat(SourceFileHelper.FindSourceFiles(dirPath, "*.vbproj"))
            .Concat(SourceFileHelper.FindSourceFiles(dirPath, "Directory.Packages.props"))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        foreach (var projFile in projectFiles)
        {
            if (cancellationToken.IsCancellationRequested) break;

            try
            {
                using var stream = File.OpenRead(projFile);
                var doc = XDocument.Load(stream, LoadOptions.SetLineInfo);
                var relativePath = Path.GetRelativePath(dirPath, projFile).Replace('\\', '/');
                var projDir = Path.GetDirectoryName(projFile) ?? dirPath;

                // 1. Check for floating / wildcard package versions
                var packageRefs = doc.Descendants("PackageReference").Concat(doc.Descendants("PackageVersion"));
                var hasPackages = false;

                foreach (var pref in packageRefs)
                {
                    hasPackages = true;
                    var packageName = pref.Attribute("Include")?.Value ?? pref.Attribute("Update")?.Value ?? "Package";
                    var version = pref.Attribute("Version")?.Value ?? pref.Element("Version")?.Value;

                    if (!string.IsNullOrWhiteSpace(version) && (version.Contains('*') || version.Contains('[') || version.Contains('(')))
                    {
                        var line = (pref as IXmlLineInfo)?.LineNumber ?? 1;
                        var col = (pref as IXmlLineInfo)?.LinePosition ?? 1;
                        var location = new FindingLocation(relativePath, line, col);
                        var fingerprint = Finding.ComputeFingerprint(RuleId, location, $"{packageName}:{version}");

                        findings.Add(new Finding(
                            Id: $"{RuleId}-{findingIndex++:D3}",
                            RuleId: RuleId,
                            Title: $"Unpinned floating package version for '{packageName}': {version}",
                            SourceName: "NativeRules",
                            SourceVersion: "0.1.0",
                            TscCriteria: TscCriteria,
                            OrgControlId: null,
                            Severity: Severity.Medium,
                            Category: FindingCategory.Configuration,
                            Location: location,
                            RedactedEvidence: pref.ToString(),
                            RiskExplanation: $"Dependency '{packageName}' specifies an unpinned or wildcard version ('{version}'). Non-pinned dependencies can resolve different package versions across builds, compromising build reproducibility and exposing the solution to unexpected upstream changes or dependency confusion attacks (SOC 2 CC8.1).",
                            RecommendedFix: $"Pin dependency '{packageName}' to an exact immutable version (e.g. Version=\"1.2.3\") rather than a wildcard range.",
                            Effort: EffortEstimate.Low,
                            Confidence: ConfidenceLevel.High,
                            Fingerprint: fingerprint
                        ));
                    }
                }

                // 2. Check for missing lockfile on projects referencing packages
                if (hasPackages && !projFile.EndsWith("Directory.Packages.props", StringComparison.OrdinalIgnoreCase))
                {
                    var projLockEnabled = CheckProjectLockfileSetting(doc);
                    var lockfileExists = File.Exists(Path.Combine(projDir, "packages.lock.json"));

                    if (!projLockEnabled && !globalLockfileEnabled && !lockfileExists)
                    {
                        var location = new FindingLocation(relativePath, 1, 1);
                        var fingerprint = Finding.ComputeFingerprint(RuleId, location, "missing-lockfile");

                        findings.Add(new Finding(
                            Id: $"{RuleId}-{findingIndex++:D3}",
                            RuleId: RuleId,
                            Title: $"Project '{Path.GetFileName(projFile)}' is missing packages.lock.json or RestorePackagesWithLockFile",
                            SourceName: "NativeRules",
                            SourceVersion: "0.1.0",
                            TscCriteria: TscCriteria,
                            OrgControlId: null,
                            Severity: Severity.Medium,
                            Category: FindingCategory.Configuration,
                            Location: location,
                            RedactedEvidence: $"<Project Sdk=\"...\"> in {relativePath}",
                            RiskExplanation: $"Project '{Path.GetFileName(projFile)}' consumes NuGet packages without a committed packages.lock.json or without enabling <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>. This risks non-deterministic builds and untracked transitive dependency updates in violation of SOC 2 CC8.1 change management controls.",
                            RecommendedFix: "Enable NuGet lockfiles by adding `<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>` to the project or Directory.Build.props and commit the generated packages.lock.json.",
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

        // 3. Check Node.js package.json if present
        var packageJsonFiles = SourceFileHelper.FindSourceFiles(dirPath, "package.json").ToList();
        foreach (var pjson in packageJsonFiles)
        {
            var pdir = Path.GetDirectoryName(pjson) ?? dirPath;
            var hasLockfile = File.Exists(Path.Combine(pdir, "package-lock.json")) ||
                              File.Exists(Path.Combine(pdir, "pnpm-lock.yaml")) ||
                              File.Exists(Path.Combine(pdir, "yarn.lock"));

            if (!hasLockfile)
            {
                var relPath = Path.GetRelativePath(dirPath, pjson).Replace('\\', '/');
                var location = new FindingLocation(relPath, 1, 1);
                var fingerprint = Finding.ComputeFingerprint(RuleId, location, "npm-missing-lockfile");

                findings.Add(new Finding(
                    Id: $"{RuleId}-{findingIndex++:D3}",
                    RuleId: RuleId,
                    Title: "Node.js project missing package-lock.json or lockfile",
                    SourceName: "NativeRules",
                    SourceVersion: "0.1.0",
                    TscCriteria: TscCriteria,
                    OrgControlId: null,
                    Severity: Severity.Medium,
                    Category: FindingCategory.Configuration,
                    Location: location,
                    RedactedEvidence: relPath,
                    RiskExplanation: "package.json exists without a corresponding lockfile (package-lock.json, pnpm-lock.yaml, or yarn.lock). Build outputs may drift across environments, violating SOC 2 CC8.1 change management controls.",
                    RecommendedFix: "Run 'npm install' or your package manager install command to generate a lockfile, and commit it to source control.",
                    Effort: EffortEstimate.Low,
                    Confidence: ConfidenceLevel.High,
                    Fingerprint: fingerprint
                ));
            }
        }

        return Task.FromResult<IReadOnlyList<Finding>>(findings);
    }

    private static bool CheckGlobalLockfileEnabled(string rootPath)
    {
        var buildProps = Path.Combine(rootPath, "Directory.Build.props");
        if (File.Exists(buildProps))
        {
            try
            {
                var doc = XDocument.Load(buildProps);
                return CheckProjectLockfileSetting(doc);
            }
            catch
            {
                // Best effort
            }
        }
        return false;
    }

    private static bool CheckProjectLockfileSetting(XDocument doc)
    {
        var setting = doc.Descendants("RestorePackagesWithLockFile").FirstOrDefault()?.Value ??
                      doc.Descendants("RestoreLockedMode").FirstOrDefault()?.Value;

        return string.Equals(setting, "true", StringComparison.OrdinalIgnoreCase);
    }
}