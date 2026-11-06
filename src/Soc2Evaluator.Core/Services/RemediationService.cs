using System.Reflection;
using Soc2Evaluator.Core.Models;

namespace Soc2Evaluator.Core.Services;

public class RemediationService : IRemediationService
{
    private readonly Dictionary<string, string> _templates = new(StringComparer.OrdinalIgnoreCase);

    public RemediationService(string? customRemediationDir = null)
    {
        LoadEmbeddedTemplates();

        if (!string.IsNullOrWhiteSpace(customRemediationDir) && Directory.Exists(customRemediationDir))
        {
            LoadCustomTemplates(customRemediationDir);
        }
    }

    public string? GetRemediationTemplate(string ruleId)
    {
        if (string.IsNullOrWhiteSpace(ruleId)) return null;
        return _templates.TryGetValue(ruleId, out var template) ? template : null;
    }

    public Finding EnrichWithRemediation(Finding finding)
    {
        if (string.IsNullOrWhiteSpace(finding.RuleId)) return finding;

        if (_templates.TryGetValue(finding.RuleId, out var template))
        {
            return finding with { RecommendedFix = template };
        }

        return finding;
    }

    private void LoadEmbeddedTemplates()
    {
        var assembly = typeof(RemediationService).Assembly;
        var resourceNames = assembly.GetManifestResourceNames();

        foreach (var resName in resourceNames)
        {
            if (resName.EndsWith(".md", StringComparison.OrdinalIgnoreCase) &&
                resName.Contains("Remediations", StringComparison.OrdinalIgnoreCase))
            {
                // Resource name format: Soc2Evaluator.Core.Resources.Remediations.<RuleId>.md
                var parts = resName.Split('.');
                // Find index of "Remediations"
                var remIndex = Array.IndexOf(parts, "Remediations");
                if (remIndex >= 0 && remIndex + 1 < parts.Length)
                {
                    var ruleId = parts[remIndex + 1];
                    using var stream = assembly.GetManifestResourceStream(resName);
                    if (stream != null)
                    {
                        using var reader = new StreamReader(stream);
                        _templates[ruleId] = reader.ReadToEnd().Trim();
                    }
                }
            }
        }

        // Fallback to local files if embedded resources not resolved (e.g. during some test runs)
        var localDir = Path.Combine(AppContext.BaseDirectory, "../../../../config/remediations");
        if (Directory.Exists(localDir))
        {
            LoadCustomTemplates(localDir);
        }
        else if (Directory.Exists("config/remediations"))
        {
            LoadCustomTemplates("config/remediations");
        }
    }

    private void LoadCustomTemplates(string directory)
    {
        try
        {
            var files = Directory.EnumerateFiles(directory, "*.md");
            foreach (var file in files)
            {
                var ruleId = Path.GetFileNameWithoutExtension(file);
                _templates[ruleId] = File.ReadAllText(file).Trim();
            }
        }
        catch
        {
            // Best effort
        }
    }
}