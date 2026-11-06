using System.Reflection;
using Soc2Evaluator.Core.Models;
using YamlDotNet.Serialization;
using YamlDotNet.Serialization.NamingConventions;

namespace Soc2Evaluator.Core.Services;

public class ControlMappingService : IControlMappingService
{
    private readonly IDeserializer _yamlDeserializer;
    private ControlMappingConfig _currentConfig;
    private readonly Dictionary<string, ControlMappingEntry> _mappingsByRuleId = new(StringComparer.OrdinalIgnoreCase);

    public ControlMappingConfig CurrentConfig => _currentConfig;

    public ControlMappingService(string? orgConfigPath = null)
    {
        _yamlDeserializer = new DeserializerBuilder()
            .WithNamingConvention(UnderscoredNamingConvention.Instance)
            .IgnoreUnmatchedProperties()
            .Build();

        _currentConfig = LoadMapping(orgConfigPath);
    }

    public ControlMappingConfig LoadMapping(string? orgConfigPath = null)
    {
        _mappingsByRuleId.Clear();

        // 1. Load default mappings from embedded resource or local config
        var defaultYaml = LoadDefaultYamlContent();
        var defaultFile = _yamlDeserializer.Deserialize<YamlControlMappingFile>(defaultYaml);

        var organization = defaultFile.Organization ?? "Default";
        var version = defaultFile.Version ?? "1.0";
        var description = defaultFile.Description;

        if (defaultFile.Mappings != null)
        {
            foreach (var item in defaultFile.Mappings)
            {
                if (string.IsNullOrWhiteSpace(item.RuleId))
                {
                    continue;
                }

                var entry = MapYamlItemToEntry(item);
                _mappingsByRuleId[entry.RuleId] = entry;
            }
        }

        // 2. Load and merge org-specific config if provided
        if (!string.IsNullOrWhiteSpace(orgConfigPath))
        {
            if (!File.Exists(orgConfigPath))
            {
                throw new FileNotFoundException($"Organization configuration file not found: {orgConfigPath}", orgConfigPath);
            }

            var orgYaml = File.ReadAllText(orgConfigPath);
            var orgFile = _yamlDeserializer.Deserialize<YamlControlMappingFile>(orgYaml);

            if (!string.IsNullOrWhiteSpace(orgFile.Organization))
            {
                organization = orgFile.Organization;
            }

            if (!string.IsNullOrWhiteSpace(orgFile.Version))
            {
                version = orgFile.Version;
            }

            if (!string.IsNullOrWhiteSpace(orgFile.Description))
            {
                description = orgFile.Description;
            }

            if (orgFile.Mappings != null)
            {
                foreach (var orgItem in orgFile.Mappings)
                {
                    if (string.IsNullOrWhiteSpace(orgItem.RuleId))
                    {
                        continue;
                    }

                    if (_mappingsByRuleId.TryGetValue(orgItem.RuleId, out var existing))
                    {
                        // Merge/override
                        var mergedTsc = (orgItem.TscCriteria != null && orgItem.TscCriteria.Count > 0)
                            ? (IReadOnlyList<string>)orgItem.TscCriteria
                            : existing.TscCriteria;

                        var mergedOrgControlId = !string.IsNullOrWhiteSpace(orgItem.OrgControlId)
                            ? orgItem.OrgControlId
                            : existing.OrgControlId;

                        var mergedTitle = !string.IsNullOrWhiteSpace(orgItem.Title)
                            ? orgItem.Title
                            : existing.Title;

                        var mergedDescription = !string.IsNullOrWhiteSpace(orgItem.Description)
                            ? orgItem.Description
                            : existing.Description;

                        var mergedCategory = ParseCategory(orgItem.Category) ?? existing.Category;

                        var mergedOverrideSev = ParseSeverity(orgItem.OverrideSeverity) ?? existing.OverrideSeverity;

                        var mergedEnabled = orgItem.Enabled ?? existing.Enabled;

                        var mergedJustification = !string.IsNullOrWhiteSpace(orgItem.Justification)
                            ? orgItem.Justification
                            : existing.Justification;

                        var mergedNotes = !string.IsNullOrWhiteSpace(orgItem.Notes)
                            ? orgItem.Notes
                            : existing.Notes;

                        _mappingsByRuleId[orgItem.RuleId] = new ControlMappingEntry(
                            RuleId: existing.RuleId,
                            TscCriteria: mergedTsc,
                            OrgControlId: mergedOrgControlId,
                            Title: mergedTitle,
                            Description: mergedDescription,
                            Category: mergedCategory,
                            DefaultSeverity: existing.DefaultSeverity,
                            OverrideSeverity: mergedOverrideSev,
                            Enabled: mergedEnabled,
                            Justification: mergedJustification,
                            Notes: mergedNotes
                        );
                    }
                    else
                    {
                        var entry = MapYamlItemToEntry(orgItem);
                        _mappingsByRuleId[entry.RuleId] = entry;
                    }
                }
            }
        }

        _currentConfig = new ControlMappingConfig(
            Organization: organization,
            Version: version,
            Description: description,
            Mappings: _mappingsByRuleId.Values.ToList()
        );

        return _currentConfig;
    }

    public ControlMappingEntry? GetMapping(string ruleId)
    {
        if (string.IsNullOrWhiteSpace(ruleId))
        {
            return null;
        }

        return _mappingsByRuleId.TryGetValue(ruleId, out var entry) ? entry : null;
    }

    public IReadOnlyList<ControlMappingEntry> GetAllMappings()
    {
        return _mappingsByRuleId.Values.ToList();
    }

    public Finding EnrichFinding(Finding finding)
    {
        if (string.IsNullOrWhiteSpace(finding.RuleId))
        {
            return finding;
        }

        if (!_mappingsByRuleId.TryGetValue(finding.RuleId, out var mapping))
        {
            return finding;
        }

        var tscCriteria = (mapping.TscCriteria != null && mapping.TscCriteria.Count > 0)
            ? mapping.TscCriteria
            : finding.TscCriteria;

        var orgControlId = !string.IsNullOrWhiteSpace(mapping.OrgControlId)
            ? mapping.OrgControlId
            : finding.OrgControlId;

        var severity = mapping.OverrideSeverity ?? finding.Severity;

        var category = mapping.Category ?? finding.Category;

        var status = finding.Status;
        var risk = finding.RiskExplanation;

        if (!mapping.Enabled)
        {
            status = FindingStatus.Suppressed;
            var disabledNotice = string.IsNullOrWhiteSpace(mapping.Justification)
                ? "[Suppressed: Rule disabled by organization control mapping]"
                : $"[Suppressed: Rule disabled by organization control mapping: {mapping.Justification}]";

            if (!risk.Contains("[Suppressed:"))
            {
                risk = $"{disabledNotice} {risk}".Trim();
            }
        }

        return finding with
        {
            TscCriteria = tscCriteria,
            OrgControlId = orgControlId,
            Severity = severity,
            Category = category,
            Status = status,
            RiskExplanation = risk
        };
    }

    private static string LoadDefaultYamlContent()
    {
        var assembly = typeof(ControlMappingService).Assembly;
        var resourceNames = assembly.GetManifestResourceNames();
        var defaultResName = resourceNames.FirstOrDefault(n => n.EndsWith("control-mapping.default.yml", StringComparison.OrdinalIgnoreCase));

        if (!string.IsNullOrWhiteSpace(defaultResName))
        {
            using var stream = assembly.GetManifestResourceStream(defaultResName);
            if (stream != null)
            {
                using var reader = new StreamReader(stream);
                return reader.ReadToEnd();
            }
        }

        // Fallback to local config path if not embedded or during test runs
        var candidatePaths = new[]
        {
            "config/control-mapping.default.yml",
            "../../config/control-mapping.default.yml",
            "../../../config/control-mapping.default.yml"
        };

        foreach (var path in candidatePaths)
        {
            if (File.Exists(path))
            {
                return File.ReadAllText(path);
            }
        }

        throw new InvalidOperationException("Default control mapping YAML could not be loaded from embedded resources or filesystem.");
    }

    private static ControlMappingEntry MapYamlItemToEntry(YamlControlMappingItem item)
    {
        return new ControlMappingEntry(
            RuleId: item.RuleId ?? "UNKNOWN",
            TscCriteria: (item.TscCriteria ?? []).AsReadOnly(),
            OrgControlId: item.OrgControlId,
            Title: item.Title,
            Description: item.Description,
            Category: ParseCategory(item.Category),
            DefaultSeverity: ParseSeverity(item.DefaultSeverity),
            OverrideSeverity: ParseSeverity(item.OverrideSeverity),
            Enabled: item.Enabled ?? true,
            Justification: item.Justification,
            Notes: item.Notes
        );
    }

    private static Severity? ParseSeverity(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return Enum.TryParse<Severity>(value, ignoreCase: true, out var result) ? result : null;
    }

    private static FindingCategory? ParseCategory(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return Enum.TryParse<FindingCategory>(value, ignoreCase: true, out var result) ? result : null;
    }

    private class YamlControlMappingFile
    {
        public string? Organization { get; set; }
        public string? Version { get; set; }
        public string? Description { get; set; }
        public List<YamlControlMappingItem>? Mappings { get; set; }
    }

    private class YamlControlMappingItem
    {
        public string? RuleId { get; set; }
        public string? Title { get; set; }
        public string? Description { get; set; }
        public List<string>? TscCriteria { get; set; }
        public string? DefaultSeverity { get; set; }
        public string? OverrideSeverity { get; set; }
        public string? Category { get; set; }
        public string? OrgControlId { get; set; }
        public bool? Enabled { get; set; }
        public string? Justification { get; set; }
        public string? Notes { get; set; }
    }
}