using Soc2Evaluator.Core.Models;

namespace Soc2Evaluator.Core.Services;

public interface IControlMappingService
{
    /// <summary>
    /// Loads default mappings and merges optional organization overrides from YAML file.
    /// </summary>
    ControlMappingConfig LoadMapping(string? orgConfigPath = null);

    /// <summary>
    /// The currently active control mapping configuration.
    /// </summary>
    ControlMappingConfig CurrentConfig { get; }

    /// <summary>
    /// Gets the mapping entry for a specific rule ID if registered.
    /// </summary>
    ControlMappingEntry? GetMapping(string ruleId);

    /// <summary>
    /// Returns all registered control mapping entries.
    /// </summary>
    IReadOnlyList<ControlMappingEntry> GetAllMappings();

    /// <summary>
    /// Enriches a raw scanner finding with organization control IDs, TSC criteria, severity overrides, and suppression status.
    /// </summary>
    Finding EnrichFinding(Finding finding);
}