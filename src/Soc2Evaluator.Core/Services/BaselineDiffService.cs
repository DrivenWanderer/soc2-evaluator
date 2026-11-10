using System.Text.Json;
using System.Text.Json.Serialization;
using Soc2Evaluator.Core.Models;

namespace Soc2Evaluator.Core.Services;

public class BaselineDiffService : IBaselineDiffService
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public BaselineDelta ComputeDelta(IReadOnlyList<Finding> currentFindings, string baselineFilePath)
    {
        var baselineFindings = LoadBaselineFindings(baselineFilePath);

        var baselineByFingerprint = new Dictionary<string, Finding>(StringComparer.OrdinalIgnoreCase);
        foreach (var bf in baselineFindings)
        {
            if (!string.IsNullOrWhiteSpace(bf.Fingerprint))
            {
                baselineByFingerprint[bf.Fingerprint] = bf;
            }
        }

        var currentFingerprints = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var newFindings = new List<Finding>();
        var persistingFindings = new List<Finding>();

        foreach (var cf in currentFindings)
        {
            currentFingerprints.Add(cf.Fingerprint);
            if (baselineByFingerprint.ContainsKey(cf.Fingerprint))
            {
                persistingFindings.Add(cf);
            }
            else
            {
                newFindings.Add(cf);
            }
        }

        var resolvedFindings = new List<Finding>();
        foreach (var (fp, bf) in baselineByFingerprint)
        {
            if (!currentFingerprints.Contains(fp))
            {
                resolvedFindings.Add(bf with { Status = FindingStatus.Resolved });
            }
        }

        return new BaselineDelta(
            BaselinePath: baselineFilePath,
            NewFindings: newFindings,
            PersistingFindings: persistingFindings,
            ResolvedFindings: resolvedFindings
        );
    }

    public IReadOnlyList<Finding> LoadBaselineFindings(string baselineFilePath)
    {
        if (string.IsNullOrWhiteSpace(baselineFilePath))
        {
            throw new ArgumentException("Baseline file path cannot be null or empty.", nameof(baselineFilePath));
        }

        if (!File.Exists(baselineFilePath))
        {
            throw new FileNotFoundException($"Baseline file not found: {baselineFilePath}", baselineFilePath);
        }

        var json = File.ReadAllText(baselineFilePath);
        using var doc = JsonDocument.Parse(json);
        var root = doc.RootElement;

        // 1. EvidenceBundle format: { "manifest": { "findings": [ ... ] } }
        if (root.ValueKind == JsonValueKind.Object)
        {
            var manifestProp = root.EnumerateObject().FirstOrDefault(p => p.Name.Equals("manifest", StringComparison.OrdinalIgnoreCase));
            if (manifestProp.Value.ValueKind == JsonValueKind.Object)
            {
                var findingsProp = manifestProp.Value.EnumerateObject().FirstOrDefault(p => p.Name.Equals("findings", StringComparison.OrdinalIgnoreCase));
                if (findingsProp.Value.ValueKind == JsonValueKind.Array)
                {
                    return JsonSerializer.Deserialize<List<Finding>>(findingsProp.Value.GetRawText(), JsonOptions) ?? [];
                }
            }

            // 2. EvidenceManifest or findings report format: { "findings": [ ... ] }
            var directFindings = root.EnumerateObject().FirstOrDefault(p => p.Name.Equals("findings", StringComparison.OrdinalIgnoreCase));
            if (directFindings.Value.ValueKind == JsonValueKind.Array)
            {
                return JsonSerializer.Deserialize<List<Finding>>(directFindings.Value.GetRawText(), JsonOptions) ?? [];
            }

            throw new FormatException(
                $"Unsupported baseline JSON format in '{baselineFilePath}'. The JSON object must contain a 'findings' array or a 'manifest.findings' array."
            );
        }

        // 3. Direct array of findings: [ { ... }, { ... } ]
        if (root.ValueKind == JsonValueKind.Array)
        {
            return JsonSerializer.Deserialize<List<Finding>>(root.GetRawText(), JsonOptions) ?? [];
        }

        throw new FormatException(
            $"Unsupported baseline JSON format in '{baselineFilePath}'. Expected a JSON array of findings or a JSON object containing findings."
        );
    }
}