using System.Text.Json;
using System.Text.Json.Serialization;
using Soc2Evaluator.Core.Models;

namespace Soc2Evaluator.Reporting;

public class JsonReporter : IReporter
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = true,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        Converters = { new JsonStringEnumConverter() }
    };

    public string FormatName => "json";
    public string OutputFileName => "findings.json";

    public Task<string> RenderAsync(EvidenceManifest manifest, CancellationToken cancellationToken = default)
    {
        var json = JsonSerializer.Serialize(manifest, JsonOptions);
        return Task.FromResult(json);
    }
}