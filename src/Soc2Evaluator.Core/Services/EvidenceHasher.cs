using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Soc2Evaluator.Core.Models;

namespace Soc2Evaluator.Core.Services;

public class EvidenceHasher : IEvidenceHasher
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        WriteIndented = false,
        Converters = { new JsonStringEnumConverter() }
    };

    public string ComputeSha256(byte[] data)
    {
        var hash = SHA256.HashData(data);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public string ComputeSha256(string content)
    {
        var bytes = Encoding.UTF8.GetBytes(content);
        return ComputeSha256(bytes);
    }

    public string ComputeSha256(Stream stream)
    {
        using var sha256 = SHA256.Create();
        var hash = sha256.ComputeHash(stream);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    public EvidenceManifest SignManifest(EvidenceManifest manifest)
    {
        var unsignedManifest = manifest with { ManifestSha256 = null };
        var json = JsonSerializer.Serialize(unsignedManifest, JsonOptions);
        var hash = ComputeSha256(json);
        return manifest with { ManifestSha256 = hash };
    }

    public bool VerifyManifest(EvidenceManifest manifest)
    {
        if (string.IsNullOrWhiteSpace(manifest.ManifestSha256))
        {
            return false;
        }

        var unsignedManifest = manifest with { ManifestSha256 = null };
        var json = JsonSerializer.Serialize(unsignedManifest, JsonOptions);
        var computedHash = ComputeSha256(json);

        return string.Equals(manifest.ManifestSha256, computedHash, StringComparison.OrdinalIgnoreCase);
    }
}