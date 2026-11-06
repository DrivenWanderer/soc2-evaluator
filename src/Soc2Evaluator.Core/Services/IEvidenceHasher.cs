using Soc2Evaluator.Core.Models;

namespace Soc2Evaluator.Core.Services;

public interface IEvidenceHasher
{
    string ComputeSha256(byte[] data);
    string ComputeSha256(string content);
    string ComputeSha256(Stream stream);

    /// <summary>
    /// Computes and attaches a deterministic SHA-256 integrity checksum to the manifest.
    /// Note: This is an integrity checksum, not a cryptographic digital signature.
    /// </summary>
    EvidenceManifest AttachManifestChecksum(EvidenceManifest manifest);

    /// <summary>
    /// Verifies the internal consistency of the manifest's integrity checksum.
    /// </summary>
    bool VerifyManifestChecksum(EvidenceManifest manifest);

    /// <summary>
    /// Verifies that all recorded artifacts match their recorded SHA-256 hashes against actual artifact data.
    /// </summary>
    bool VerifyArtifacts(EvidenceManifest manifest, IReadOnlyDictionary<string, byte[]> artifactBytes);

    // Aliases retained for backwards compatibility
    EvidenceManifest SignManifest(EvidenceManifest manifest) => AttachManifestChecksum(manifest);
    bool VerifyManifest(EvidenceManifest manifest) => VerifyManifestChecksum(manifest);
}