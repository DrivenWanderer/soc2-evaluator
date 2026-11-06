namespace Soc2Evaluator.Core.Models;

public record EvidenceArtifact(
    string Name,
    string ContentType,
    string Sha256Hash,
    string RelativePath
);

public record EvidenceManifest(
    string RunId,
    DateTimeOffset TimestampUtc,
    string ToolVersion,
    string Target,
    string? CommitSha,
    IReadOnlyList<string> CriteriaInScope,
    IReadOnlyList<ToolExecutionProvenance> ToolProvenance,
    IReadOnlyList<EvidenceArtifact> Artifacts,
    IReadOnlyList<Finding> Findings,
    string? ManifestSha256 = null
);

public record EvidenceBundle(
    EvidenceManifest Manifest,
    IReadOnlyDictionary<string, byte[]> RawArtifactBytes
);