using Soc2Evaluator.Core.Adapters;
using Soc2Evaluator.Core.Models;

namespace Soc2Evaluator.Core.Services;

public class EvaluationOrchestrator : IEvaluationOrchestrator
{
    private readonly IEnumerable<IScannerAdapter> _adapters;
    private readonly IEvidenceHasher _hasher;

    public EvaluationOrchestrator(IEnumerable<IScannerAdapter> adapters, IEvidenceHasher hasher)
    {
        _adapters = adapters;
        _hasher = hasher;
    }

    public async Task<EvidenceBundle> RunEvaluationAsync(EvaluationRequest request, CancellationToken cancellationToken = default)
    {
        var runId = $"run-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid():N}"[..28];
        var timestamp = DateTimeOffset.UtcNow;
        var fullTargetPath = Path.GetFullPath(request.TargetPath);

        var allFindings = new List<Finding>();
        var allProvenance = new List<ToolExecutionProvenance>();
        var allArtifacts = new List<EvidenceArtifact>();
        var artifactBytes = new Dictionary<string, byte[]>();

        var adapterContext = new AdapterExecutionContext(
            TargetPath: fullTargetPath,
            InScopeCriteria: request.Criteria,
            Offline: request.Offline
        );

        foreach (var adapter in _adapters)
        {
            var result = await adapter.ExecuteAsync(adapterContext, cancellationToken);
            allProvenance.Add(result.Provenance);
            allFindings.AddRange(result.Findings);
            allArtifacts.AddRange(result.Artifacts);

            foreach (var (k, v) in result.RawArtifactBytes)
            {
                artifactBytes[k] = v;
            }
        }

        var unsignedManifest = new EvidenceManifest(
            RunId: runId,
            TimestampUtc: timestamp,
            ToolVersion: "0.1.0",
            Target: fullTargetPath,
            CommitSha: request.CommitSha,
            CriteriaInScope: request.Criteria,
            ToolProvenance: allProvenance,
            Artifacts: allArtifacts,
            Findings: allFindings,
            ManifestSha256: null
        );

        var signedManifest = _hasher.AttachManifestChecksum(unsignedManifest);

        return new EvidenceBundle(signedManifest, artifactBytes);
    }
}