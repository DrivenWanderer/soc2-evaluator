using Soc2Evaluator.Core.Adapters;
using Soc2Evaluator.Core.Models;

namespace Soc2Evaluator.Core.Services;

public class EvaluationOrchestrator : IEvaluationOrchestrator
{
    private readonly IEnumerable<IScannerAdapter> _adapters;
    private readonly IEvidenceHasher _hasher;
    private readonly IControlMappingService _mappingService;
    private readonly IRemediationService? _remediationService;
    private readonly IBaselineDiffService? _baselineDiffService;

    public EvaluationOrchestrator(
        IEnumerable<IScannerAdapter> adapters,
        IEvidenceHasher hasher,
        IControlMappingService mappingService,
        IRemediationService? remediationService = null,
        IBaselineDiffService? baselineDiffService = null)
    {
        _adapters = adapters;
        _hasher = hasher;
        _mappingService = mappingService;
        _remediationService = remediationService;
        _baselineDiffService = baselineDiffService;
    }

    public async Task<EvidenceBundle> RunEvaluationAsync(EvaluationRequest request, CancellationToken cancellationToken = default)
    {
        var runId = $"run-{DateTimeOffset.UtcNow:yyyyMMddHHmmss}-{Guid.NewGuid():N}"[..28];
        var timestamp = DateTimeOffset.UtcNow;
        var fullTargetPath = Path.GetFullPath(request.TargetPath);

        if (!string.IsNullOrWhiteSpace(request.OrgConfigPath))
        {
            _mappingService.LoadMapping(request.OrgConfigPath);
        }

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

        var enrichedFindings = allFindings
            .Select(_mappingService.EnrichFinding)
            .Select(f => _remediationService?.EnrichWithRemediation(f) ?? f)
            .ToList();

        BaselineDelta? baselineDelta = null;
        if (!string.IsNullOrWhiteSpace(request.BaselinePath) && _baselineDiffService != null)
        {
            baselineDelta = _baselineDiffService.ComputeDelta(enrichedFindings, request.BaselinePath);
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
            Findings: enrichedFindings,
            ManifestSha256: null,
            BaselineDelta: baselineDelta
        );

        var signedManifest = _hasher.AttachManifestChecksum(unsignedManifest);

        return new EvidenceBundle(signedManifest, artifactBytes);
    }
}