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

        // Plan Section 10 Phase 0 requirement:
        // "MD and JSON reporters with a hard-coded sample finding"
        // Ensure at least one finding is present to verify reporting layout if no scanners detect findings.
        if (allFindings.Count == 0)
        {
            var sampleLocation = new FindingLocation("appsettings.json", 14, 5);
            var sampleFinding = new Finding(
                Id: "SEC-001-SAMPLE",
                RuleId: "SEC-001",
                Title: "Hardcoded connection string detected (Phase 0 Sample Finding)",
                SourceName: "Soc2Evaluator.Sample",
                SourceVersion: "0.1.0",
                TscCriteria: ["CC6.1"],
                OrgControlId: "ACME-AC-04",
                Severity: Severity.High,
                Category: FindingCategory.Code,
                Location: sampleLocation,
                RedactedEvidence: "Server=tcp:sqlserver.database.windows.net;Database=SampleDb;User Id=dbadmin;Password=***[REDACTED]***",
                RiskExplanation: "Hardcoded database credentials in source-controlled configuration files expose the data tier to unauthorized access.",
                RecommendedFix: "Extract sensitive credentials into Azure Key Vault, AWS Secrets Manager, or machine-level environment variables.",
                Effort: EffortEstimate.Low,
                Confidence: ConfidenceLevel.High,
                Fingerprint: Finding.ComputeFingerprint("SEC-001", sampleLocation)
            );

            allFindings.Add(sampleFinding);
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

        var signedManifest = _hasher.SignManifest(unsignedManifest);

        return new EvidenceBundle(signedManifest, artifactBytes);
    }
}