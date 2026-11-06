using Soc2Evaluator.Core.Models;
using Soc2Evaluator.Core.Services;
using Xunit;

namespace Soc2Evaluator.Tests;

public class EvidenceHasherTests
{
    private readonly EvidenceHasher _hasher = new();

    [Fact]
    public void ComputeSha256_ComputesKnownHashCorrectly()
    {
        // SHA-256 of "hello world" in lowercase hex
        const string input = "hello world";
        const string expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

        var actual = _hasher.ComputeSha256(input);

        Assert.Equal(expected, actual);
    }

    [Fact]
    public void SignManifest_ComputesDeterministicHashAndVerifies()
    {
        var manifest = CreateSampleManifest();

        var signed1 = _hasher.SignManifest(manifest);
        var signed2 = _hasher.SignManifest(manifest);

        Assert.NotNull(signed1.ManifestSha256);
        Assert.Equal(signed1.ManifestSha256, signed2.ManifestSha256);
        Assert.True(_hasher.VerifyManifest(signed1));
    }

    [Fact]
    public void VerifyManifest_DetectsTamperingInFindings()
    {
        var manifest = CreateSampleManifest();
        var signed = _hasher.SignManifest(manifest);

        // Tamper with finding title
        var tamperedFindings = signed.Findings.Select(f => f with { Title = "Tampered Title" }).ToList();
        var tamperedManifest = signed with { Findings = tamperedFindings };

        Assert.False(_hasher.VerifyManifest(tamperedManifest));
    }

    [Fact]
    public void VerifyManifest_DetectsTamperingInArtifactHash()
    {
        var manifest = CreateSampleManifest();
        var signed = _hasher.SignManifest(manifest);

        // Tamper with an artifact hash
        var tamperedArtifacts = new List<EvidenceArtifact>
        {
            new("sarif.json", "application/json", "deadbeef00000000000000000000000000000000000000000000000000000000", "artifacts/sarif.json")
        };
        var tamperedManifest = signed with { Artifacts = tamperedArtifacts };

        Assert.False(_hasher.VerifyManifest(tamperedManifest));
    }

    [Fact]
    public void ComputeFingerprint_GeneratesStableReproducibleHash()
    {
        var location1 = new FindingLocation("src/Web/Controllers/AuthController.cs", 42, 10);
        var location2 = new FindingLocation("src/Web/Controllers/AuthController.cs", 42, 10);
        var differentLocation = new FindingLocation("src/Web/Controllers/UserController.cs", 42, 10);

        var fp1 = Finding.ComputeFingerprint("SEC-001", location1);
        var fp2 = Finding.ComputeFingerprint("SEC-001", location2);
        var fp3 = Finding.ComputeFingerprint("SEC-001", differentLocation);

        Assert.Equal(fp1, fp2);
        Assert.NotEqual(fp1, fp3);
    }

    private static EvidenceManifest CreateSampleManifest()
    {
        var finding = new Finding(
            Id: "SEC-001-1",
            RuleId: "SEC-001",
            Title: "Hardcoded credential detected in connection string",
            SourceName: "gitleaks",
            SourceVersion: "8.18.2",
            TscCriteria: ["CC6.1"],
            OrgControlId: "ACME-AC-04",
            Severity: Severity.High,
            Category: FindingCategory.Code,
            Location: new FindingLocation("appsettings.json", 14, 5),
            RedactedEvidence: "Server=myServerAddress;Database=myDataBase;Uid=myUsername;Pwd=***",
            RiskExplanation: "Hardcoded credentials can be extracted from source control and leaked.",
            RecommendedFix: "Move credentials to Azure Key Vault or environment variables.",
            Effort: EffortEstimate.Low,
            Confidence: ConfidenceLevel.High,
            Fingerprint: Finding.ComputeFingerprint("SEC-001", new FindingLocation("appsettings.json", 14, 5))
        );

        var provenance = new ToolExecutionProvenance(
            ToolName: "gitleaks",
            ToolVersion: "8.18.2",
            Arguments: ["detect", "--no-git", "--report-format", "sarif"],
            StartTimeUtc: DateTimeOffset.UtcNow.AddSeconds(-5),
            EndTimeUtc: DateTimeOffset.UtcNow,
            ExitCode: 0,
            Status: "Success"
        );

        var artifact = new EvidenceArtifact(
            Name: "gitleaks-output.sarif",
            ContentType: "application/sarif+json",
            Sha256Hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            RelativePath: "evidence/gitleaks-output.sarif"
        );

        return new EvidenceManifest(
            RunId: "run-20261106-001",
            TimestampUtc: DateTimeOffset.UtcNow,
            ToolVersion: "0.1.0",
            Target: "C:/Projects/SampleApp",
            CommitSha: "a1b2c3d4e5f6789012345678901234567890abcd",
            CriteriaInScope: ["CC6.1", "CC6.7"],
            ToolProvenance: [provenance],
            Artifacts: [artifact],
            Findings: [finding]
        );
    }
}