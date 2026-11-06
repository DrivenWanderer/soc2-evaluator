using Soc2Evaluator.Core.Models;

namespace Soc2Evaluator.Core.Services;

public interface IEvidenceHasher
{
    string ComputeSha256(byte[] data);
    string ComputeSha256(string content);
    string ComputeSha256(Stream stream);
    EvidenceManifest SignManifest(EvidenceManifest manifest);
    bool VerifyManifest(EvidenceManifest manifest);
}