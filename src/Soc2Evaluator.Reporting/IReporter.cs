using Soc2Evaluator.Core.Models;

namespace Soc2Evaluator.Reporting;

public interface IReporter
{
    string FormatName { get; }
    string OutputFileName { get; }
    Task<string> RenderAsync(EvidenceManifest manifest, CancellationToken cancellationToken = default);
}