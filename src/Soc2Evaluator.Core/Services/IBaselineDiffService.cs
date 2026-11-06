using Soc2Evaluator.Core.Models;

namespace Soc2Evaluator.Core.Services;

public interface IBaselineDiffService
{
    /// <summary>
    /// Loads previous findings from a baseline file (manifest, bundle, or finding list) and computes the delta against current findings.
    /// </summary>
    BaselineDelta ComputeDelta(IReadOnlyList<Finding> currentFindings, string baselineFilePath);

    /// <summary>
    /// Parses previous findings from a baseline file.
    /// </summary>
    IReadOnlyList<Finding> LoadBaselineFindings(string baselineFilePath);
}