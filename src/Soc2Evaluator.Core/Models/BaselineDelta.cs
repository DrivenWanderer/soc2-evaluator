namespace Soc2Evaluator.Core.Models;

public record BaselineDelta(
    string BaselinePath,
    IReadOnlyList<Finding> NewFindings,
    IReadOnlyList<Finding> PersistingFindings,
    IReadOnlyList<Finding> ResolvedFindings
)
{
    public int NewCount => NewFindings.Count;
    public int PersistingCount => PersistingFindings.Count;
    public int ResolvedCount => ResolvedFindings.Count;
}