namespace Soc2Evaluator.Reporting;

public class ReporterFactory
{
    private readonly Dictionary<string, IReporter> _reporters;

    public ReporterFactory(IEnumerable<IReporter> reporters)
    {
        _reporters = reporters.ToDictionary(r => r.FormatName.ToLowerInvariant(), r => r);
    }

    public IReporter GetReporter(string format)
    {
        if (_reporters.TryGetValue(format.Trim().ToLowerInvariant(), out var reporter))
        {
            return reporter;
        }

        throw new ArgumentException($"Unsupported report format '{format}'. Supported formats: {string.Join(", ", _reporters.Keys)}");
    }

    public IEnumerable<IReporter> GetAllReporters() => _reporters.Values;
}