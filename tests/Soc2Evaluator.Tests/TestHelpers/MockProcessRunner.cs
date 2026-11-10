using Soc2Evaluator.Adapters;

namespace Soc2Evaluator.Tests.TestHelpers;

public class MockProcessRunner : IProcessRunner
{
    private readonly bool _exists;
    public string VersionOutput { get; set; } = "1.0.0";
    public Func<string, IReadOnlyList<string>, ProcessResult>? OnRun { get; set; }

    public MockProcessRunner(bool isToolAvailable, string versionOutput = "1.0.0", Func<string, IReadOnlyList<string>, ProcessResult>? onRun = null)
    {
        _exists = isToolAvailable;
        VersionOutput = versionOutput;
        OnRun = onRun;
    }

    public bool ExistsOnPath(string executableName) => _exists;

    public Task<ProcessResult> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        string? workingDirectory = null,
        IReadOnlyDictionary<string, string>? environmentVariables = null,
        CancellationToken cancellationToken = default
    )
    {
        if (!_exists)
        {
            throw new FileNotFoundException($"Executable {fileName} not found");
        }

        if (arguments.Count == 1 && (arguments[0] == "version" || arguments[0] == "--version"))
        {
            return Task.FromResult(new ProcessResult(0, VersionOutput, "", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow));
        }

        if (OnRun != null)
        {
            return Task.FromResult(OnRun(fileName, arguments));
        }

        return Task.FromResult(new ProcessResult(0, "", "", DateTimeOffset.UtcNow, DateTimeOffset.UtcNow));
    }
}