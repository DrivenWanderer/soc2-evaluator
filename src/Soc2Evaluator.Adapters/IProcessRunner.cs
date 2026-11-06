namespace Soc2Evaluator.Adapters;

public record ProcessResult(
    int ExitCode,
    string StandardOutput,
    string StandardError,
    DateTimeOffset StartTimeUtc,
    DateTimeOffset EndTimeUtc
);

public interface IProcessRunner
{
    Task<ProcessResult> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        string? workingDirectory = null,
        IReadOnlyDictionary<string, string>? environmentVariables = null,
        CancellationToken cancellationToken = default
    );

    bool ExistsOnPath(string executableName);
}