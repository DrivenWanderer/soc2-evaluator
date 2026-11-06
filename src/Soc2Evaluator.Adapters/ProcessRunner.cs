using System.Diagnostics;

namespace Soc2Evaluator.Adapters;

public class ProcessRunner : IProcessRunner
{
    public bool ExistsOnPath(string executableName)
    {
        if (Path.IsPathRooted(executableName) && File.Exists(executableName))
        {
            return true;
        }

        var pathEnv = Environment.GetEnvironmentVariable("PATH") ?? string.Empty;
        var paths = pathEnv.Split(Path.PathSeparator, StringSplitOptions.RemoveEmptyEntries);

        var extensions = OperatingSystem.IsWindows()
            ? (Environment.GetEnvironmentVariable("PATHEXT") ?? ".EXE;.BAT;.CMD").Split(';')
            : [""];

        foreach (var dir in paths)
        {
            foreach (var ext in extensions)
            {
                var full = Path.Combine(dir, executableName.EndsWith(ext, StringComparison.OrdinalIgnoreCase) ? executableName : executableName + ext);
                if (File.Exists(full))
                {
                    return true;
                }
            }
        }

        return false;
    }

    public async Task<ProcessResult> RunAsync(
        string fileName,
        IReadOnlyList<string> arguments,
        string? workingDirectory = null,
        IReadOnlyDictionary<string, string>? environmentVariables = null,
        CancellationToken cancellationToken = default
    )
    {
        var startInfo = new ProcessStartInfo
        {
            FileName = fileName,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            UseShellExecute = false,
            CreateNoWindow = true,
            WorkingDirectory = workingDirectory ?? Directory.GetCurrentDirectory()
        };

        foreach (var arg in arguments)
        {
            startInfo.ArgumentList.Add(arg);
        }

        if (environmentVariables != null)
        {
            foreach (var (k, v) in environmentVariables)
            {
                startInfo.EnvironmentVariables[k] = v;
            }
        }

        var startTime = DateTimeOffset.UtcNow;
        using var process = new Process { StartInfo = startInfo };

        process.Start();

        var stdoutTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
        var stderrTask = process.StandardError.ReadToEndAsync(cancellationToken);

        await process.WaitForExitAsync(cancellationToken);
        var stdout = await stdoutTask;
        var stderr = await stderrTask;
        var endTime = DateTimeOffset.UtcNow;

        return new ProcessResult(
            ExitCode: process.ExitCode,
            StandardOutput: stdout,
            StandardError: stderr,
            StartTimeUtc: startTime,
            EndTimeUtc: endTime
        );
    }
}