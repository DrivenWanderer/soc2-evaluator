namespace Soc2Evaluator.Core.Models;

public record ToolExecutionProvenance(
    string ToolName,
    string? ToolVersion,
    IReadOnlyList<string> Arguments,
    DateTimeOffset StartTimeUtc,
    DateTimeOffset EndTimeUtc,
    int? ExitCode,
    string Status, // "Success", "Failed", "NotRun", "Skipped"
    string? ErrorMessage = null
);