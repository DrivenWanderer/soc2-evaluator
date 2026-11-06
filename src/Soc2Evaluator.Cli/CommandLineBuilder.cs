using System.CommandLine;

namespace Soc2Evaluator.Cli;

public static class CommandLineBuilder
{
    public static RootCommand BuildRootCommand(Func<ScanOptions, CancellationToken, Task<int>> scanHandler)
    {
        var rootCommand = new RootCommand("SOC 2 readiness assessment and evidence collection orchestrator for .NET and cloud solutions");

        var scanCommand = BuildScanCommand(scanHandler);
        var trendCommand = BuildTrendCommand();

        rootCommand.Add(scanCommand);
        rootCommand.Add(trendCommand);

        return rootCommand;
    }

    private static Command BuildScanCommand(Func<ScanOptions, CancellationToken, Task<int>> scanHandler)
    {
        var scanCommand = new Command("scan", "Scan a target repository or solution and generate a SOC 2 evidence bundle");

        var pathArg = new Argument<string>("path-or-repo-url")
        {
            Description = "Path to local directory or solution file, or git repository URL",
            DefaultValueFactory = _ => "."
        };

        var urlOpt = new Option<string?>("--url")
        {
            Description = "Enable external probe against the target URL (GET/HEAD only; passive probe)"
        };

        var criteriaOpt = new Option<string[]>("--criteria")
        {
            Description = "Trust Services Criteria in scope (e.g. security, availability)",
            AllowMultipleArgumentsPerToken = true
        };

        var orgConfigOpt = new Option<string?>("--org-config")
        {
            Description = "Path to organization control mapping, suppressions, and settings YAML"
        };

        var evidenceOpt = new Option<string?>("--evidence")
        {
            Description = "Path to process-control attestations YAML (evidence questionnaire)"
        };

        var outOpt = new Option<string>("--out")
        {
            Description = "Directory where evidence bundle and reports will be saved",
            DefaultValueFactory = _ => "./reports"
        };

        var formatOpt = new Option<string[]>("--format")
        {
            Description = "Report formats to generate (supported: md, json)",
            AllowMultipleArgumentsPerToken = true,
            DefaultValueFactory = _ => ["md", "json"]
        };

        var failOnOpt = new Option<string?>("--fail-on")
        {
            Description = "Severity threshold for non-zero exit in CI gating (critical, high, medium, low, informational)"
        };

        var baselineOpt = new Option<string?>("--baseline")
        {
            Description = "Path to previous findings.json for delta diffing"
        };

        var sandboxOpt = new Option<bool>("--sandbox")
        {
            Description = "Opt-in build-based semantic analysis in isolation"
        };

        var offlineOpt = new Option<bool>("--offline")
        {
            Description = "Skip network-dependent checks and record them as not run in coverage"
        };

        scanCommand.Add(pathArg);
        scanCommand.Add(urlOpt);
        scanCommand.Add(criteriaOpt);
        scanCommand.Add(orgConfigOpt);
        scanCommand.Add(evidenceOpt);
        scanCommand.Add(outOpt);
        scanCommand.Add(formatOpt);
        scanCommand.Add(failOnOpt);
        scanCommand.Add(baselineOpt);
        scanCommand.Add(sandboxOpt);
        scanCommand.Add(offlineOpt);

        scanCommand.SetAction(async (parseResult, cancellationToken) =>
        {
            var options = new ScanOptions(
                Target: parseResult.GetValue(pathArg) ?? ".",
                Url: parseResult.GetValue(urlOpt),
                Criteria: parseResult.GetValue(criteriaOpt) ?? ["security"],
                OrgConfigPath: parseResult.GetValue(orgConfigOpt),
                EvidencePath: parseResult.GetValue(evidenceOpt),
                OutputPath: parseResult.GetValue(outOpt) ?? "./reports",
                Formats: parseResult.GetValue(formatOpt) ?? ["md", "json"],
                FailOnSeverity: parseResult.GetValue(failOnOpt),
                BaselinePath: parseResult.GetValue(baselineOpt),
                Sandbox: parseResult.GetValue(sandboxOpt),
                Offline: parseResult.GetValue(offlineOpt)
            );

            return await scanHandler(options, cancellationToken);
        });

        return scanCommand;
    }

    private static Command BuildTrendCommand()
    {
        var trendCommand = new Command("trend", "Generate a trend report across previously stored evidence bundles");

        var reportsDirArg = new Argument<string>("reports-dir")
        {
            Description = "Directory containing previously stored evidence runs",
            DefaultValueFactory = _ => "./reports"
        };

        trendCommand.Add(reportsDirArg);

        trendCommand.SetAction((parseResult) =>
        {
            var dir = parseResult.GetValue(reportsDirArg) ?? "./reports";
            Console.WriteLine($"Trend analysis for reports in: {dir} (Feature scheduled for Phase 5)");
            return 0;
        });

        return trendCommand;
    }
}

public record ScanOptions(
    string Target,
    string? Url,
    string[] Criteria,
    string? OrgConfigPath,
    string? EvidencePath,
    string OutputPath,
    string[] Formats,
    string? FailOnSeverity,
    string? BaselinePath,
    bool Sandbox,
    bool Offline
);