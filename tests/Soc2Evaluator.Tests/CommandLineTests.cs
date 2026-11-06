using Soc2Evaluator.Cli;
using Xunit;

namespace Soc2Evaluator.Tests;

public class CommandLineTests
{
    [Fact]
    public void RootCommand_ContainsExpectedSubcommands()
    {
        var root = CommandLineBuilder.BuildRootCommand((_, _) => Task.FromResult(0));

        Assert.Contains(root.Subcommands, c => c.Name == "scan");
        Assert.Contains(root.Subcommands, c => c.Name == "trend");
    }

    [Fact]
    public async Task ScanCommand_WithDefaults_ParsesCorrectly()
    {
        ScanOptions? captured = null;
        var root = CommandLineBuilder.BuildRootCommand((options, _) =>
        {
            captured = options;
            return Task.FromResult(0);
        });

        var exitCode = await root.Parse("scan").InvokeAsync();

        Assert.Equal(0, exitCode);
        Assert.NotNull(captured);
        Assert.Equal(".", captured.Target);
        Assert.Equal("./reports", captured.OutputPath);
        Assert.Equal(["md", "json"], captured.Formats);
        Assert.False(captured.Sandbox);
        Assert.False(captured.Offline);
    }

    [Fact]
    public async Task ScanCommand_WithExplicitOptions_BindsAllParameters()
    {
        ScanOptions? captured = null;
        var root = CommandLineBuilder.BuildRootCommand((options, _) =>
        {
            captured = options;
            return Task.FromResult(0);
        });

        var args = "scan ./my-repo --url https://example.com --criteria security availability --out ./custom-out --fail-on high --sandbox --offline";
        var exitCode = await root.Parse(args).InvokeAsync();

        Assert.Equal(0, exitCode);
        Assert.NotNull(captured);
        Assert.Equal("./my-repo", captured.Target);
        Assert.Equal("https://example.com", captured.Url);
        Assert.Equal(["security", "availability"], captured.Criteria);
        Assert.Equal("./custom-out", captured.OutputPath);
        Assert.Equal("high", captured.FailOnSeverity);
        Assert.True(captured.Sandbox);
        Assert.True(captured.Offline);
    }
}