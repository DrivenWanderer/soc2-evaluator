using Soc2Evaluator.Core.Adapters;
using Soc2Evaluator.Core.Models;
using Soc2Evaluator.Core.Services;
using Soc2Evaluator.Rules;
using Soc2Evaluator.Rules.Checks;
using Xunit;

namespace Soc2Evaluator.Tests;

public class VerboseErrorsCheckTests : IDisposable
{
    private readonly List<string> _tempDirs = [];
    private readonly IEvidenceHasher _hasher = new EvidenceHasher();

    public void Dispose()
    {
        foreach (var dir in _tempDirs)
        {
            if (Directory.Exists(dir))
            {
                try { Directory.Delete(dir, true); } catch { /* ignore */ }
            }
        }
    }

    [Fact]
    public async Task VerboseErrorsCheck_VulnerableApp_DetectsDebugAndCustomErrorsOff()
    {
        var check = new VerboseErrorsCheck();
        var fixturePath = GetFixturePath("vulnerable-app");

        var findings = await check.EvaluateAsync(fixturePath);

        Assert.Equal(2, findings.Count);

        var debugFinding = findings.FirstOrDefault(f => f.Title.Contains("Debug compilation"));
        Assert.NotNull(debugFinding);
        Assert.Equal("CFG-002", debugFinding.RuleId);
        Assert.Contains("CC6.1", debugFinding.TscCriteria);
        Assert.Contains("CC7.2", debugFinding.TscCriteria);
        Assert.Equal(Severity.Medium, debugFinding.Severity);
        Assert.Equal(FindingCategory.Configuration, debugFinding.Category);
        Assert.NotNull(debugFinding.Location?.LineNumber);

        var customErrorsFinding = findings.FirstOrDefault(f => f.Title.Contains("Custom errors"));
        Assert.NotNull(customErrorsFinding);
        Assert.Equal("CFG-002", customErrorsFinding.RuleId);
        Assert.NotNull(customErrorsFinding.Location?.LineNumber);
    }

    [Fact]
    public async Task VerboseErrorsCheck_CleanApp_ProducesZeroFindings()
    {
        var check = new VerboseErrorsCheck();
        var fixturePath = GetFixturePath("clean-app");

        var findings = await check.EvaluateAsync(fixturePath);

        Assert.Empty(findings);
    }

    [Fact]
    public async Task VerboseErrorsCheck_AppSettingsDetailedErrors_DetectsVulnerability()
    {
        var tempDir = Path.Combine(Path.GetTempPath(), $"cfg-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(tempDir);
        _tempDirs.Add(tempDir);

        var appSettingsContent = """
        {
          "Logging": {
            "LogLevel": { "Default": "Information" }
          },
          "DetailedErrors": true
        }
        """;

        File.WriteAllText(Path.Combine(tempDir, "appsettings.Production.json"), appSettingsContent);

        var check = new VerboseErrorsCheck();
        var findings = await check.EvaluateAsync(tempDir);

        Assert.Single(findings);
        var finding = findings[0];
        Assert.Equal("CFG-002", finding.RuleId);
        Assert.Contains("DetailedErrors", finding.Title);
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal(FindingCategory.Configuration, finding.Category);
        Assert.Contains("CC6.1", finding.TscCriteria);
        Assert.Contains("CC7.2", finding.TscCriteria);
        Assert.NotNull(finding.Location?.LineNumber);
    }

    [Fact]
    public async Task RulesScannerAdapter_ExecutesChecksAndProducesArtifact()
    {
        var check = new VerboseErrorsCheck();
        var adapter = new RulesScannerAdapter([check], _hasher);

        var fixturePath = GetFixturePath("vulnerable-app");
        var result = await adapter.ExecuteAsync(new AdapterExecutionContext(fixturePath, ["CC6.1", "CC7.2"]));

        Assert.NotNull(result);
        Assert.Equal("Success", result.Provenance.Status);
        Assert.Equal("Soc2Evaluator.Rules", result.Provenance.ToolName);
        Assert.Equal(2, result.Findings.Count);
        Assert.Single(result.Artifacts);
        Assert.Equal("rules-engine-summary.json", result.Artifacts[0].Name);
        Assert.True(result.RawArtifactBytes.ContainsKey("rules-engine-summary.json"));
    }

    private static string GetFixturePath(string fixtureName)
    {
        var candidates = new[]
        {
            Path.Combine(AppContext.BaseDirectory, $"../../../../fixtures/{fixtureName}"),
            Path.Combine(AppContext.BaseDirectory, $"../../../fixtures/{fixtureName}"),
            Path.Combine(Directory.GetCurrentDirectory(), $"tests/fixtures/{fixtureName}"),
            Path.Combine(Directory.GetCurrentDirectory(), $"fixtures/{fixtureName}")
        };

        foreach (var c in candidates)
        {
            var full = Path.GetFullPath(c);
            if (Directory.Exists(full))
            {
                return full;
            }
        }

        throw new DirectoryNotFoundException($"Could not locate fixture '{fixtureName}'");
    }
}