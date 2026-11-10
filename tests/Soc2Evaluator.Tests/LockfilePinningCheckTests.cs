using Soc2Evaluator.Core.Models;
using Soc2Evaluator.Rules.Checks;
using Xunit;

namespace Soc2Evaluator.Tests;

public class LockfilePinningCheckTests : IDisposable
{
    private readonly string _tempDir;

    public LockfilePinningCheckTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"soc2-lockfile-test-{Guid.NewGuid():N}");
        Directory.CreateDirectory(_tempDir);
    }

    public void Dispose()
    {
        try
        {
            if (Directory.Exists(_tempDir))
            {
                Directory.Delete(_tempDir, true);
            }
        }
        catch
        {
            // Best effort cleanup
        }
    }

    [Fact]
    public async Task LockfilePinningCheck_FloatingVersions_DetectsUnpinnedDependencies()
    {
        var csproj = """
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup>
                <TargetFramework>net10.0</TargetFramework>
                <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
              </PropertyGroup>
              <ItemGroup>
                <PackageReference Include="Newtonsoft.Json" Version="13.*" />
                <PackageReference Include="Serilog" Version="2.10.0" />
              </ItemGroup>
            </Project>
            """;

        var projPath = Path.Combine(_tempDir, "SampleApp.csproj");
        await File.WriteAllTextAsync(projPath, csproj);

        var check = new LockfilePinningCheck();
        var findings = await check.EvaluateAsync(_tempDir);

        Assert.Single(findings);
        var finding = findings[0];
        Assert.Equal("DEP-002", finding.RuleId);
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Equal(FindingCategory.Configuration, finding.Category);
        Assert.Contains("CC8.1", finding.TscCriteria);
        Assert.Contains("Newtonsoft.Json", finding.Title);
        Assert.Contains("13.*", finding.Title);
    }

    [Fact]
    public async Task LockfilePinningCheck_MissingLockfile_DetectsMissingLockfile()
    {
        var csproj = """
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup>
                <TargetFramework>net10.0</TargetFramework>
              </PropertyGroup>
              <ItemGroup>
                <PackageReference Include="Serilog" Version="2.10.0" />
              </ItemGroup>
            </Project>
            """;

        var projPath = Path.Combine(_tempDir, "SampleApp.csproj");
        await File.WriteAllTextAsync(projPath, csproj);

        var check = new LockfilePinningCheck();
        var findings = await check.EvaluateAsync(_tempDir);

        Assert.Single(findings);
        var finding = findings[0];
        Assert.Equal("DEP-002", finding.RuleId);
        Assert.Contains("missing packages.lock.json", finding.Title, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("CC8.1", finding.TscCriteria);
    }

    [Fact]
    public async Task LockfilePinningCheck_WithLockfileSettingAndPinnedVersions_ProducesZeroFindings()
    {
        var csproj = """
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup>
                <TargetFramework>net10.0</TargetFramework>
                <RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>
              </PropertyGroup>
              <ItemGroup>
                <PackageReference Include="Serilog" Version="2.10.0" />
              </ItemGroup>
            </Project>
            """;

        var projPath = Path.Combine(_tempDir, "SampleApp.csproj");
        await File.WriteAllTextAsync(projPath, csproj);

        var check = new LockfilePinningCheck();
        var findings = await check.EvaluateAsync(_tempDir);

        Assert.Empty(findings);
    }

    [Fact]
    public async Task LockfilePinningCheck_WithCommittedLockfile_ProducesZeroFindings()
    {
        var csproj = """
            <Project Sdk="Microsoft.NET.Sdk">
              <PropertyGroup>
                <TargetFramework>net10.0</TargetFramework>
              </PropertyGroup>
              <ItemGroup>
                <PackageReference Include="Serilog" Version="2.10.0" />
              </ItemGroup>
            </Project>
            """;

        var projPath = Path.Combine(_tempDir, "SampleApp.csproj");
        await File.WriteAllTextAsync(projPath, csproj);
        await File.WriteAllTextAsync(Path.Combine(_tempDir, "packages.lock.json"), "{}");

        var check = new LockfilePinningCheck();
        var findings = await check.EvaluateAsync(_tempDir);

        Assert.Empty(findings);
    }

    [Fact]
    public async Task LockfilePinningCheck_NpmMissingLockfile_DetectsVulnerability()
    {
        var packageJson = """
            {
              "name": "sample-web",
              "dependencies": {
                "express": "^4.18.2"
              }
            }
            """;

        await File.WriteAllTextAsync(Path.Combine(_tempDir, "package.json"), packageJson);

        var check = new LockfilePinningCheck();
        var findings = await check.EvaluateAsync(_tempDir);

        Assert.Single(findings);
        var finding = findings[0];
        Assert.Equal("DEP-002", finding.RuleId);
        Assert.Contains("Node.js project missing package-lock.json", finding.Title);
    }
}