using Soc2Evaluator.Core.Models;
using Soc2Evaluator.Rules.Checks;
using Xunit;

namespace Soc2Evaluator.Tests;

public class NativeCodeRulesTests : IDisposable
{
    private readonly string _tempDir;

    public NativeCodeRulesTests()
    {
        _tempDir = Path.Combine(Path.GetTempPath(), $"soc2-rules-test-{Guid.NewGuid():N}");
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
    public async Task WeakCryptoCheck_VulnerableCode_DetectsWeakAlgorithms()
    {
        var vulnerableCode = """
            using System.Security.Cryptography;

            namespace SampleApp;

            public class CryptoHelper
            {
                public byte[] ComputeHash(byte[] data)
                {
                    var md5 = MD5.Create();
                    return md5.ComputeHash(data);
                }

                public void EncryptLegacy()
                {
                    var des = new DESCryptoServiceProvider();
                    des.Mode = CipherMode.ECB;
                }
            }
            """;

        var filePath = Path.Combine(_tempDir, "CryptoHelper.cs");
        await File.WriteAllTextAsync(filePath, vulnerableCode);

        var check = new WeakCryptoCheck();
        var findings = await check.EvaluateAsync(_tempDir);

        Assert.True(findings.Count >= 2);
        Assert.All(findings, f =>
        {
            Assert.Equal("SEC-002", f.RuleId);
            Assert.Contains("CC6.1", f.TscCriteria);
            Assert.Contains("CC6.7", f.TscCriteria);
            Assert.Equal(Severity.High, f.Severity);
            Assert.Equal(FindingCategory.Code, f.Category);
        });
    }

    [Fact]
    public async Task WeakCryptoCheck_CleanCode_ProducesZeroFindings()
    {
        var cleanCode = """
            using System.Security.Cryptography;

            namespace SampleApp;

            public class SecureCryptoHelper
            {
                public byte[] ComputeHash(byte[] data)
                {
                    return SHA256.HashData(data);
                }

                public void EncryptModern()
                {
                    using var aes = Aes.Create();
                    aes.Mode = CipherMode.CBC;
                }
            }
            """;

        var filePath = Path.Combine(_tempDir, "SecureCryptoHelper.cs");
        await File.WriteAllTextAsync(filePath, cleanCode);

        var check = new WeakCryptoCheck();
        var findings = await check.EvaluateAsync(_tempDir);

        Assert.Empty(findings);
    }

    [Fact]
    public async Task MissingAuthorizeCheck_UnprotectedController_DetectsMissingAuthorize()
    {
        var vulnerableCode = """
            using Microsoft.AspNetCore.Mvc;

            namespace SampleApp.Controllers;

            public class AdminController : ControllerBase
            {
                public IActionResult GetUserRecords()
                {
                    return Ok();
                }
            }
            """;

        var filePath = Path.Combine(_tempDir, "AdminController.cs");
        await File.WriteAllTextAsync(filePath, vulnerableCode);

        var check = new MissingAuthorizeCheck();
        var findings = await check.EvaluateAsync(_tempDir);

        Assert.Single(findings);
        var finding = findings[0];
        Assert.Equal("SEC-003", finding.RuleId);
        Assert.Contains("CC6.1", finding.TscCriteria);
        Assert.Contains("CC6.3", finding.TscCriteria);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Contains("GetUserRecords", finding.Title);
    }

    [Fact]
    public async Task MissingAuthorizeCheck_ProtectedController_ProducesZeroFindings()
    {
        var cleanCode = """
            using Microsoft.AspNetCore.Authorization;
            using Microsoft.AspNetCore.Mvc;

            namespace SampleApp.Controllers;

            [Authorize]
            public class SecureAdminController : ControllerBase
            {
                public IActionResult GetUserRecords()
                {
                    return Ok();
                }
            }
            """;

        var filePath = Path.Combine(_tempDir, "SecureAdminController.cs");
        await File.WriteAllTextAsync(filePath, cleanCode);

        var check = new MissingAuthorizeCheck();
        var findings = await check.EvaluateAsync(_tempDir);

        Assert.Empty(findings);
    }

    [Fact]
    public async Task DisabledCertValidationCheck_DisabledCallback_DetectsVulnerability()
    {
        var vulnerableCode = """
            using System.Net.Http;

            namespace SampleApp;

            public class HttpFactory
            {
                public HttpClient CreateInsecureClient()
                {
                    var handler = new HttpClientHandler
                    {
                        ServerCertificateCustomValidationCallback = (msg, cert, chain, err) => true
                    };
                    return new HttpClient(handler);
                }
            }
            """;

        var filePath = Path.Combine(_tempDir, "HttpFactory.cs");
        await File.WriteAllTextAsync(filePath, vulnerableCode);

        var check = new DisabledCertValidationCheck();
        var findings = await check.EvaluateAsync(_tempDir);

        Assert.Single(findings);
        var finding = findings[0];
        Assert.Equal("SEC-004", finding.RuleId);
        Assert.Equal(Severity.Critical, finding.Severity);
        Assert.Contains("CC6.7", finding.TscCriteria);
    }

    [Fact]
    public async Task DisabledCertValidationCheck_CleanClient_ProducesZeroFindings()
    {
        var cleanCode = """
            using System.Net.Http;

            namespace SampleApp;

            public class HttpFactory
            {
                public HttpClient CreateSecureClient()
                {
                    var handler = new HttpClientHandler();
                    return new HttpClient(handler);
                }
            }
            """;

        var filePath = Path.Combine(_tempDir, "HttpFactory.cs");
        await File.WriteAllTextAsync(filePath, cleanCode);

        var check = new DisabledCertValidationCheck();
        var findings = await check.EvaluateAsync(_tempDir);

        Assert.Empty(findings);
    }

    [Fact]
    public async Task SqlConcatenationCheck_StringConcatQuery_DetectsVulnerability()
    {
        var vulnerableCode = """
            using Microsoft.Data.SqlClient;

            namespace SampleApp;

            public class UserRepo
            {
                public void DeleteUser(string userId)
                {
                    var query = "DELETE FROM Users WHERE Id = '" + userId + "'";
                    using var cmd = new SqlCommand(query);
                }
            }
            """;

        var filePath = Path.Combine(_tempDir, "UserRepo.cs");
        await File.WriteAllTextAsync(filePath, vulnerableCode);

        var check = new SqlConcatenationCheck();
        var findings = await check.EvaluateAsync(_tempDir);

        Assert.Single(findings);
        var finding = findings[0];
        Assert.Equal("SEC-005", finding.RuleId);
        Assert.Equal(Severity.High, finding.Severity);
        Assert.Contains("CC6.1", finding.TscCriteria);
        Assert.Contains("CC7.1", finding.TscCriteria);
    }

    [Fact]
    public async Task SqlConcatenationCheck_ParameterizedQuery_ProducesZeroFindings()
    {
        var cleanCode = """
            using Microsoft.Data.SqlClient;

            namespace SampleApp;

            public class UserRepo
            {
                public void DeleteUser(string userId)
                {
                    using var cmd = new SqlCommand("DELETE FROM Users WHERE Id = @Id");
                    cmd.Parameters.AddWithValue("@Id", userId);
                }
            }
            """;

        var filePath = Path.Combine(_tempDir, "UserRepo.cs");
        await File.WriteAllTextAsync(filePath, cleanCode);

        var check = new SqlConcatenationCheck();
        var findings = await check.EvaluateAsync(_tempDir);

        Assert.Empty(findings);
    }

    [Fact]
    public async Task PermissiveCorsCheck_WildcardOriginPolicy_DetectsVulnerability()
    {
        var vulnerableCode = """
            using Microsoft.AspNetCore.Builder;

            namespace SampleApp;

            public class Startup
            {
                public void ConfigureCors(CorsPolicyBuilder builder)
                {
                    builder.SetIsOriginAllowed(_ => true);
                }
            }
            """;

        var filePath = Path.Combine(_tempDir, "Startup.cs");
        await File.WriteAllTextAsync(filePath, vulnerableCode);

        var check = new PermissiveCorsCheck();
        var findings = await check.EvaluateAsync(_tempDir);

        Assert.Single(findings);
        var finding = findings[0];
        Assert.Equal("CFG-005", finding.RuleId);
        Assert.Equal(Severity.Medium, finding.Severity);
        Assert.Contains("CC6.6", finding.TscCriteria);
    }

    [Fact]
    public async Task PermissiveCorsCheck_ExplicitOrigins_ProducesZeroFindings()
    {
        var cleanCode = """
            using Microsoft.AspNetCore.Builder;

            namespace SampleApp;

            public class Startup
            {
                public void ConfigureCors(CorsPolicyBuilder builder)
                {
                    builder.WithOrigins("https://app.example.com", "https://admin.example.com")
                           .AllowAnyMethod()
                           .AllowAnyHeader();
                }
            }
            """;

        var filePath = Path.Combine(_tempDir, "Startup.cs");
        await File.WriteAllTextAsync(filePath, cleanCode);

        var check = new PermissiveCorsCheck();
        var findings = await check.EvaluateAsync(_tempDir);

        Assert.Empty(findings);
    }
}