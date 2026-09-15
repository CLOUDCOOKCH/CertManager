using System.IO.Compression;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CertificateManager.Application;
using CertificateManager.Domain;

namespace CertificateManager.UnitTests;

public class CertificateServicesTests
{
    [Fact]
    public void GeneratesExpectedCertificateAndExports()
    {
        var service = new CertificateGenerator();
        var request = new GenerateCertificateRequest(
            Guid.NewGuid(),
            "api-prod",
            "api.example",
            365,
            "owner@example.com");

        var result = service.Generate(
            request,
            "user",
            "Contoso",
            "Production",
            "API",
            null);

        using var certificate = new X509Certificate2(
            result.Pfx,
            result.Password,
            X509KeyStorageFlags.EphemeralKeySet);
        using var zip = new ZipArchive(new MemoryStream(result.Package));

        Assert.Equal(3072, certificate.GetRSAPublicKey()!.KeySize);
        Assert.Equal("CN=api.example", certificate.Subject);
        Assert.True(certificate.HasPrivateKey);
        Assert.NotEmpty(result.Cer);
        Assert.Equal(certificate.Thumbprint, result.Metadata.Thumbprint);
        Assert.InRange(
            (result.Metadata.ValidUntil - result.Metadata.ValidFrom).TotalDays,
            364.9,
            365.1);
        Assert.Equal(4, zip.Entries.Count);
        Assert.DoesNotContain(
            zip.Entries,
            entry => entry.FullName.Contains("password", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void CalendarIsStandardsShapedAndHasAlarms()
    {
        var certificate = new CertificateRecord
        {
            ServiceId = Guid.NewGuid(),
            Name = "api",
            Subject = "CN=api",
            Issuer = "CN=api",
            Thumbprint = "ABC",
            SerialNumber = "1",
            CreatedByUserId = "u",
            PrimaryOwnerEmail = "a@b.test",
            ValidUntil = DateTimeOffset.UtcNow.AddDays(365),
            RenewalDueAt = DateTimeOffset.UtcNow.AddDays(335)
        };

        var calendar = Encoding.UTF8.GetString(
            CalendarGenerator.Generate(certificate, "Contoso", "Prod", "API"));

        Assert.StartsWith("BEGIN:VCALENDAR\r\n", calendar);
        Assert.Contains("VERSION:2.0", calendar);
        Assert.Equal(2, calendar.Split("BEGIN:VALARM").Length - 1);
        Assert.EndsWith("END:VCALENDAR\r\n", calendar);
    }

    [Theory]
    [InlineData(-1, "Expired")]
    [InlineData(3, "Critical")]
    [InlineData(20, "RenewalRequired")]
    [InlineData(45, "RenewalUpcoming")]
    [InlineData(100, "Healthy")]
    public void CalculatesHealth(int days, string expected)
    {
        var expiry = DateTimeOffset.UtcNow.AddDays(days);
        Assert.Equal(expected, CertificateHealth.Calculate(expiry, DateTimeOffset.UtcNow));
    }

    [Fact]
    public void PasswordsAreStrongAndUnique()
    {
        var first = PasswordGenerator.Generate();
        var second = PasswordGenerator.Generate();

        Assert.Equal(24, first.Length);
        Assert.NotEqual(first, second);
        Assert.All(
            new[] { first, second },
            password => Assert.Contains(password, character => !char.IsLetterOrDigit(character)));
    }

    [Theory]
    [InlineData("SHA256")]
    [InlineData("SHA384")]
    [InlineData("SHA512")]
    public void AppliesRequestedSignatureHash(string hashAlgorithm)
    {
        var request = new GenerateCertificateRequest(
            Guid.NewGuid(),
            "api",
            "api.example",
            90,
            "owner@example.com",
            HashAlgorithm: hashAlgorithm);

        var result = new CertificateGenerator().Generate(
            request,
            "user",
            "Contoso",
            "Production",
            "API",
            null);

        Assert.Equal(hashAlgorithm, result.Metadata.HashAlgorithm);
    }

    [Theory]
    [InlineData(
        CertificateUseCase.ClientAuthentication,
        new[] { "1.3.6.1.5.5.7.3.2" })]
    [InlineData(
        CertificateUseCase.ServerAuthentication,
        new[] { "1.3.6.1.5.5.7.3.1" })]
    [InlineData(
        CertificateUseCase.ClientAndServerAuthentication,
        new[] { "1.3.6.1.5.5.7.3.1", "1.3.6.1.5.5.7.3.2" })]
    public void AppliesRequestedExtendedKeyUsage(
        CertificateUseCase useCase,
        string[] expected)
    {
        var request = new GenerateCertificateRequest(
            Guid.NewGuid(),
            "api",
            "api.example",
            365,
            "owner@example.com",
            UseCase: useCase);
        var result = new CertificateGenerator().Generate(
            request,
            "user",
            "Contoso",
            "Production",
            "API",
            null);

        using var certificate = new X509Certificate2(result.Cer);
        var eku = certificate.Extensions
            .OfType<X509EnhancedKeyUsageExtension>()
            .Single();
        var actual = eku.EnhancedKeyUsages
            .Cast<System.Security.Cryptography.Oid>()
            .Select(oid => oid.Value)
            .OrderBy(value => value);

        Assert.Equal(expected.OrderBy(value => value), actual);
    }
}
