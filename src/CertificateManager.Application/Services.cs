using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CertificateManager.Domain;

namespace CertificateManager.Application;

public enum CertificateUseCase
{
    ClientAuthentication = 0,
    ServerAuthentication = 1,
    ClientAndServerAuthentication = 2
}

public record GenerateCertificateRequest(
    Guid ServiceId,
    string Name,
    string CommonName,
    int ValidityDays,
    string PrimaryOwnerEmail,
    int RenewalReminderDays = 30,
    int KeySize = 3072,
    string HashAlgorithm = "SHA256",
    string? Password = null,
    Guid? PreviousCertificateId = null,
    string? Notes = null,
    CertificateUseCase UseCase = CertificateUseCase.ClientAuthentication);

public sealed record GeneratedCertificate(
    CertificateRecord Metadata,
    byte[] Pfx,
    byte[] Cer,
    byte[] Calendar,
    byte[] Package,
    string Password);

public interface ICertificateGenerator
{
    GeneratedCertificate Generate(
        GenerateCertificateRequest request,
        string userId,
        string customer,
        string environment,
        string service,
        string? clientId);
}

public sealed class CertificateGenerator : ICertificateGenerator
{
    public GeneratedCertificate Generate(
        GenerateCertificateRequest request,
        string userId,
        string customer,
        string environment,
        string service,
        string? clientId)
    {
        Validate(request);

        var hash = GetHashAlgorithm(request.HashAlgorithm);
        using var rsa = RSA.Create(request.KeySize);

        var subject = new X500DistinguishedName($"CN={EscapeDn(request.CommonName)}");
        var certificateRequest = new CertificateRequest(
            subject,
            rsa,
            hash,
            RSASignaturePadding.Pkcs1);

        AddCertificateExtensions(certificateRequest, request.UseCase);

        var validFrom = DateTimeOffset.UtcNow.AddMinutes(-5);
        var validUntil = validFrom.AddDays(request.ValidityDays);
        var serial = CreateSerialNumber();

        using var certificate = certificateRequest.Create(
            subject,
            X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1),
            validFrom,
            validUntil,
            serial);
        using var certificateWithKey = certificate.CopyWithPrivateKey(rsa);

        var password = string.IsNullOrEmpty(request.Password)
            ? PasswordGenerator.Generate()
            : request.Password;
        var pfx = certificateWithKey.Export(X509ContentType.Pfx, password);
        var cer = certificate.Export(X509ContentType.Cert);

        var metadata = new CertificateRecord
        {
            ServiceId = request.ServiceId,
            Name = request.Name,
            Subject = certificate.Subject,
            Issuer = certificate.Issuer,
            Thumbprint = certificate.Thumbprint,
            SerialNumber = certificate.SerialNumber,
            KeySize = request.KeySize,
            HashAlgorithm = hash.Name!,
            ValidFrom = validFrom,
            ValidUntil = validUntil,
            RenewalDueAt = validUntil.AddDays(-request.RenewalReminderDays),
            CreatedByUserId = userId,
            PrimaryOwnerEmail = request.PrimaryOwnerEmail,
            PreviousCertificateId = request.PreviousCertificateId,
            Notes = request.Notes
        };

        var calendar = CalendarGenerator.Generate(metadata, customer, environment, service);
        var package = CreatePackage(
            request.Name,
            pfx,
            cer,
            calendar,
            CreateCertificateInfo(metadata, customer, environment, service, clientId, request.UseCase));

        return new GeneratedCertificate(metadata, pfx, cer, calendar, package, password);
    }

    private static void Validate(GenerateCertificateRequest request)
    {
        if (request.KeySize is not (2048 or 3072 or 4096))
        {
            throw new ArgumentOutOfRangeException(nameof(request.KeySize));
        }

        if (request.ValidityDays is < 1 or > 3650)
        {
            throw new ArgumentOutOfRangeException(nameof(request.ValidityDays));
        }

        if (request.RenewalReminderDays < 1 ||
            request.RenewalReminderDays > request.ValidityDays)
        {
            throw new ArgumentOutOfRangeException(nameof(request.RenewalReminderDays));
        }

        if (string.IsNullOrWhiteSpace(request.Name) || request.Name.Length > 200)
        {
            throw new ArgumentException(
                "Certificate name is required and must be 200 characters or fewer",
                nameof(request.Name));
        }

        if (Safe(request.Name).Length == 0)
        {
            throw new ArgumentException(
                "Certificate name must contain at least one letter or number",
                nameof(request.Name));
        }

        if (string.IsNullOrWhiteSpace(request.CommonName) || request.CommonName.Length > 255)
        {
            throw new ArgumentException(
                "Common name is required and must be 255 characters or fewer",
                nameof(request.CommonName));
        }

        if (string.IsNullOrWhiteSpace(request.PrimaryOwnerEmail) ||
            request.PrimaryOwnerEmail.Length > 320 ||
            !request.PrimaryOwnerEmail.Contains('@'))
        {
            throw new ArgumentException(
                "A valid owner email is required",
                nameof(request.PrimaryOwnerEmail));
        }

        if (!Enum.IsDefined(typeof(CertificateUseCase), request.UseCase))
        {
            throw new ArgumentOutOfRangeException(nameof(request.UseCase));
        }

        if (!string.IsNullOrEmpty(request.Password) && request.Password.Length < 16)
        {
            throw new ArgumentException(
                "A supplied PFX password must be at least 16 characters",
                nameof(request.Password));
        }

        if (string.IsNullOrWhiteSpace(request.HashAlgorithm))
        {
            throw new ArgumentException("A signature hash algorithm is required", nameof(request.HashAlgorithm));
        }
    }

    private static HashAlgorithmName GetHashAlgorithm(string value) =>
        value.ToUpperInvariant() switch
        {
            "SHA256" => HashAlgorithmName.SHA256,
            "SHA384" => HashAlgorithmName.SHA384,
            "SHA512" => HashAlgorithmName.SHA512,
            _ => throw new ArgumentException("Unsupported hash algorithm", nameof(value))
        };

    private static void AddCertificateExtensions(
        CertificateRequest request,
        CertificateUseCase useCase)
    {
        request.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, true));
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));

        var enhancedKeyUsages = new OidCollection();

        if (useCase is CertificateUseCase.ClientAuthentication
            or CertificateUseCase.ClientAndServerAuthentication)
        {
            enhancedKeyUsages.Add(
                new Oid("1.3.6.1.5.5.7.3.2", "Client Authentication"));
        }

        if (useCase is CertificateUseCase.ServerAuthentication
            or CertificateUseCase.ClientAndServerAuthentication)
        {
            enhancedKeyUsages.Add(
                new Oid("1.3.6.1.5.5.7.3.1", "Server Authentication"));
        }

        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(enhancedKeyUsages, true));
        request.CertificateExtensions.Add(
            new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
    }

    private static byte[] CreateSerialNumber()
    {
        Span<byte> serial = stackalloc byte[16];
        RandomNumberGenerator.Fill(serial);
        serial[0] &= 0x7f;

        if (serial[0] == 0)
        {
            serial[0] = 1;
        }

        return serial.ToArray();
    }

    private static string EscapeDn(string value) =>
        value
            .Replace("\\", "\\\\")
            .Replace(",", "\\,")
            .Replace("+", "\\+")
            .Replace("\"", "\\\"");

    private static byte[] CreatePackage(
        string name,
        byte[] pfx,
        byte[] cer,
        byte[] calendar,
        string information)
    {
        using var output = new MemoryStream();

        using (var archive = new ZipArchive(output, ZipArchiveMode.Create, true))
        {
            AddToArchive(archive, $"{Safe(name)}.pfx", pfx);
            AddToArchive(archive, $"{Safe(name)}.cer", cer);
            AddToArchive(archive, "renewal-reminder.ics", calendar);
            AddToArchive(
                archive,
                "certificate-information.txt",
                Encoding.UTF8.GetBytes(information));
        }

        return output.ToArray();
    }

    private static void AddToArchive(ZipArchive archive, string name, byte[] content)
    {
        var entry = archive.CreateEntry(name, CompressionLevel.Optimal);
        using var stream = entry.Open();
        stream.Write(content);
    }

    private static string Safe(string value) =>
        string.Concat(
                value.Select(character =>
                    char.IsLetterOrDigit(character) || character is '-' or '_'
                        ? character
                        : '-'))
            .Trim('-');

    private static string CreateCertificateInfo(
        CertificateRecord certificate,
        string customer,
        string environment,
        string service,
        string? clientId,
        CertificateUseCase useCase) =>
        $"Certificate Lifecycle Manager\n\n" +
        $"Customer:\n{customer}\n\n" +
        $"Environment:\n{environment}\n\n" +
        $"Service / Application:\n{service}\n\n" +
        $"Application Client ID:\n{clientId ?? "Not specified"}\n\n" +
        $"Certificate purpose:\n{useCase}\n\n" +
        $"Certificate:\n{certificate.Name}\n\n" +
        $"Subject:\n{certificate.Subject}\n\n" +
        $"Thumbprint:\n{certificate.Thumbprint}\n\n" +
        $"Serial Number:\n{certificate.SerialNumber}\n\n" +
        $"Issued:\n{certificate.ValidFrom:u}\n\n" +
        $"Expires:\n{certificate.ValidUntil:u}\n\n" +
        $"Renewal Due:\n{certificate.RenewalDueAt:u}\n";
}

public static class PasswordGenerator
{
    private const string Alphabet =
        "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@$%*?";

    public static string Generate(int length = 24)
    {
        if (length < 16)
        {
            throw new ArgumentOutOfRangeException(nameof(length));
        }

        return string.Create(
            length,
            0,
            (span, _) =>
            {
                for (var index = 0; index < span.Length; index++)
                {
                    span[index] = Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)];
                }
            });
    }
}

public static class CertificateHealth
{
    public static string Calculate(DateTimeOffset expiry, DateTimeOffset now)
    {
        var days = (expiry - now).TotalDays;

        return days switch
        {
            <= 0 => "Expired",
            <= 7 => "Critical",
            <= 30 => "RenewalRequired",
            <= 60 => "RenewalUpcoming",
            _ => "Healthy"
        };
    }
}

public static class CalendarGenerator
{
    public static byte[] Generate(
        CertificateRecord certificate,
        string customer,
        string environment,
        string service)
    {
        var uid = $"{certificate.Id}@certificate-lifecycle-manager";
        var description =
            $"Certificate renewal required.\\n\\n" +
            $"Customer: {customer}\\n" +
            $"Environment: {environment}\\n" +
            $"Application: {service}\\n" +
            $"Certificate: {certificate.Name}\\n" +
            $"Thumbprint: {certificate.Thumbprint}\\n" +
            $"Certificate expiration: {certificate.ValidUntil:yyyy-MM-dd}\\n\\n" +
            "Generate and deploy the replacement certificate before the expiration date.";

        var calendar =
            "BEGIN:VCALENDAR\r\n" +
            "VERSION:2.0\r\n" +
            "PRODID:-//Certificate Lifecycle Manager//EN\r\n" +
            "CALSCALE:GREGORIAN\r\n" +
            "METHOD:PUBLISH\r\n" +
            "BEGIN:VEVENT\r\n" +
            $"UID:{uid}\r\n" +
            $"DTSTAMP:{DateTimeOffset.UtcNow:yyyyMMdd'T'HHmmss'Z'}\r\n" +
            $"DTSTART;VALUE=DATE:{certificate.RenewalDueAt:yyyyMMdd}\r\n" +
            $"SUMMARY:{Escape($"Certificate Renewal: {customer} - {service}")}\r\n" +
            $"DESCRIPTION:{Escape(description)}\r\n" +
            "BEGIN:VALARM\r\n" +
            "TRIGGER:-P7D\r\n" +
            "ACTION:DISPLAY\r\n" +
            "DESCRIPTION:Certificate renewal due in 7 days\r\n" +
            "END:VALARM\r\n" +
            "BEGIN:VALARM\r\n" +
            "TRIGGER:-P1D\r\n" +
            "ACTION:DISPLAY\r\n" +
            "DESCRIPTION:Certificate renewal due tomorrow\r\n" +
            "END:VALARM\r\n" +
            "END:VEVENT\r\n" +
            "END:VCALENDAR\r\n";

        return Encoding.UTF8.GetBytes(calendar);
    }

    private static string Escape(string value) =>
        value
            .Replace("\\", "\\\\")
            .Replace(";", "\\;")
            .Replace(",", "\\,")
            .Replace("\r", "")
            .Replace("\n", "\\n");
}

public interface INotificationService
{
    Task SendAsync(
        string recipient,
        string subject,
        string body,
        CancellationToken cancellationToken);
}
