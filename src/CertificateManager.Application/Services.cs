using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using CertificateManager.Domain;

namespace CertificateManager.Application;
public record GenerateCertificateRequest(Guid ServiceId, string Name, string CommonName, int ValidityDays, string PrimaryOwnerEmail, int RenewalReminderDays = 30, int KeySize = 3072, string HashAlgorithm = "SHA256", string? Password = null, Guid? PreviousCertificateId = null, string? Notes = null);
public sealed record GeneratedCertificate(CertificateRecord Metadata, byte[] Pfx, byte[] Cer, byte[] Calendar, byte[] Package, string Password);
public interface ICertificateGenerator { GeneratedCertificate Generate(GenerateCertificateRequest request, string userId, string customer, string environment, string service, string? clientId); }
public sealed class CertificateGenerator : ICertificateGenerator {
 public GeneratedCertificate Generate(GenerateCertificateRequest r, string userId, string customer, string environment, string service, string? clientId) {
  if (r.KeySize is not (2048 or 3072 or 4096)) throw new ArgumentOutOfRangeException(nameof(r.KeySize));
  if (r.ValidityDays is < 1 or > 3650) throw new ArgumentOutOfRangeException(nameof(r.ValidityDays));
  var hash = r.HashAlgorithm.ToUpperInvariant() switch { "SHA256" => HashAlgorithmName.SHA256, "SHA384" => HashAlgorithmName.SHA384, "SHA512" => HashAlgorithmName.SHA512, _ => throw new ArgumentException("Unsupported hash algorithm") };
  using var rsa = RSA.Create(r.KeySize);
  var subject = new X500DistinguishedName($"CN={EscapeDn(r.CommonName)}");
  var request = new CertificateRequest(subject, rsa, hash, RSASignaturePadding.Pkcs1);
  request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, true));
  request.CertificateExtensions.Add(new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, true));
  var eku = new OidCollection { new("1.3.6.1.5.5.7.3.2", "Client Authentication") };
  request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(eku, true));
  request.CertificateExtensions.Add(new X509SubjectKeyIdentifierExtension(request.PublicKey, false));
  var from = DateTimeOffset.UtcNow.AddMinutes(-5); var until = from.AddDays(r.ValidityDays);
  Span<byte> serial = stackalloc byte[16]; RandomNumberGenerator.Fill(serial); serial[0] &= 0x7f; if (serial[0] == 0) serial[0] = 1;
  using var cert = request.Create(subject, X509SignatureGenerator.CreateForRSA(rsa, RSASignaturePadding.Pkcs1), from, until, serial);
  using var withKey = cert.CopyWithPrivateKey(rsa);
  var password = string.IsNullOrEmpty(r.Password) ? PasswordGenerator.Generate() : r.Password;
  var pfx = withKey.Export(X509ContentType.Pfx, password); var cer = cert.Export(X509ContentType.Cert);
  var metadata = new CertificateRecord { ServiceId=r.ServiceId, Name=r.Name, Subject=cert.Subject, Issuer=cert.Issuer, Thumbprint=cert.Thumbprint, SerialNumber=cert.SerialNumber, KeySize=r.KeySize, HashAlgorithm=hash.Name!, ValidFrom=from, ValidUntil=until, RenewalDueAt=until.AddDays(-r.RenewalReminderDays), CreatedByUserId=userId, PrimaryOwnerEmail=r.PrimaryOwnerEmail, PreviousCertificateId=r.PreviousCertificateId, Notes=r.Notes };
  var calendar = CalendarGenerator.Generate(metadata, customer, environment, service);
  var package = CreatePackage(r.Name, pfx, cer, calendar, Info(metadata, customer, environment, service, clientId));
  return new(metadata, pfx, cer, calendar, package, password);
 }
 static string EscapeDn(string value) => value.Replace("\\", "\\\\").Replace(",", "\\,").Replace("+", "\\+").Replace("\"", "\\\"");
 static byte[] CreatePackage(string name, byte[] pfx, byte[] cer, byte[] ics, string info) { using var output=new MemoryStream(); using (var zip=new ZipArchive(output,ZipArchiveMode.Create,true)) { Add(zip,$"{Safe(name)}.pfx",pfx); Add(zip,$"{Safe(name)}.cer",cer); Add(zip,"renewal-reminder.ics",ics); Add(zip,"certificate-information.txt",Encoding.UTF8.GetBytes(info)); } return output.ToArray(); }
 static void Add(ZipArchive z,string n,byte[] b) { var e=z.CreateEntry(n,CompressionLevel.Optimal); using var s=e.Open(); s.Write(b); }
 static string Safe(string n) => string.Concat(n.Select(c => char.IsLetterOrDigit(c)||c is '-' or '_' ? c : '-')).Trim('-');
 static string Info(CertificateRecord c,string customer,string env,string service,string? clientId) => $"Certificate Lifecycle Manager\n\nCustomer:\n{customer}\n\nEnvironment:\n{env}\n\nService / Application:\n{service}\n\nApplication Client ID:\n{clientId ?? "Not specified"}\n\nCertificate:\n{c.Name}\n\nSubject:\n{c.Subject}\n\nThumbprint:\n{c.Thumbprint}\n\nSerial Number:\n{c.SerialNumber}\n\nIssued:\n{c.ValidFrom:u}\n\nExpires:\n{c.ValidUntil:u}\n\nRenewal Due:\n{c.RenewalDueAt:u}\n";
}
public static class PasswordGenerator { const string Alphabet="ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789!@$%*?"; public static string Generate(int length=24) { if(length<16) throw new ArgumentOutOfRangeException(nameof(length)); return string.Create(length,0,(span,_)=>{ for(var i=0;i<span.Length;i++) span[i]=Alphabet[RandomNumberGenerator.GetInt32(Alphabet.Length)]; }); } }
public static class CertificateHealth { public static string Calculate(DateTimeOffset expiry, DateTimeOffset now) { var days=(expiry-now).TotalDays; return days<=0?"Expired":days<=7?"Critical":days<=30?"RenewalRequired":days<=60?"RenewalUpcoming":"Healthy"; } }
public static class CalendarGenerator {
 public static byte[] Generate(CertificateRecord c,string customer,string environment,string service) { var uid=$"{c.Id}@certificate-lifecycle-manager"; var description=$"Certificate renewal required.\\n\\nCustomer: {customer}\\nEnvironment: {environment}\\nApplication: {service}\\nCertificate: {c.Name}\\nThumbprint: {c.Thumbprint}\\nCertificate expiration: {c.ValidUntil:yyyy-MM-dd}\\n\\nGenerate and deploy the replacement certificate before the expiration date."; var s=$"BEGIN:VCALENDAR\r\nVERSION:2.0\r\nPRODID:-//Certificate Lifecycle Manager//EN\r\nCALSCALE:GREGORIAN\r\nMETHOD:PUBLISH\r\nBEGIN:VEVENT\r\nUID:{uid}\r\nDTSTAMP:{DateTimeOffset.UtcNow:yyyyMMdd'T'HHmmss'Z'}\r\nDTSTART;VALUE=DATE:{c.RenewalDueAt:yyyyMMdd}\r\nSUMMARY:{Escape($"Certificate Renewal: {customer} - {service}")}\r\nDESCRIPTION:{Escape(description)}\r\nBEGIN:VALARM\r\nTRIGGER:-P7D\r\nACTION:DISPLAY\r\nDESCRIPTION:Certificate renewal due in 7 days\r\nEND:VALARM\r\nBEGIN:VALARM\r\nTRIGGER:-P1D\r\nACTION:DISPLAY\r\nDESCRIPTION:Certificate renewal due tomorrow\r\nEND:VALARM\r\nEND:VEVENT\r\nEND:VCALENDAR\r\n"; return Encoding.UTF8.GetBytes(s); }
 static string Escape(string s)=>s.Replace("\\","\\\\").Replace(";","\\;").Replace(",","\\,").Replace("\r","").Replace("\n","\\n");
}
public interface INotificationService { Task SendAsync(string recipient,string subject,string body,CancellationToken cancellationToken); }
