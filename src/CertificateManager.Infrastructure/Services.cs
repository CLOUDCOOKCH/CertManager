using CertificateManager.Application;
using MailKit.Net.Smtp;
using Microsoft.Extensions.Options;
using MimeKit;
namespace CertificateManager.Infrastructure;
public sealed class SmtpOptions { public const string Section="Smtp"; public bool Enabled {get;set;} public string Host {get;set;}=""; public int Port {get;set;}=587; public string Username {get;set;}=""; public string Password {get;set;}=""; public string From {get;set;}=""; }
public sealed class SmtpNotificationService(IOptions<SmtpOptions> options) : INotificationService { public async Task SendAsync(string recipient,string subject,string body,CancellationToken ct) { var o=options.Value; if(!o.Enabled) return; var message=new MimeMessage(); message.From.Add(MailboxAddress.Parse(o.From)); message.To.Add(MailboxAddress.Parse(recipient)); message.Subject=subject; message.Body=new TextPart("plain"){Text=body}; using var smtp=new SmtpClient(); await smtp.ConnectAsync(o.Host,o.Port,MailKit.Security.SecureSocketOptions.StartTls,ct); if(!string.IsNullOrEmpty(o.Username)) await smtp.AuthenticateAsync(o.Username,o.Password,ct); await smtp.SendAsync(message,ct); await smtp.DisconnectAsync(true,ct); } }
