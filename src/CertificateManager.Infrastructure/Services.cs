using CertificateManager.Application;
using MailKit.Net.Smtp;
using Microsoft.Extensions.Options;
using MimeKit;

namespace CertificateManager.Infrastructure;

public sealed class MailProviderSettings
{
    public int Id { get; set; } = 1;
    public bool Enabled { get; set; }
    public string Host { get; set; } = "";
    public int Port { get; set; } = 587;
    public string Username { get; set; } = "";
    public string ProtectedPassword { get; set; } = "";
    public string From { get; set; } = "";
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class NotificationSettings
{
    public int Id { get; set; } = 1;
    public bool Enabled { get; set; }
    public int InitialDelaySeconds { get; set; } = 30;
    public int IntervalHours { get; set; } = 24;
    public string Milestones { get; set; } = "60,30,14,7,1,0";
    public DateTimeOffset UpdatedAt { get; set; } = DateTimeOffset.UtcNow;
}

public sealed class SmtpOptions
{
    public const string Section = "Smtp";

    public bool Enabled { get; set; }
    public string Host { get; set; } = "";
    public int Port { get; set; } = 587;
    public string Username { get; set; } = "";
    public string Password { get; set; } = "";
    public string From { get; set; } = "";
}

public sealed class SmtpNotificationService(IOptionsMonitor<SmtpOptions> options)
    : INotificationService
{
    public async Task SendAsync(
        string recipient,
        string subject,
        string body,
        CancellationToken cancellationToken)
    {
        var settings = options.CurrentValue;

        if (!settings.Enabled)
        {
            return;
        }

        var message = new MimeMessage();
        message.From.Add(MailboxAddress.Parse(settings.From));
        message.To.Add(MailboxAddress.Parse(recipient));
        message.Subject = subject;
        message.Body = new TextPart("plain") { Text = body };

        using var smtp = new SmtpClient();
        await smtp.ConnectAsync(
            settings.Host,
            settings.Port,
            MailKit.Security.SecureSocketOptions.StartTls,
            cancellationToken);

        if (!string.IsNullOrEmpty(settings.Username))
        {
            await smtp.AuthenticateAsync(
                settings.Username,
                settings.Password,
                cancellationToken);
        }

        await smtp.SendAsync(message, cancellationToken);
        await smtp.DisconnectAsync(true, cancellationToken);
    }
}
