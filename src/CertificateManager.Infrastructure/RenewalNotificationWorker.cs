using CertificateManager.Application;
using CertificateManager.Domain;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;

namespace CertificateManager.Infrastructure;

public sealed class NotificationOptions
{
    public const string Section = "Notifications";

    public bool Enabled { get; set; }
    public int InitialDelaySeconds { get; set; } = 30;
    public int IntervalHours { get; set; } = 24;
    public int[] Milestones { get; set; } = [60, 30, 14, 7, 1, 0];
}

public sealed class RenewalNotificationWorker(
    IServiceScopeFactory scopeFactory,
    IOptionsMonitor<NotificationOptions> options,
    ILogger<RenewalNotificationWorker> logger) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var firstRun = true;

        while (!stoppingToken.IsCancellationRequested)
        {
            var delay = firstRun
                ? TimeSpan.FromSeconds(Math.Clamp(
                    options.CurrentValue.InitialDelaySeconds,
                    5,
                    3600))
                : TimeSpan.FromHours(Math.Clamp(
                    options.CurrentValue.IntervalHours,
                    1,
                    168));

            try
            {
                await Task.Delay(delay, stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }

            firstRun = false;

            try
            {
                await ProcessRenewalsAsync(stoppingToken);
            }
            catch (OperationCanceledException) when (stoppingToken.IsCancellationRequested)
            {
                break;
            }
            catch (Exception exception)
            {
                logger.LogError(exception, "Renewal notification scan failed");
            }
        }
    }

    private async Task ProcessRenewalsAsync(CancellationToken cancellationToken)
    {
        var notificationOptions = options.CurrentValue;
        var milestones = notificationOptions.Milestones
            .Where(milestone => milestone >= 0)
            .Distinct()
            .OrderByDescending(milestone => milestone)
            .ToArray();

        if (!notificationOptions.Enabled || milestones.Length == 0)
        {
            return;
        }

        using var scope = scopeFactory.CreateScope();
        var smtp = scope.ServiceProvider
            .GetRequiredService<IOptionsMonitor<SmtpOptions>>()
            .CurrentValue;

        if (!smtp.Enabled || string.IsNullOrWhiteSpace(smtp.Host) ||
            string.IsNullOrWhiteSpace(smtp.From))
        {
            return;
        }

        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        var mail = scope.ServiceProvider.GetRequiredService<INotificationService>();
        var now = DateTimeOffset.UtcNow;
        var horizon = now.AddDays(milestones.Max());
        var certificates = await db.Certificates
            .AsNoTracking()
            .Where(certificate =>
                certificate.Status != CertificateStatus.Decommissioned &&
                certificate.Status != CertificateStatus.Superseded &&
                certificate.Status != CertificateStatus.Renewed &&
                certificate.ValidUntil <= horizon &&
                certificate.PrimaryOwnerEmail != "")
            .Include(certificate => certificate.Service)
            .ThenInclude(service => service.Environment)
            .ThenInclude(environment => environment.Customer)
            .ToListAsync(cancellationToken);

        foreach (var certificate in certificates)
        {
            var daysRemaining = (int)Math.Ceiling(
                (certificate.ValidUntil - now).TotalDays);
            var dueMilestones = milestones
                .Where(configuredMilestone => daysRemaining <= configuredMilestone)
                .OrderBy(configuredMilestone => configuredMilestone)
                .ToArray();

            if (dueMilestones.Length == 0)
            {
                continue;
            }

            var sentMilestones = await db.NotificationHistory
                .Where(history =>
                    history.CertificateId == certificate.Id &&
                    history.Recipient == certificate.PrimaryOwnerEmail)
                .Select(history => history.DaysBeforeExpiration)
                .ToListAsync(cancellationToken);
            var nextMilestone = dueMilestones
                .Where(candidate =>
                    !sentMilestones.Contains(candidate) &&
                    (sentMilestones.Count == 0 || candidate < sentMilestones.Min()))
                .OrderBy(candidate => candidate)
                .FirstOrDefault(-1);

            if (nextMilestone < 0)
            {
                continue;
            }

            var milestone = nextMilestone;

            var subject = daysRemaining <= 0
                ? $"Certificate expired: {certificate.Name}"
                : $"Certificate renewal due in {Math.Max(daysRemaining, 0)} days: {certificate.Name}";
            var body = BuildMessage(certificate, daysRemaining);

            try
            {
                await mail.SendAsync(
                    certificate.PrimaryOwnerEmail,
                    subject,
                    body,
                    cancellationToken);

                db.NotificationHistory.Add(new NotificationHistory
                {
                    CertificateId = certificate.Id,
                    NotificationType = "Renewal",
                    Recipient = certificate.PrimaryOwnerEmail,
                    SentAt = DateTimeOffset.UtcNow,
                    DaysBeforeExpiration = milestone,
                    Success = true
                });
                await db.SaveChangesAsync(cancellationToken);
            }
            catch (Exception exception)
            {
                logger.LogWarning(
                    exception,
                    "Could not send renewal notification for certificate {CertificateId}",
                    certificate.Id);
            }
        }
    }

    private static string BuildMessage(
        CertificateRecord certificate,
        int daysRemaining) =>
        $"Certificate lifecycle notification\n\n" +
        $"Certificate: {certificate.Name}\n" +
        $"Customer: {certificate.Service.Environment.Customer.Name}\n" +
        $"Service: {certificate.Service.Name}\n" +
        $"Subject: {certificate.Subject}\n" +
        $"Thumbprint: {certificate.Thumbprint}\n" +
        $"Expires: {certificate.ValidUntil:u}\n" +
        $"Days remaining: {daysRemaining}\n\n" +
        "Generate and deploy a replacement certificate before expiration.";
}
