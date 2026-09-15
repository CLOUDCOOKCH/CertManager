using CertificateManager.Domain;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace CertificateManager.Infrastructure;

public sealed class ApplicationUser : IdentityUser
{
    public string DisplayName { get; set; } = "";
}

public sealed class AppDbContext(DbContextOptions<AppDbContext> options)
    : IdentityDbContext<ApplicationUser>(options)
{
    public DbSet<MailProviderSettings> MailProviderSettings => Set<MailProviderSettings>();
    public DbSet<NotificationSettings> NotificationSettings => Set<NotificationSettings>();
    public DbSet<Customer> Customers => Set<Customer>();
    public DbSet<TargetEnvironment> Environments => Set<TargetEnvironment>();
    public DbSet<ManagedService> Services => Set<ManagedService>();
    public DbSet<CertificateRecord> Certificates => Set<CertificateRecord>();
    public DbSet<NotificationHistory> NotificationHistory => Set<NotificationHistory>();
    public DbSet<AuditLog> AuditLogs => Set<AuditLog>();

    public override int SaveChanges(bool acceptAllChangesOnSuccess)
    {
        TouchEntities();
        return base.SaveChanges(acceptAllChangesOnSuccess);
    }

    public override Task<int> SaveChangesAsync(
        bool acceptAllChangesOnSuccess,
        CancellationToken cancellationToken = default)
    {
        TouchEntities();
        return base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken);
    }

    private void TouchEntities()
    {
        var now = DateTimeOffset.UtcNow;

        foreach (var entry in ChangeTracker.Entries<Entity>()
                     .Where(entry => entry.State is EntityState.Added or EntityState.Modified))
        {
            entry.Entity.UpdatedAt = now;

            if (entry.State == EntityState.Added)
            {
                entry.Entity.CreatedAt = now;
            }
        }
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<Customer>().HasIndex(entity => entity.Name);
        builder.Entity<MailProviderSettings>().HasKey(entity => entity.Id);
        builder.Entity<NotificationSettings>().HasKey(entity => entity.Id);
        builder.Entity<TargetEnvironment>().HasIndex(entity => entity.CustomerId);
        builder.Entity<ManagedService>().HasIndex(entity => entity.EnvironmentId);
        builder.Entity<CertificateRecord>().HasIndex(entity => entity.ServiceId);
        builder.Entity<CertificateRecord>().HasIndex(entity => entity.ValidUntil);
        builder.Entity<CertificateRecord>().HasIndex(entity => entity.PrimaryOwnerEmail);
        builder.Entity<CertificateRecord>().HasIndex(entity => entity.Status);
        builder.Entity<CertificateRecord>().HasIndex(entity => entity.Thumbprint).IsUnique();
        builder.Entity<NotificationHistory>()
            .HasIndex(entity => new
            {
                entity.CertificateId,
                entity.DaysBeforeExpiration,
                entity.Recipient
            })
            .IsUnique();
        builder.Entity<AuditLog>().Property(entity => entity.Metadata).HasColumnType("jsonb");
    }
}

public static class Roles
{
    public const string Reader = "Reader";
    public const string Operator = "CertificateOperator";
    public const string Administrator = "Administrator";
}
