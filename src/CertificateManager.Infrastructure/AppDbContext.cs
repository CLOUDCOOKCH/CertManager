using CertificateManager.Domain;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace CertificateManager.Infrastructure;
public sealed class ApplicationUser : IdentityUser { public string DisplayName { get; set; } = ""; }
public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : IdentityDbContext<ApplicationUser>(options) {
 public DbSet<Customer> Customers => Set<Customer>(); public DbSet<TargetEnvironment> Environments => Set<TargetEnvironment>(); public DbSet<ManagedService> Services => Set<ManagedService>(); public DbSet<CertificateRecord> Certificates => Set<CertificateRecord>(); public DbSet<NotificationHistory> NotificationHistory => Set<NotificationHistory>(); public DbSet<AuditLog> AuditLogs => Set<AuditLog>();
 protected override void OnModelCreating(ModelBuilder b) { base.OnModelCreating(b); b.Entity<Customer>().HasIndex(x=>x.Name); b.Entity<TargetEnvironment>().HasIndex(x=>x.CustomerId); b.Entity<ManagedService>().HasIndex(x=>x.EnvironmentId); b.Entity<CertificateRecord>().HasIndex(x=>x.ServiceId); b.Entity<CertificateRecord>().HasIndex(x=>x.ValidUntil); b.Entity<CertificateRecord>().HasIndex(x=>x.PrimaryOwnerEmail); b.Entity<CertificateRecord>().HasIndex(x=>x.Status); b.Entity<CertificateRecord>().HasIndex(x=>x.Thumbprint).IsUnique(); b.Entity<NotificationHistory>().HasIndex(x=>new{x.CertificateId,x.DaysBeforeExpiration,x.Recipient}).IsUnique(); b.Entity<AuditLog>().Property(x=>x.Metadata).HasColumnType("jsonb"); }
}
public static class Roles { public const string Reader="Reader"; public const string Operator="CertificateOperator"; public const string Administrator="Administrator"; }
