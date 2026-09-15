# Codebase reference

## Solution layout

| Project | Responsibility | Must not do |
| --- | --- | --- |
| `CertificateManager.Domain` | Entities and lifecycle enums | Depend on EF Core, HTTP, SMTP, or UI code |
| `CertificateManager.Application` | Certificate generation, export packaging, calendar generation, lifecycle calculations, interfaces | Persist private keys or depend on infrastructure |
| `CertificateManager.Infrastructure` | EF Core/PostgreSQL, ASP.NET Identity, SMTP, persisted settings, renewal worker | Expose secret material to callers or logs |
| `CertificateManager.Api` | Composition root, authentication, authorization, validation, endpoints, startup migration/seeding | Store generated PFX/password data |
| `CertificateManager.Web` | React operator portal compiled into API static assets | Treat UI role checks as authorization |
| `CertificateManager.UnitTests` | Cryptography, export, lifecycle, health, and safety regression tests | Require production credentials or infrastructure |

## Domain model

The hierarchy is `Customer -> TargetEnvironment -> ManagedService -> CertificateRecord`.

- A customer is an organizational boundary and can be archived.
- An environment distinguishes production, development, testing, staging, and other targets.
- A managed service holds application/client and external inventory references.
- A certificate record contains public certificate and lifecycle metadata only.
- `NotificationHistory` provides renewal-message deduplication.
- `AuditLog` records actor, action, entity, outcome, and non-secret metadata.

Certificate expiry health is calculated from `ValidUntil` and the current UTC time. It is not persisted. Lifecycle status and deployment status are separate concepts: lifecycle describes whether a record is active, replaced, or retired; deployment status describes the operator-reported rollout state.

## Certificate generation boundary

`ICertificateGenerator` is implemented in the application layer. Generation creates RSA material and certificate artifacts in memory. The API returns the password-protected PFX and password once. Only metadata is written to PostgreSQL.

The following values must never be persisted or logged:

- RSA private key parameters
- PFX or ZIP bytes
- Generated PFX passwords
- SMTP passwords in plaintext
- Authentication cookies or antiforgery tokens

The CER and calendar do not contain private-key material. The ZIP is still sensitive because it contains the PFX.

## API composition and request security

[`Program.cs`](../src/CertificateManager.Api/Program.cs) is the composition root. Startup performs these operations in order:

1. Validate production-only configuration.
2. Register PostgreSQL, Identity, optional Microsoft sign-in, authorization policies, antiforgery, rate limiting, SMTP, and the renewal worker.
3. Apply forwarded headers before authentication.
4. Apply defensive response headers and production HSTS.
5. Validate antiforgery tokens for authenticated API mutations.
6. Map API and static-frontend routes.
7. Apply the production migration or initialize a development database.
8. Seed roles and the bootstrap administrator.

Authorization policies are server-enforced:

- `Read`: Reader, CertificateOperator, or Administrator
- `Operate`: CertificateOperator or Administrator
- `Admin`: Administrator only

Frontend role-based visibility is convenience only. Every sensitive endpoint must retain its matching server policy.

Production startup fails when the database is missing/development-only, `AllowedHosts` is unrestricted, or the bootstrap password is missing/default. This prevents an apparently healthy but insecure deployment.

## Persistence and migrations

`AppDbContext` contains Identity and application tables. Its model configures indexes used by inventory, expiry, ownership, status, hierarchy, thumbprint uniqueness, and notification deduplication.

Production uses `Database.MigrateAsync()` and the checked-in migrations under `CertificateManager.Infrastructure/Migrations`. Development uses `EnsureCreated` plus compatibility DDL to preserve existing disposable local volumes.

Migration workflow:

```bash
dotnet tool restore
dotnet ef migrations add MeaningfulName \
  --project src/CertificateManager.Infrastructure \
  --startup-project src/CertificateManager.Api
dotnet ef migrations script --idempotent \
  --project src/CertificateManager.Infrastructure \
  --startup-project src/CertificateManager.Api
```

Review generated SQL for data loss, long table locks, unbounded backfills, and irreversible transformations. Back up and test restoration before applying schema changes to production.

`DesignTimeAppDbContextFactory` allows EF tooling to inspect the model without starting the web application or requiring production configuration.

## Renewal worker and SMTP

`RenewalNotificationWorker` reads persisted notification settings through the options cache. It scans certificate expiry milestones and calls `INotificationService`. Successful sends are recorded with a unique certificate/milestone/recipient key. Failed sends remain eligible for retry and must log only non-sensitive diagnostic information.

SMTP passwords saved through the portal are encrypted with ASP.NET Core Data Protection. Persisting Data Protection keys is therefore required for both login continuity and SMTP credential recovery after restart.

## Frontend

`main.tsx` contains the current React shell, pages, dialogs, API client, authentication expiry handling, and one-time artifact workflow. `styles.css` supplies the base visual system; `interaction.css` contains extended dialogs, admin panels, responsive behavior, and interaction polish.

The API helper always uses cookie credentials. Mutations retrieve a fresh antiforgery token and retry once if it has expired. A 401 dispatches `auth-expired`, clears client authentication state, and returns to sign-in.

The generated-artifact dialog tracks PFX/ZIP downloads, provides copy actions, and warns before closing if private-key material has not been downloaded. This is a usability safeguard, not proof that an operator stored the artifact securely.

## Adding a feature

1. Put domain state and enums in the Domain project.
2. Put business rules or interfaces in Application.
3. Put database, mail, or external implementation details in Infrastructure.
4. Expose the behavior through a validated and authorized API endpoint.
5. Add frontend behavior without duplicating authorization assumptions.
6. Add regression tests for business rules and sensitive failure paths.
7. Add a migration for every production schema change.
8. Update the relevant document under `docs/`.

## Verification commands

```bash
dotnet restore
dotnet build --no-restore -c Release
dotnet test --no-build -c Release
dotnet tool restore
dotnet ef migrations script --idempotent -c Release \
  --project src/CertificateManager.Infrastructure \
  --startup-project src/CertificateManager.Api
cd src/CertificateManager.Web
npm install
npm run lint
npm run build
```

The container build is the final packaging check because it verifies frontend embedding, multi-stage publishing, runtime ownership, and the health command.

