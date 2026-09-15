# Certificate Lifecycle Manager

A tenant-agnostic internal portal for generating self-signed service-authentication certificates, delivering their one-time artifacts to authorized operators, and tracking metadata, expiry, deployment confirmation, renewal, notifications, and audit history.

Documentation: [architecture](docs/architecture.md), [codebase reference](docs/codebase.md), [API reference](docs/api.md), [certificate lifecycle](docs/certificate-lifecycle.md), [security model](docs/security.md), [infrastructure](docs/infrastructure.md), [CI and deployment pipelines](docs/pipelines.md), [Azure deployment](docs/deployment.md), and [Microsoft sign-in](docs/microsoft-sign-in.md).

> **Security boundary:** this system never calls Microsoft Graph, Entra ID, customer tenants, app registrations, or workloads. Tenant and application IDs are metadata only. Deployment is always manual and confirmation is an operator assertion.

## Architecture

The .NET 8 solution uses clean, deliberately small layers: Domain entities; Application cryptography and lifecycle rules; Infrastructure for EF Core/PostgreSQL, Identity, and SMTP; and an ASP.NET Core API. React/TypeScript/Vite produces static assets served by the API in the single production container. See [architecture](docs/architecture.md), [security](docs/security.md), [lifecycle](docs/certificate-lifecycle.md), and [deployment](docs/deployment.md).

Operational probes are available at `GET /api/health`; they verify database connectivity and return HTTP 503 when the application is not ready. Docker and Azure App Service use this endpoint for container health monitoring. Administrators can search audit history from the global search field; API results are capped to protect the database.

Customers and services can be edited or archived from their management screens. Archiving preserves historical certificates but prevents new certificate generation until the record is restored.

Certificate inventory now distinguishes active, renewed, and superseded records; historical records remain searchable/exportable but cannot be deployed or renewed from the UI.

Administrators can retire a certificate with an optional reason. Retirement time, operator, and reason are retained as metadata and are available through `GET /api/certificates/{id}` and the recent-retirement feed at `GET /api/certificates/retired`.

Certificate generation supports SHA-256, SHA-384, and SHA-512 signature hashes plus operator notes that are retained with certificate metadata and shown in the detail view.

Services show service-principal readiness based on their Application (client) ID. The generator warns in the UI and rejects the request when client authentication is selected without that ID; duplicate active certificate names within a service are also rejected.

Signed-in operators can change their own password from the workspace header. Password changes use the Identity policy and are recorded in the audit log; administrators can still reset another user's password from the Admin portal.
The frontend also detects expired API sessions and returns the operator to the sign-in screen instead of leaving stale data actions silently failing.

Optional Microsoft Entra ID sign-in is supported alongside local accounts. See the [Microsoft sign-in setup guide](docs/microsoft-sign-in.md) for app registration, redirect URI, secret storage, and role provisioning instructions.

## Certificate and private-key lifecycle

Generation uses .NET `RSA`, `CertificateRequest`, Client Authentication EKU, and Digital Signature key usage. The key, CER, password-protected PFX, ICS, and ZIP are made in memory. The generation response displays the password once and supplies the PFX once. The server disposes cryptographic objects and persists **metadata only**—never a password, PFX, or private key. Consequently a PFX cannot be downloaded later; renew to obtain another.

## Quick start with Docker

Requirements: Docker Compose v2. Run:

```bash
SEED_ADMIN_PASSWORD='choose-a-strong-password' docker compose up --build
```

Open <http://localhost:8080> and sign in as `admin@localhost`. Without the override, local-only password `ChangeMe!123456` is used; change this before any shared deployment. `SEED_ADMIN_PASSWORD` is used when the account is first created and does not overwrite a password changed in the portal. For an intentional one-time recovery, set `SEED_ADMIN_RESET_PASSWORD=true` together with the desired password, start the stack, then remove the reset flag. PostgreSQL data persists in `postgres-data`. Stop with `docker compose down`; add `-v` only when intentionally deleting local data.

The portal is organized around customers, services, and certificates. It includes global search, health filtering, CSV export, renewal shortcuts, replacement tracking, and an Administrator area for local users, SMTP status, and API details. Renewing a certificate marks the previous record as superseded and links it to the replacement.

## Direct development

Requires .NET SDK 8, Node 20+, and PostgreSQL 16.

```bash
docker compose up postgres
dotnet restore
dotnet run --project src/CertificateManager.Api --urls http://localhost:5080
# separate terminal
cd src/CertificateManager.Web && npm install && npm run dev
```

Vite proxies `/api` to port 5080. Configuration uses ASP.NET Core's normal precedence; environment variables use double underscores, for example `ConnectionStrings__Database`. Never commit `.env` files.

## Database and migrations

The model includes indexes for expiry, owner, status, and parent foreign keys. Production applies checked-in EF Core migrations at startup before seeding; development uses `EnsureCreated` for disposable local databases. Create and review a migration before upgrading a persistent environment:

```bash
dotnet ef migrations add InitialCreate --project src/CertificateManager.Infrastructure --startup-project src/CertificateManager.Api
dotnet ef database update --project src/CertificateManager.Infrastructure --startup-project src/CertificateManager.Api
```

All application timestamps are UTC. Back up PostgreSQL with tested, encrypted, access-controlled backups and regularly rehearse point-in-time restoration. Backups contain certificate metadata and account/audit data, but never generated private keys.

## SMTP and renewal checking

Set `Smtp__Enabled=true`, `Smtp__Host`, `Smtp__Port`, `Smtp__Username`, `Smtp__Password`, and `Smtp__From` for bootstrap configuration. Administrators can also update these values in the Admin portal, preserve the password by leaving it blank, and send a test message. Portal-managed passwords are encrypted with ASP.NET Core Data Protection and the Docker Compose `web-keys` volume preserves the encryption keys. Set `Notifications__Enabled=true` to activate the hosted renewal worker; it scans every 24 hours by default and sends one deduplicated message at 60, 30, 14, 7, 1, and 0 days before expiry. Store production values in Key Vault and expose Key Vault references to App Service. The provider is behind `INotificationService`; credentials and generated passwords must never be logged or emailed. The notification history uniqueness key prevents duplicate milestones.
Notification enablement, scan interval, and milestone thresholds can also be changed from the Admin portal; those settings are persisted in PostgreSQL and applied to the worker without restarting the container.

## Build and test

```bash
dotnet restore
dotnet build -c Release
dotnet test -c Release
cd src/CertificateManager.Web
npm install
npm run lint
npm run build
docker build -t certmanager:local .
```

Unit tests cover certificate properties/exports, ZIP safety, passwords, health, and ICS alarms. CI repeats frontend lint/build, backend build/tests, and the container build for pull requests and `main`.

## Authentication and authorization

Local accounts use ASP.NET Core Identity password hashing, lockout, secure HttpOnly/SameSite cookies, and server-enforced policies:

* **Reader** — dashboard, inventory, and metadata.
* **CertificateOperator** — Reader plus generation, renewal, one-time generated downloads, and deployment confirmation.
* **Administrator** — Operator plus hierarchy/user administration, decommissioning, configuration, and audit access.

The default account is bootstrap-only. Administrators can create users, assign Reader/CertificateOperator/Administrator roles, lock or unlock accounts, and reset passwords from the Admin portal; role changes protect the last administrator and sensitive actions are audited. Establish password rotation procedures before production. HTTPS must terminate at App Service; the application sets defensive browser headers and rate limits API traffic.

## Azure and GitHub Actions

`infrastructure/bicep/main.bicep` creates environment-specific ACR, Linux App Service, PostgreSQL Flexible Server, Key Vault, Log Analytics, Application Insights, and managed identity resources. Deploy manually with:

```bash
az group create -n certmanager-dev -l westeurope
az deployment group create -g certmanager-dev -f infrastructure/bicep/main.bicep \
  -p environmentName=dev postgresAdminLogin=certadmin postgresAdminPassword='<secure-bootstrap-value>' seedAdminPassword='<secure-admin-password>'
```

Deployment Actions use Azure OIDC—not a client secret. Create a federated credential for the GitHub repository/environment. Configure environment variables `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `AZURE_RESOURCE_GROUP`, `AZURE_LOCATION`, `AZURE_ACR_NAME`, `AZURE_WEBAPP_NAME`, and `POSTGRES_ADMIN_LOGIN`; configure protected secret `POSTGRES_ADMIN_PASSWORD`. The identity needs resource-group deployment rights, ACR push, and permission to create the template's scoped role assignments. See [deployment details](docs/deployment.md).

## Production checklist

1. Replace the bootstrap administrator password; implement reviewed account provisioning and MFA through a future provider if required.
2. Use HTTPS only, secure cookies, a trusted proxy, an explicit host allowlist, and private endpoints/firewalls for PostgreSQL, ACR, and Key Vault.
3. Put database and SMTP secrets in Key Vault; grant the web identity least privilege and rotate bootstrap credentials.
4. Apply reviewed EF migrations as a controlled release step; do not rely on runtime schema ownership.
5. Configure App Service health checks, alerting, log retention, database PITR, and restore drills.
6. Verify audit retention/export, email suppression/deduplication, clock synchronization, and operator download procedures.
7. Run dependency/container scanning and penetration tests. Confirm logs contain no passwords, cookies, PFX bytes, or keys.
8. Document that decommissioning is not PKI revocation and deployment confirmation does not verify the remote workload.

## Troubleshooting

* **Database unavailable:** check `ConnectionStrings__Database`, PostgreSQL health, DNS/firewall rules, and TLS settings.
* **Cannot sign in:** confirm the bootstrap seed ran and inspect non-sensitive Identity lockout events; reset through an approved administrator process.
* **Frontend returns 404:** run `npm run build`; output must exist in `src/CertificateManager.Api/wwwroot` before publishing outside Docker.
* **Mail not sent:** verify `Smtp__Enabled`, network egress, STARTTLS support, sender policy, and notification history. Never print the SMTP password.
* **PFX unavailable:** this is intentional after initial generation. Generate a replacement; private key material is not retained.

## Non-goals

This is not a CA and implements no Graph/Entra integration, automatic upload/deployment, customer authentication, SCEP, ACME, CRL, OCSP, or revocation.
