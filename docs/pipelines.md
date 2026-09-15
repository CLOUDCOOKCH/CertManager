# CI and deployment pipelines

## CI workflow

File: `.github/workflows/ci.yml`

CI runs for pull requests and pushes to `main` with read-only repository permissions. Its job is a release-candidate verification sequence:

1. Check out the exact commit.
2. Install .NET 8 and Node 20.
3. Install frontend dependencies.
4. Run ESLint and the production frontend build.
5. Restore, compile, and test the .NET solution in Release mode.
6. Restore the pinned `dotnet-ef` tool and generate an idempotent migration script.
7. Build the final Linux container image.

Any failure blocks the job. Protect `main` and require this workflow before merge.

The migration-script step does not alter a database. It proves that EF discovers the context and migrations and can render deployment SQL. The container step does not publish an image.

## Azure deployment workflow

File: `.github/workflows/deploy.yml`

Deployment is intentionally manual through `workflow_dispatch`. The operator selects `dev`, `test`, or `prod`. The selected GitHub Environment supplies its variables, secrets, protection rules, and required reviewers.

Deployments use a per-environment concurrency group and do not cancel an active rollout. This prevents two schema/infrastructure/image changes from racing in the same environment.

The workflow performs:

1. The same frontend and backend verification used by CI.
2. Idempotent migration-script generation.
3. Azure login through GitHub OIDC—no stored Azure client secret.
4. Bicep compilation to catch template/type errors.
5. Resource-group creation and idempotent Bicep deployment.
6. Image build and push using the Git commit SHA as an immutable tag.
7. App Service image activation.

## Required GitHub configuration

Environment variables:

| Name | Purpose |
| --- | --- |
| `AZURE_CLIENT_ID` | Federated deployment identity client ID |
| `AZURE_TENANT_ID` | Entra tenant containing that identity |
| `AZURE_SUBSCRIPTION_ID` | Target Azure subscription |
| `AZURE_RESOURCE_GROUP` | Environment-specific resource group |
| `AZURE_LOCATION` | Resource-group region |
| `AZURE_ACR_NAME` | Registry created or managed for this environment |
| `AZURE_WEBAPP_NAME` | App Service receiving the immutable image |
| `POSTGRES_ADMIN_LOGIN` | PostgreSQL bootstrap administrator name |

Environment secrets:

| Name | Purpose |
| --- | --- |
| `POSTGRES_ADMIN_PASSWORD` | PostgreSQL bootstrap password passed as a secure Bicep parameter |
| `SEED_ADMIN_PASSWORD` | Initial local administrator password; must be non-default |

The OIDC identity needs enough scope to deploy resources, create role assignments, push to ACR, and update the target App Service. Avoid subscription-wide Owner unless there is no narrower reviewed alternative.

## Production environment controls

Configure the GitHub `prod` Environment with:

- Required reviewers
- No unreviewed branch deployment
- Environment-specific secrets rather than repository-wide secrets
- A deployment identity restricted to the production resource group
- Branch protection requiring CI

Rotate the bootstrap secrets after provisioning. Keep `SEED_ADMIN_RESET_PASSWORD=false` except during an explicitly approved recovery.

## Rollout verification

After activation:

1. Confirm App Service reports the expected commit-tagged image.
2. Confirm `/api/health` returns HTTP 200 and database status `ok`.
3. Sign in using an approved account.
4. Verify dashboard counts and a read-only certificate query.
5. Confirm migration history contains the expected latest migration.
6. Check Application Insights for startup, migration, authentication, or SMTP errors.
7. If notifications are enabled, verify the worker status without sending certificate secrets.

## Rollback

Application rollback means reactivating a previously verified immutable image tag. Do not roll application code backward across an incompatible database migration.

For schema changes, every migration pull request must document whether downgrade is supported. Prefer forward fixes for additive migrations. For destructive migrations, take and verify a backup, define the rollback window, and stage data removal separately from code removal.

Infrastructure rollback must account for immutable Azure properties. PostgreSQL public/private network mode cannot be safely treated as an ordinary in-place toggle; migrate to a replacement server when changing that boundary.

## Common failures

| Failure | Likely cause | Response |
| --- | --- | --- |
| Bicep validation fails | Invalid API property or resource dependency | Fix the template; do not bypass validation |
| App starts unhealthy | Key Vault propagation, database DNS/network, or migration failure | Inspect App Service and PostgreSQL logs; keep the prior image available |
| Host rejected | `AllowedHosts` does not include the requested custom domain | Add the reviewed production hostname |
| Cookie login loops | HTTPS/forwarded-header or Data Protection persistence problem | Verify proxy settings and `/home/data-protection-keys` persistence |
| Initial migration reports existing tables | Database was created by the legacy `EnsureCreated` path | Stop, restore/backup, and perform the documented baseline procedure |

