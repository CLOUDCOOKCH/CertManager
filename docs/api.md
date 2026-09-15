# API reference

All routes use the `/api` prefix. Authentication uses an ASP.NET Core Identity cookie. Except for login and provider discovery, mutation requests require the `X-XSRF-TOKEN` header obtained from `GET /api/antiforgery`.

Policies used below are `Public`, `Authenticated`, `Read`, `Operate`, and `Admin`. `Read` includes all three application roles; `Operate` includes CertificateOperator and Administrator.

## Authentication and health

| Method and route | Policy | Purpose |
| --- | --- | --- |
| `GET /antiforgery` | Public | Issue a no-store antiforgery request token |
| `GET /auth/providers` | Public | Report whether Microsoft sign-in is configured |
| `GET /auth/microsoft` | Public | Start the Microsoft OpenID Connect challenge |
| `POST /auth/login` | Public, auth rate limit | Sign in a local account and audit the attempt |
| `POST /auth/logout` | Authenticated | End the current cookie session |
| `POST /auth/password` | Authenticated | Change the current local password |
| `GET /me` | Authenticated | Return current identity and roles |
| `GET /health` | Public | Verify database connectivity; returns 503 when unavailable |

## Administration

| Method and route | Policy | Purpose |
| --- | --- | --- |
| `GET /admin/users` | Admin | List local/Microsoft-linked users and roles |
| `POST /admin/users` | Admin | Create a local user |
| `POST /admin/users/{id}/lock` | Admin | Toggle account lock state |
| `PUT /admin/users/{id}/role` | Admin | Replace the assigned application role |
| `POST /admin/users/{id}/password` | Admin | Reset a local password and clear lockout |
| `GET /admin/integrations` | Admin | Return API and SMTP configuration status without secrets |
| `PUT /admin/integrations/mail` | Admin | Persist SMTP settings; encrypt a supplied password |
| `POST /admin/integrations/mail/test` | Admin | Send a non-sensitive SMTP test message |
| `GET /admin/notifications` | Admin | Return worker schedule and last successful send |
| `PUT /admin/notifications` | Admin | Persist validated renewal milestones and interval |

The API prevents self-lockout, self-removal of administrator access, and removal of the final administrator.

## Hierarchy management

| Method and route | Policy | Purpose |
| --- | --- | --- |
| `GET /customers` | Read | List customers |
| `POST /customers` | Admin | Create a customer and its default environment |
| `PUT /customers/{id}` | Admin | Update customer metadata |
| `POST /customers/{id}/status` | Admin | Archive or restore a customer |
| `GET /environments?customerId=` | Read | List environments, optionally by customer |
| `POST /environments` | Admin | Create an environment |
| `GET /services?customerId=` | Read | List services with customer and readiness metadata |
| `POST /services` | Admin | Create a service under the customer's default environment |
| `PUT /services/{id}` | Admin | Update service metadata |
| `POST /services/{id}/status` | Admin | Archive or restore a service |

Archived hierarchy records remain available for historical reporting but cannot be used for new generation.

## Certificates

| Method and route | Policy | Purpose |
| --- | --- | --- |
| `GET /certificates` | Read | Paged inventory search, health filter, and sort |
| `GET /certificates/retired` | Read | Latest 50 retired records |
| `GET /certificates/export` | Read | Server-generated CSV export with spreadsheet-injection protection |
| `POST /certificates/generate` | Operate | Generate and return one-time artifacts; persist metadata only |
| `GET /certificates/{id}` | Read | Return lifecycle and public certificate metadata |
| `POST /certificates/{id}/mark-deployed` | Operate | Record an operator deployment assertion |
| `POST /certificates/{id}/decommission` | Admin | Retire a certificate with an optional reason |
| `GET /certificates/{id}/calendar` | Read | Download a renewal calendar |
| `GET /dashboard` | Read | Return current expiry-health aggregates |
| `GET /audit` | Admin | Search recent audit history, capped at 500 entries |

`GET /certificates` accepts:

- `search`: name, thumbprint, owner, service, or customer text
- `health`: `Healthy`, `RenewalUpcoming`, `RenewalRequired`, `Critical`, or `Expired`
- `sort`: `validUntil`, `name`, `customer`, or `owner`
- `direction`: `asc` or `desc`
- `page`: one-based page number
- `pageSize`: 1–100

## Response and security conventions

- Validation failures return HTTP 400 with an `error` property.
- Missing entities return HTTP 404.
- Duplicate resources return HTTP 409 where applicable.
- Unauthenticated API requests return HTTP 401 rather than an HTML redirect.
- Authenticated but unauthorized requests return HTTP 403.
- Generated PFX/password values appear only in the successful generation response.
- API errors and audit metadata must never include passwords, cookies, PFX bytes, or private keys.

