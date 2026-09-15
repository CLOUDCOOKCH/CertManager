# Microsoft sign-in setup

Certificate Lifecycle Manager can optionally authenticate operators with Microsoft Entra ID (the Microsoft identity platform). Local Identity/password sign-in remains available. Microsoft users are provisioned as `Reader` users on their first sign-in; an administrator can promote them to `CertificateOperator` or `Administrator` in the Admin portal.

## 1. Create the app registration

1. Open **Microsoft Entra admin center** → **Identity** → **Applications** → **App registrations** → **New registration**.
2. Choose a name such as `Certificate Lifecycle Manager`.
3. For an internal company deployment, choose **Accounts in this organizational directory only** (single tenant). Choose a multi-tenant option only after reviewing cross-tenant access requirements.
4. Under **Redirect URI**, select **Web** and add the exact public callback URL:
   - Docker on your workstation: `http://localhost:8080/signin-microsoft`
   - Azure App Service: `https://<your-app-name>.azurewebsites.net/signin-microsoft`
5. Select **Register**, then copy **Application (client) ID** and **Directory (tenant) ID** from the Overview page.
6. Open **Certificates & secrets** → **New client secret**, choose an expiration, and copy the secret value immediately. Do not commit it to source control. For production, prefer a certificate or workload identity/federated credential and store secrets in Key Vault.

Microsoft's registration and redirect-URI guidance is available in the [ASP.NET Core Microsoft Entra quickstart](https://learn.microsoft.com/en-us/entra/msidweb/getting-started/quickstart-webapp) and [Microsoft identity platform web-app configuration guide](https://learn.microsoft.com/en-us/entra/identity-platform/scenario-web-app-sign-user-app-configuration).

## 2. Configure the application

Set these environment variables for the web container:

```text
Authentication__Microsoft__Enabled=true
Authentication__Microsoft__TenantId=<directory-tenant-id>
Authentication__Microsoft__ClientId=<application-client-id>
Authentication__Microsoft__ClientSecret=<secret-value>
Authentication__Microsoft__CallbackPath=/signin-microsoft
```

For Docker Compose, put the values in a local `.env` file (which must never be committed) and start the stack:

```text
MICROSOFT_AUTH_ENABLED=true
MICROSOFT_TENANT_ID=<directory-tenant-id>
MICROSOFT_CLIENT_ID=<application-client-id>
MICROSOFT_CLIENT_SECRET=<secret-value>
MICROSOFT_CALLBACK_PATH=/signin-microsoft
```

```powershell
docker compose up -d --build
```

The sign-in button appears only when all required values are configured. The callback path must match the registered redirect URI exactly, including scheme, hostname, port, and path. If TLS terminates at a reverse proxy, register the public HTTPS URL; configure forwarded headers for that trusted proxy.

## 3. Assign application access

The first Microsoft account to sign in is intentionally limited to `Reader`. An administrator must open **Admin → Users** and assign the required role. This prevents an arbitrary directory user from receiving certificate-generation or administrative permissions automatically.

If a user is locked in the local portal, Microsoft sign-in is rejected until an administrator unlocks the account. Sign-in events are written to the audit log without storing access tokens.

## Troubleshooting

- **AADSTS50011**: the redirect URI in the app registration does not exactly match the public callback URL.
- **Microsoft button is missing**: verify `Enabled`, tenant ID, client ID, and client secret are all present in the running container.
- **Sign-in succeeds but access is denied**: assign a local role in **Admin → Users**; new Microsoft accounts start as `Reader`.
- **Callback loops or reports invalid state**: preserve the Data Protection keys across restarts (`web-keys` in Compose or `/home/data-protection-keys` in App Service).
