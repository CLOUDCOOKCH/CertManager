# Azure deployment

The Bicep template provisions ACR, Linux App Service, PostgreSQL Flexible Server, Key Vault, Log Analytics, Application Insights, and a system-assigned managed identity. The identity receives ACR pull and Key Vault secrets-user roles. Add PostgreSQL firewall/private networking and write the database/SMTP secrets to Key Vault before production use.

GitHub Actions authenticates with OIDC. Create an Entra application or user-assigned identity with a federated credential restricted to the repository/environment and grant only the target resource group's deployment permissions plus role-assignment rights where required.

Configure GitHub environment variables: `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_SUBSCRIPTION_ID`, `AZURE_RESOURCE_GROUP`, `AZURE_LOCATION`, `AZURE_ACR_NAME`, `AZURE_WEBAPP_NAME`, and `POSTGRES_ADMIN_LOGIN`. Configure `POSTGRES_ADMIN_PASSWORD` as an environment secret. Prefer moving that bootstrap password to a protected deployment secret store after provisioning.
