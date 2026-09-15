// Certificate Manager Azure infrastructure.
// Production uses private PostgreSQL networking; dev/test retain public access for bootstrap convenience.

@description('Deployment environment. Controls sizing, availability, and database network exposure.')
@allowed(['dev', 'test', 'prod'])
param environmentName string

@description('Azure region for all regional resources.')
param location string = resourceGroup().location

@description('PostgreSQL administrator login used to create the server.')
param postgresAdminLogin string

@secure()
@description('PostgreSQL bootstrap administrator password. Stored in Key Vault through the connection-string secret.')
param postgresAdminPassword string

@secure()
@description('Initial local administrator password. The application rejects missing/default values in production.')
param seedAdminPassword string

@description('Immutable container tag, normally the Git commit SHA supplied by the deployment workflow.')
param imageTag string = 'latest'

@description('Prefix used for generated Azure resource names.')
param prefix string = 'certmanager'

var suffix = uniqueString(resourceGroup().id, environmentName)
var base = '${prefix}-${environmentName}'

// Network topology: PostgreSQL and App Service use separate delegated subnets.
resource network 'Microsoft.Network/virtualNetworks@2024-01-01' = {
  name: '${base}-vnet'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: ['10.20.0.0/16']
    }
  }
}

resource databaseSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-01-01' = {
  parent: network
  name: 'database'
  properties: {
    addressPrefix: '10.20.1.0/24'
    delegations: [
      {
        name: 'postgres-flexible-server'
        properties: {
          serviceName: 'Microsoft.DBforPostgreSQL/flexibleServers'
        }
      }
    ]
    privateEndpointNetworkPolicies: 'Disabled'
  }
}

resource applicationSubnet 'Microsoft.Network/virtualNetworks/subnets@2024-01-01' = {
  parent: network
  name: 'application'
  properties: {
    addressPrefix: '10.20.2.0/24'
    delegations: [
      {
        name: 'app-service'
        properties: {
          serviceName: 'Microsoft.Web/serverFarms'
        }
      }
    ]
  }
}

resource privateDns 'Microsoft.Network/privateDnsZones@2020-06-01' = {
  name: 'privatelink.postgres.database.azure.com'
  location: 'global'
}

resource privateDnsLink 'Microsoft.Network/privateDnsZones/virtualNetworkLinks@2020-06-01' = {
  parent: privateDns
  name: '${base}-database-link'
  location: 'global'
  properties: {
    registrationEnabled: false
    virtualNetwork: {
      id: network.id
    }
  }
}

// Image registry and compute plan. Production uses a larger always-on plan.
resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: take(replace('${base}${suffix}', '-', ''), 50)
  location: location
  sku: {
    name: 'Basic'
  }
  properties: {
    adminUserEnabled: false
  }
}

resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {
  name: '${base}-plan'
  location: location
  sku: {
    name: environmentName == 'prod' ? 'P1v3' : 'B1'
  }
  kind: 'linux'
  properties: {
    reserved: true
  }
}

// Centralized logs and traces. The connection string is passed to App Service.
resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${base}-logs'
  location: location
  properties: {
    retentionInDays: 30
  }
}

resource insights 'Microsoft.Insights/components@2020-02-02' = {
  name: '${base}-insights'
  location: location
  kind: 'web'
  properties: {
    Application_Type: 'web'
    WorkspaceResourceId: logs.id
  }
}

// Key Vault stores the database connection string. Soft delete protects accidental removal.
resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: take('${base}-${suffix}', 24)
  location: location
  properties: {
    tenantId: subscription().tenantId
    enableRbacAuthorization: true
    enableSoftDelete: true
    softDeleteRetentionInDays: 90
    sku: {
      family: 'A'
      name: 'standard'
    }
    accessPolicies: []
  }
}

// Production is VNet-injected and has no public endpoint. Dev/test use a public endpoint.
resource postgres 'Microsoft.DBforPostgreSQL/flexibleServers@2023-12-01-preview' = {
  name: '${base}-pg-${suffix}'
  location: location
  sku: {
    name: environmentName == 'prod' ? 'Standard_D2ds_v5' : 'Standard_B1ms'
    tier: environmentName == 'prod' ? 'GeneralPurpose' : 'Burstable'
  }
  properties: {
    administratorLogin: postgresAdminLogin
    administratorLoginPassword: postgresAdminPassword
    version: '16'
    storage: {
      storageSizeGB: 32
    }
    backup: {
      backupRetentionDays: environmentName == 'prod' ? 14 : 7
      geoRedundantBackup: 'Disabled'
    }
    highAvailability: {
      mode: 'Disabled'
    }
    network: environmentName == 'prod' ? {
      publicNetworkAccess: 'Disabled'
      delegatedSubnetResourceId: databaseSubnet.id
      privateDnsZoneArmResourceId: privateDns.id
    } : {
      publicNetworkAccess: 'Enabled'
    }
  }
  dependsOn: [privateDnsLink]
}

resource database 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2023-12-01-preview' = {
  parent: postgres
  name: 'certmanager'
  properties: {
    charset: 'UTF8'
    collation: 'en_US.utf8'
  }
}

// Never created in production. This broad Azure-services rule is only a dev/test bootstrap aid.
resource postgresFirewall 'Microsoft.DBforPostgreSQL/flexibleServers/firewallRules@2023-12-01-preview' = if (environmentName != 'prod') {
  parent: postgres
  name: 'AllowAzureServices'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '0.0.0.0'
  }
}

resource dbConnectionSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: vault
  name: 'DatabaseConnectionString'
  properties: {
    value: 'Host=${postgres.properties.fullyQualifiedDomainName};Port=5432;Database=${database.name};Username=${postgresAdminLogin};Password=${postgresAdminPassword};SSL Mode=VerifyFull;Trust Server Certificate=false'
  }
}

// Single production container serves the React assets, API, and notification worker.
resource web 'Microsoft.Web/sites@2023-12-01' = {
  name: '${base}-web-${suffix}'
  location: location
  kind: 'app,linux,container'
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    serverFarmId: plan.id
    httpsOnly: true
    siteConfig: {
      linuxFxVersion: 'DOCKER|${acr.properties.loginServer}/certmanager:${imageTag}'
      alwaysOn: environmentName == 'prod'
      ftpsState: 'Disabled'
      minTlsVersion: '1.2'
      vnetRouteAllEnabled: true
      healthCheckPath: '/api/health'
      appSettings: [
        { name: 'WEBSITES_PORT', value: '8080' }
        { name: 'WEBSITES_ENABLE_APP_SERVICE_STORAGE', value: 'true' }
        { name: 'ASPNETCORE_ENVIRONMENT', value: 'Production' }
        { name: 'AllowedHosts', value: '${base}-web-${suffix}.azurewebsites.net' }
        { name: 'DataProtection__KeysPath', value: '/home/data-protection-keys' }
        { name: 'ForwardedHeaders__TrustAll', value: 'true' }
        { name: 'SEED_ADMIN_PASSWORD', value: seedAdminPassword }
        { name: 'SEED_ADMIN_RESET_PASSWORD', value: 'false' }
        { name: 'APPLICATIONINSIGHTS_CONNECTION_STRING', value: insights.properties.ConnectionString }
        { name: 'KeyVault__Uri', value: vault.properties.vaultUri }
        { name: 'ConnectionStrings__Database', value: '@Microsoft.KeyVault(SecretUri=${dbConnectionSecret.properties.secretUriWithVersion})' }
      ]
    }
  }
}

resource webNetwork 'Microsoft.Web/sites/networkConfig@2023-12-01' = {
  parent: web
  name: 'virtualNetwork'
  properties: {
    subnetResourceId: applicationSubnet.id
    swiftSupported: true
  }
}

// Managed identity permissions: image pull and read-only secret retrieval.
resource acrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(acr.id, web.id, 'pull')
  scope: acr
  properties: {
    principalId: web.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '7f951dda-4ed3-4680-a7ca-43fe172d538d')
  }
}

resource kvReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(vault.id, web.id, 'secrets')
  scope: vault
  properties: {
    principalId: web.identity.principalId
    principalType: 'ServicePrincipal'
    roleDefinitionId: subscriptionResourceId('Microsoft.Authorization/roleDefinitions', '4633458b-17de-408a-b874-0445c86b69e6')
  }
}

output acrName string = acr.name
output webAppName string = web.name
output postgresHost string = postgres.properties.fullyQualifiedDomainName
output keyVaultName string = vault.name
output virtualNetworkName string = network.name
