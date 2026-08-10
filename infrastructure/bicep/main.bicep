@allowed(['dev','test','prod']) param environmentName string
param location string = resourceGroup().location
param postgresAdminLogin string
@secure() param postgresAdminPassword string
param imageTag string = 'latest'
param prefix string = 'certmanager'
var suffix = uniqueString(resourceGroup().id, environmentName)
var base = '${prefix}-${environmentName}'
resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = { name: take(replace('${base}${suffix}','-',''),50) location: location sku: {name:'Basic'} properties:{adminUserEnabled:false} }
resource plan 'Microsoft.Web/serverfarms@2023-12-01' = {name:'${base}-plan' location:location sku:{name:environmentName=='prod'?'P1v3':'B1'} kind:'linux' properties:{reserved:true}}
resource logs 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {name:'${base}-logs' location:location properties:{retentionInDays:30}}
resource insights 'Microsoft.Insights/components@2020-02-02' = {name:'${base}-insights' location:location kind:'web' properties:{Application_Type:'web' WorkspaceResourceId:logs.id}}
resource vault 'Microsoft.KeyVault/vaults@2023-07-01' = {name:take('${base}-${suffix}',24) location:location properties:{tenantId:subscription().tenantId enableRbacAuthorization:true enableSoftDelete:true softDeleteRetentionInDays:90 sku:{family:'A' name:'standard'} accessPolicies:[]}}
resource postgres 'Microsoft.DBforPostgreSQL/flexibleServers@2023-12-01-preview' = {name:'${base}-pg-${suffix}' location:location sku:{name:environmentName=='prod'?'Standard_D2ds_v5':'Standard_B1ms' tier:environmentName=='prod'?'GeneralPurpose':'Burstable'} properties:{administratorLogin:postgresAdminLogin administratorLoginPassword:postgresAdminPassword version:'16' storage:{storageSizeGB:32} backup:{backupRetentionDays:environmentName=='prod'?14:7 geoRedundantBackup:'Disabled'} highAvailability:{mode:'Disabled'} network:{publicNetworkAccess:'Enabled'}}}
resource database 'Microsoft.DBforPostgreSQL/flexibleServers/databases@2023-12-01-preview' = {parent:postgres name:'certmanager' properties:{charset:'UTF8' collation:'en_US.utf8'}}
resource web 'Microsoft.Web/sites@2023-12-01' = {name:'${base}-web-${suffix}' location:location kind:'app,linux,container' identity:{type:'SystemAssigned'} properties:{serverFarmId:plan.id httpsOnly:true siteConfig:{linuxFxVersion:'DOCKER|${acr.properties.loginServer}/certmanager:${imageTag}' alwaysOn:environmentName=='prod' ftpsState:'Disabled' minTlsVersion:'1.2' healthCheckPath:'/api/antiforgery' appSettings:[{name:'WEBSITES_PORT',value:'8080'},{name:'APPLICATIONINSIGHTS_CONNECTION_STRING',value:insights.properties.ConnectionString},{name:'KeyVault__Uri',value:vault.properties.vaultUri}]}}}
resource acrPull 'Microsoft.Authorization/roleAssignments@2022-04-01' = {name:guid(acr.id,web.id,'pull') scope:acr properties:{principalId:web.identity.principalId principalType:'ServicePrincipal' roleDefinitionId:subscriptionResourceId('Microsoft.Authorization/roleDefinitions','7f951dda-4ed3-4680-a7ca-43fe172d538d')}}
resource kvReader 'Microsoft.Authorization/roleAssignments@2022-04-01' = {name:guid(vault.id,web.id,'secrets') scope:vault properties:{principalId:web.identity.principalId principalType:'ServicePrincipal' roleDefinitionId:subscriptionResourceId('Microsoft.Authorization/roleDefinitions','4633458b-17de-408a-b874-0445c86b69e6')}}
output acrName string = acr.name
output webAppName string = web.name
output postgresHost string = postgres.properties.fullyQualifiedDomainName
output keyVaultName string = vault.name
