resource goodKV 'Microsoft.KeyVault/vaults@2021-06-01-preview' = {
  name: 'goodkeyvault'
  location: 'eastus'
  tags: { environment: 'prod', owner: 'team' }
  properties: {
    sku: { family: 'A', name: 'standard' }
    tenantId: subscription().tenantId
    enableSoftDelete: true
    enablePurgeProtection: true
    accessPolicies: [
      {
        tenantId: subscription().tenantId
        objectId: 'replace-with-object-id'
        permissions: { secrets: [ 'get', 'list' ] }
      }
    ]
  }
}
