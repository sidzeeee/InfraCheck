resource badKeyVault 'Microsoft.KeyVault/vaults@2021-06-01-preview' = {
  name: 'badkeyvault'
  location: 'eastus'
  properties: {
    sku: { family: 'A', name: 'standard' }
    tenantId: subscription().tenantId
    enableSoftDelete: true
  }
}
