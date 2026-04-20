resource badStorage 'Microsoft.Storage/storageAccounts@2021-02-01' = {
  name: 'badstorage'
  location: 'eastus'
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
  }
}
