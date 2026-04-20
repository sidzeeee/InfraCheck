resource storageAccount 'Microsoft.Storage/storageAccounts@2021-02-01' = {
  name: 'mystorage'
  location: 'eastus'
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
  }
}
