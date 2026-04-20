resource goodStorage 'Microsoft.Storage/storageAccounts@2021-02-01' = {
  name: 'goodstorage'
  location: 'eastus'
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  tags: { environment: 'prod', owner: 'team' }
  properties: {
    allowBlobPublicAccess: false
    supportsHttpsTrafficOnly: true
    networkAcls: { defaultAction: 'Deny' }
    deleteRetentionPolicy: { enabled: true, days: 7 }
  }
}
resource lock 'Microsoft.Authorization/locks@2020-05-01' = {
  name: 'storageLock'
  properties: { level: 'CanNotDelete' }
}
