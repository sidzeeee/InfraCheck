resource goodVM 'Microsoft.Compute/virtualMachines@2021-03-01' = {
  name: 'goodVM'
  location: 'eastus'
  tags: { environment: 'prod', owner: 'team' }
  identity: { type: 'SystemAssigned' }
  properties: {
    hardwareProfile: { vmSize: 'Standard_D2s_v3' }
    storageProfile: {
      osDisk: {
        createOption: 'FromImage'
        managedDisk: { storageAccountType: 'Premium_LRS' }
      }
    }
    securityProfile: { encryptionAtHost: true }
  }
}
