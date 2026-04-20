resource badVM 'Microsoft.Compute/virtualMachines@2021-03-01' = {
  name: 'badVM'
  location: 'eastus'
  properties: {
    hardwareProfile: { vmSize: 'Standard_D2s_v3' }
    storageProfile: {
      osDisk: {
        createOption: 'FromImage'
      }
    }
  }
}
