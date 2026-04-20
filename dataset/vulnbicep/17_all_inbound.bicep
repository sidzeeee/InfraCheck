resource badNSG 'Microsoft.Network/networkSecurityGroups@2021-02-01' = {
  name: 'badNSG'
  location: 'eastus'
  properties: {
    securityRules: [
      {
        name: 'allow-all'
        properties: {
          priority: 100
          protocol: '*'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
        }
      }
    ]
  }
}
