resource badNSG 'Microsoft.Network/networkSecurityGroups@2021-02-01' = {
  name: 'badNSG'
  location: 'eastus'
  properties: {
    securityRules: [
      {
        name: 'allow-winrm'
        properties: {
          priority: 100
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: '0.0.0.0/0'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '5985'
        }
      }
    ]
  }
}
