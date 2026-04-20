resource goodNSG 'Microsoft.Network/networkSecurityGroups@2021-02-01' = {
  name: 'goodNSG'
  location: 'eastus'
  tags: { environment: 'prod', owner: 'team' }
  properties: {
    securityRules: [
      {
        name: 'allow-https'
        properties: {
          priority: 100
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: '10.0.0.0/8'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '443'
        }
      }
    ]
  }
}
