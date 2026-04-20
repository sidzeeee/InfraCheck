resource badVNet 'Microsoft.Network/virtualNetworks@2021-02-01' = {
  name: 'badVNet'
  location: 'eastus'
  properties: {
    addressSpace: {
      addressPrefixes: [
        '10.0.0.0/16'
      ]
    }
  }
}
