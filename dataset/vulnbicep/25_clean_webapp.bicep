resource goodApp 'Microsoft.Web/sites@2021-02-01' = {
  name: 'goodwebapp'
  location: 'eastus'
  tags: { environment: 'prod', owner: 'team' }
  properties: {
    httpsOnly: true
    siteConfig: {
      minTlsVersion: '1.2'
      alwaysOn: true
    }
  }
}
