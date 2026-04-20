resource badApp 'Microsoft.Web/sites@2021-02-01' = {
  name: 'badwebapp'
  location: 'eastus'
  properties: {
    httpsOnly: false
    siteConfig: {
      minTlsVersion: '1.0'
    }
  }
}
