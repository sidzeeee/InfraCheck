resource badApp 'Microsoft.Web/sites@2021-02-01' = {
  name: 'badwebapp'
  location: 'eastus'
  properties: {
    httpsOnly: true
    siteConfig: {
      alwaysOn: true
    }
  }
}
