import re

def parse_bicep(bicep_code):
    """
    Reads Bicep code and extracts all resources.
    Returns a list of resources found.
    """
    
    resources = []
    
    # This pattern looks for every resource block in the Bicep code
    # Example: resource myStorage 'Microsoft.Storage/storageAccounts@2021-02-01'
    pattern = r"resource\s+(\w+)\s+'([^']+)'"
    
    # Find every match in the code
    matches = re.findall(pattern, bicep_code)
    
    for match in matches:
        resource_name = match[0]  # e.g. myStorage
        resource_type = match[1]  # e.g. Microsoft.Storage/storageAccounts@2021-02-01
        
        # Split the type and API version
        # Microsoft.Storage/storageAccounts@2021-02-01
        # becomes ['Microsoft.Storage/storageAccounts', '2021-02-01']
        parts = resource_type.split('@')
        
        resource = {
            'name': resource_name,
            'type': parts[0],        # Microsoft.Storage/storageAccounts
            'api_version': parts[1] if len(parts) > 1 else 'unknown',
            'raw': resource_type
        }
        
        resources.append(resource)
    
    return resources


def display_results(resources):
    """
    Prints the parsed resources in a clean readable format
    """
    if not resources:
        print("No resources found in this code.")
        return
    
    print(f"\n Found {len(resources)} resource(s):\n")
    print("-" * 40)
    
    for i, resource in enumerate(resources, 1):
        print(f"Resource {i}:")
        print(f"  Name:        {resource['name']}")
        print(f"  Type:        {resource['type']}")
        print(f"  API Version: {resource['api_version']}")
        print("-" * 40)


# This runs only when you run parser.py directly
# Good for testing
if __name__ == "__main__":
    
    # Sample Bicep code to test with
    test_bicep = """
    resource myStorage 'Microsoft.Storage/storageAccounts@2021-02-01' = {
      name: 'mystorageaccount'
      location: 'eastus'
      sku: {
        name: 'Standard_LRS'
      }
    }
    
    resource myVNet 'Microsoft.Network/virtualNetworks@2021-02-01' = {
      name: 'myVNet'
      location: 'eastus'
      properties: {
        addressSpace: {
          addressPrefixes: ['10.0.0.0/16']
        }
      }
    }
    
    resource myNSG 'Microsoft.Network/networkSecurityGroups@2021-02-01' = {
      name: 'myNSG'
      location: 'eastus'
    }
    """
    
    print("Parsing Bicep code...")
    resources = parse_bicep(test_bicep)
    display_results(resources)