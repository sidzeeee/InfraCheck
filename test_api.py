# test_api.py - debug v4
import requests

BASE_URL = "https://prices.azure.com/api/retail/prices"

def try_service_names(region="eastus"):
    """
    Try different possible service names 
    for NAT Gateway
    """
    
    possible_names = [
        "Azure Firewall",
        "Virtual Network",
        "VPN Gateway",
        "Application Gateway",
        "Azure Bastion",
        "Network Watcher",
        "Azure DNS",
    ]
    
    for name in possible_names:
        params = {
            "api-version": "2023-01-01-preview",
            "$filter": f"serviceName eq '{name}' "
                       f"and armRegionName eq '{region}'"
        }
        
        response = requests.get(BASE_URL, params=params, timeout=10)
        items = response.json().get('Items', [])
        
        print(f"  '{name}' → {len(items)} results")
        
        # If results found show first SKU
        if items:
            for item in items[:2]:
                print(f"    SKU: {item['skuName']} "
                      f"| ${item['retailPrice']} "
                      f"per {item['unitOfMeasure']}")

print("Trying possible NAT Gateway service names...\n")
try_service_names()