# pricing_api.py
import requests

BASE_URL = "https://prices.azure.com/api/retail/prices"
API_VERSION = "2023-01-01-preview"

def get_price(service_name, sku_filter, region="eastus"):
    """
    Fetches real price from Azure Pricing API.
    Returns monthly cost in USD.
    """
    params = {
        "api-version": API_VERSION,
        "$filter": f"serviceName eq '{service_name}' and armRegionName eq '{region}'"
    }

    try:
        response = requests.get(BASE_URL, params=params, timeout=10)

        if response.status_code != 200:
            return None

        items = response.json().get('Items', [])

        if not items:
            return None

        # Filter by SKU keyword
        matching = [
            item for item in items
            if sku_filter.lower() in item['skuName'].lower()
            and item['retailPrice'] > 0
            and 'Windows' not in item['skuName']
        ]

        if not matching:
            # Fall back to first result
            matching = [i for i in items if i['retailPrice'] > 0]

        if not matching:
            return None

        # Return the first matching price
        item = matching[0]
        
        return {
            'price': item['retailPrice'],
            'unit': item['unitOfMeasure'],
            'sku': item['skuName'],
            'product': item['productName']
        }

    except requests.exceptions.Timeout:
        print("   ⚠️  API timeout — using estimate")
        return None
    except Exception as e:
        print(f"   ⚠️  API error — using estimate")
        return None


def get_monthly_cost(resource_type, region="eastus"):
    """
    Maps Azure resource types to real API prices.
    Returns monthly cost estimate in USD.
    """

    # ── Storage Account ──
    if 'Storage/storageAccounts' in resource_type:
        result = get_price('Storage', 'LRS', region)
        if result:
            # API returns per GB price
            # Assume 100GB average usage
            monthly = result['price'] * 200
            return {
                'monthly_cost': round(monthly, 2),
                'unit': 'per 100GB (LRS)',
                'source': 'live',
                'detail': result['product']
            }

    # ── Virtual Network ──
    elif 'Network/virtualNetworks' in resource_type:
        result = get_price('Virtual Network', 'Peering', region)
        if result:
            return {
                'monthly_cost': round(result['price'] * 50, 2),
                'unit': 'estimate 50GB transfer',
                'source': 'live',
                'detail': result['product']
            }

    # ── NAT Gateway ──
    # Not available in Azure Pricing API
    # Using Microsoft's published rate of $0.045/hour
    elif 'Network/natGateways' in resource_type:
        monthly = 0.045 * 24 * 30
        return {
            'monthly_cost': round(monthly, 2),
            'unit': 'per gateway per month',
            'source': 'fixed',
            'detail': 'NAT Gateway — fixed Microsoft rate'
        }
    
    # ── Virtual Machine ──
    elif 'Compute/virtualMachines' in resource_type:
        result = get_price('Virtual Machines', 'B2s', region)
        if result:
            # Filter out anomalous prices over $1/hour
            # Those are reserved instance artifacts
            price = result['price']
            if price > 1.0:
                price = 0.0416  # fallback to known B2s price
            monthly = price * 24 * 30
            return {
                'monthly_cost': round(monthly, 2),
                'unit': 'B2s always on',
                'source': 'live',
                'detail': result['product']
            }

    # ── Public IP ──
    elif 'Network/publicIPAddresses' in resource_type:
        result = get_price('IP Addresses', 'Static', region)
        if result:
            monthly = result['price'] * 24 * 30
            return {
                'monthly_cost': round(monthly, 2),
                'unit': 'static IP per month',
                'source': 'live',
                'detail': result['product']
            }

    # ── Key Vault ──
    elif 'KeyVault/vaults' in resource_type:
        result = get_price('Key Vault', 'Standard', region)
        if result:
            # Per 10k operations — assume 10k/month
            return {
                'monthly_cost': round(result['price'], 2),
                'unit': 'per 10k operations',
                'source': 'live',
                'detail': result['product']
            }

    # ── SQL Server ──
    elif 'Sql/servers' in resource_type:
        result = get_price('Azure SQL Database', 'Basic', region)
        if result:
            monthly = result['price'] * 24 * 30
            return {
                'monthly_cost': round(monthly, 2),
                'unit': 'Basic tier per month',
                'source': 'live',
                'detail': result['product']
            }

    # ── Databricks ──
    elif 'Databricks/workspaces' in resource_type:
        result = get_price('Azure Databricks', 'Standard', region)
        if result:
            # Per DBU hour — assume 4 DBUs * 8 hours * 20 days
            monthly = result['price'] * 4 * 8 * 20
            return {
                'monthly_cost': round(monthly, 2),
                'unit': 'estimate 4 DBU * 8hr * 20 days',
                'source': 'live',
                'detail': result['product']
            }

    # ── NSG — Always free ──
    elif 'networkSecurityGroups' in resource_type:
        return {
            'monthly_cost': 0.00,
            'unit': 'free',
            'source': 'fixed',
            'detail': 'Network Security Groups are free'
        }

    # ── Unknown resource — use fallback ──
    return {
        'monthly_cost': 10.00,
        'unit': 'estimated',
        'source': 'fallback',
        'detail': 'Unknown resource type'
    }


# ─────────────────────────────────────────
# Test it directly
# ─────────────────────────────────────────
if __name__ == "__main__":

    test_resources = [
        'Microsoft.Storage/storageAccounts',
        'Microsoft.Network/virtualNetworks',
        'Microsoft.Network/networkSecurityGroups',
        'Microsoft.Network/natGateways',
        'Microsoft.Compute/virtualMachines',
        'Microsoft.Databricks/workspaces',
    ]

    print("Fetching live Azure prices...\n")
    print("─" * 40)

    total = 0

    for resource_type in test_resources:
        result = get_monthly_cost(resource_type)
        source_flag = "🟢 LIVE" if result['source'] == 'live' else "🟡 ESTIMATE"
        
        print(f"Resource : {resource_type.split('/')[-1]}")
        print(f"Price    : ${result['monthly_cost']:.2f}/month ({result['unit']})")
        print(f"Source   : {source_flag}")
        print(f"─" * 40)
        
        total += result['monthly_cost']

    print(f"\n💰 Total Monthly: ${total:.2f}")
    print(f"📊 Total Annual:  ${total * 12:.2f}")