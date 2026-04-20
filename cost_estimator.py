# cost_estimator.py
from pricing_api import get_monthly_cost

def estimate_cost(resources):
    """
    Takes resources from parser.py
    Gets real prices from pricing_api.py
    Returns full cost breakdown
    """
    
    breakdown = []
    total = 0.00
    
    print("   Fetching live prices from Azure API...")
    
    for resource in resources:
        price_data = get_monthly_cost(resource['type'])
        
        cost = price_data['monthly_cost']
        total += cost
        
        breakdown.append({
            'resource_name': resource['name'],
            'resource_type': resource['type'].split('/')[-1],
            'monthly_cost': cost,
            'unit': price_data['unit'],
            'source': price_data['source'],
            'detail': price_data['detail']
        })
    
    return {
        'breakdown': breakdown,
        'total_monthly': round(total, 2),
        'total_annual': round(total * 12, 2)
    }


def display_cost_results(cost_data):
    """
    Prints cost breakdown cleanly
    """
    
    print(f"\n💰 Cost Estimation")
    print(f"{'─' * 40}")
    
    for item in cost_data['breakdown']:
        
        # Show source indicator
        if item['source'] == 'live':
            source = "🟢 LIVE"
        elif item['source'] == 'fixed':
            source = "🔵 FIXED"
        else:
            source = "🟡 ESTIMATE"
        
        if item['monthly_cost'] == 0:
            cost_display = "FREE"
        else:
            cost_display = f"${item['monthly_cost']:.2f}/month"
        
        print(f"  {item['resource_name']}")
        print(f"  Type   : {item['resource_type']}")
        print(f"  Cost   : {cost_display} ({item['unit']})")
        print(f"  Source : {source}")
        print(f"{'─' * 40}")
    
    print(f"\n  📊 Total Monthly : ${cost_data['total_monthly']:.2f}")
    print(f"  📊 Total Annual  : ${cost_data['total_annual']:.2f}")
    
    # Verdict
    print(f"\n  💡 Verdict:", end=" ")
    if cost_data['total_monthly'] == 0:
        print("Free deployment!")
    elif cost_data['total_monthly'] < 50:
        print("Low cost. Looks good.")
    elif cost_data['total_monthly'] < 200:
        print("Moderate cost. Review before deploying.")
    else:
        print("High cost. Make sure this is intentional.")
    print()


if __name__ == "__main__":
    from parser import parse_bicep
    
    test_bicep = """
    resource myStorage 'Microsoft.Storage/storageAccounts@2021-02-01' = {
      name: 'mystorageaccount'
      location: 'eastus'
    }
    resource myVNet 'Microsoft.Network/virtualNetworks@2021-02-01' = {
      name: 'myVNet'
      location: 'eastus'
    }
    resource myNSG 'Microsoft.Network/networkSecurityGroups@2021-02-01' = {
      name: 'myNSG'
      location: 'eastus'
    }
    resource myNATGateway 'Microsoft.Network/natGateways@2021-02-01' = {
      name: 'myNATGateway'
      location: 'eastus'
    }
    resource myVM 'Microsoft.Compute/virtualMachines@2021-03-01' = {
      name: 'myVM'
      location: 'eastus'
    }
    """
    
    print("Estimating costs with live prices...")
    resources = parse_bicep(test_bicep)
    cost_data = estimate_cost(resources)
    display_cost_results(cost_data)