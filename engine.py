# engine.py

from parser import parse_bicep
from security_scanner import scan_security, display_security_results
from cost_estimator import estimate_cost, display_cost_results

def run_infracheck(bicep_code):
    """
    The main engine.
    Takes Bicep code and runs all checks.
    Returns a complete report.
    """
    
    print("\n" + "═" * 40)
    print("       INFRACHECK — ANALYSIS REPORT")
    print("═" * 40)
    
    # ─────────────────────────────
    # STEP 1 — Parse the code
    # ─────────────────────────────
    print("\n🔍 Step 1: Reading your IaC code...")
    resources = parse_bicep(bicep_code)
    
    if not resources:
        print("❌ No resources found. Check your code.")
        return
    
    print(f"✅ Found {len(resources)} resource(s):")
    for resource in resources:
        print(f"   → {resource['name']} ({resource['type']})")
    
    # ─────────────────────────────
    # STEP 2 — Security scan
    # ─────────────────────────────
    print("\n🔒 Step 2: Running security scan...")
    issues = scan_security(bicep_code, resources)
    
    if not issues:
        print("✅ No security issues found!")
    else:
        display_security_results(issues)
    
    # ─────────────────────────────
    # STEP 3 — Cost estimation
    # ─────────────────────────────
    print("\n💰 Step 3: Estimating costs...")
    cost_data = estimate_cost(resources)
    display_cost_results(cost_data)
    
    # ─────────────────────────────
    # STEP 4 — Final verdict
    # ─────────────────────────────
    print("═" * 40)
    print("           FINAL VERDICT")
    print("═" * 40)
    
    critical_issues = [i for i in issues if i['severity'] == 'CRITICAL']
    high_issues = [i for i in issues if i['severity'] == 'HIGH']
    medium_issues = [i for i in issues if i['severity'] == 'MEDIUM']
    
    if critical_issues:
        print("\n🔴 DO NOT DEPLOY")
        print("   Critical security issues found.")
        print("   Fix these before deploying anywhere.")
        
    elif high_issues:
        print("\n🟠 DEPLOY WITH CAUTION")
        print("   High severity issues found.")
        print("   Strongly recommend fixing before prod.")
        
    elif medium_issues:
        print("\n🟡 MOSTLY SAFE")
        print("   Minor issues found.")
        print("   Review before deploying to prod.")
        
    elif cost_data['total_monthly'] > 500:
        print("\n⚠️  REVIEW COSTS")
        print("   No security issues but high cost detected.")
        print("   Make sure this spend is intentional.")
        
    else:
        print("\n✅ SAFE TO DEPLOY")
        print("   No security issues found.")
        print("   Cost looks reasonable.")
    
    print("\n" + "═" * 40)
    
    # Return everything as a dict
    # Useful when we build the frontend
    return {
        'resources': resources,
        'security_issues': issues,
        'cost': cost_data,
        'verdict': get_verdict(issues, cost_data)
    }


def get_verdict(issues, cost_data):
    """
    Returns a simple verdict string.
    Used by the frontend later.
    """
    critical = any(i['severity'] == 'CRITICAL' for i in issues)
    high = any(i['severity'] == 'HIGH' for i in issues)
    medium = any(i['severity'] == 'MEDIUM' for i in issues)
    expensive = cost_data['total_monthly'] > 500
    
    if critical:
        return 'DO_NOT_DEPLOY'
    elif high:
        return 'DEPLOY_WITH_CAUTION'
    elif medium:
        return 'MOSTLY_SAFE'
    elif expensive:
        return 'REVIEW_COSTS'
    else:
        return 'SAFE_TO_DEPLOY'


# ─────────────────────────────────────────
# Test with two scenarios
# ─────────────────────────────────────────
if __name__ == "__main__":
    
    # ── Scenario 1 — Bad code full of issues ──
    print("\n📋 SCENARIO 1 — Dangerous Bicep Code")
    
    bad_bicep = """
    resource myStorage 'Microsoft.Storage/storageAccounts@2021-02-01' = {
      name: 'mystorageaccount'
      location: 'eastus'
      properties: {
        allowBlobPublicAccess: true
      }
    }
    
    resource myVNet 'Microsoft.Network/virtualNetworks@2021-02-01' = {
      name: 'myVNet'
      location: 'eastus'
    }
    
    resource myNSG 'Microsoft.Network/networkSecurityGroups@2021-02-01' = {
      name: 'myNSG'
      location: 'eastus'
      properties: {
        securityRules: [
          {
            name: 'allow-ssh'
            properties: {
              priority: 100
              protocol: 'Tcp'
              access: 'Allow'
              direction: 'Inbound'
              sourceAddressPrefix: '0.0.0.0/0'
              destinationPortRange: 22
            }
          }
        ]
      }
    }
    """
    
    run_infracheck(bad_bicep)
    
    # ── Scenario 2 — Clean safe code ──
    print("\n📋 SCENARIO 2 — Clean Safe Code")
    
    good_bicep = """
    resource myStorage 'Microsoft.Storage/storageAccounts@2021-02-01' = {
      name: 'mystorageaccount'
      location: 'eastus'
      properties: {
        allowBlobPublicAccess: false
      }
    }
    
    resource myVNet 'Microsoft.Network/virtualNetworks@2021-02-01' = {
      name: 'myVNet'
      location: 'eastus'
    }
    
    resource myNSG 'Microsoft.Network/networkSecurityGroups@2021-02-01' = {
      name: 'myNSG'
      location: 'eastus'
      properties: {
        securityRules: [
          {
            name: 'allow-ssh-restricted'
            properties: {
              priority: 100
              protocol: 'Tcp'
              access: 'Allow'
              direction: 'Inbound'
              sourceAddressPrefix: '192.168.1.0/24'
              destinationPortRange: 22
            }
          }
        ]
      }
    }
    """
    
    run_infracheck(good_bicep)