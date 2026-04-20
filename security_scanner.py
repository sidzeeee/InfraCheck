# security_scanner.py

# ─────────────────────────────────────────
# Azure Service Tags — these are safe
# abstractions, not open internet access
# ─────────────────────────────────────────
AZURE_SERVICE_TAGS = [
    'VirtualNetwork', 'AzureLoadBalancer',
    'Internet', 'Storage', 'Sql',
    'AzureDatabricks', 'AzureCloud',
    'AzureActiveDirectory', 'AppService',
    'AzureMonitor', 'EventHub', 'ServiceBus',
    'AzureKeyVault', 'AzureContainerRegistry'
]

# ─────────────────────────────────────────
# Architecture detection helpers
# ─────────────────────────────────────────
def detect_architecture(bicep_code, resources):
    """
    Reads the full template and figures out
    what kind of deployment this is.
    Returns a context dict used by all rules.
    """

    context = {
        'has_databricks':     any('Databricks' in r['type'] for r in resources),
        'has_nat_gateway':    any('natGateways' in r['type'] for r in resources),
        'has_vnet':           any('virtualNetworks' in r['type'] for r in resources),
        'has_nsg':            any('networkSecurityGroups' in r['type'] for r in resources),
        'has_vm':             any('virtualMachines' in r['type'] for r in resources),
        'has_storage':        any('storageAccounts' in r['type'] for r in resources),
        'has_keyvault':       any('vaults' in r['type'] for r in resources),
        'has_appservice':     any('sites' in r['type'] for r in resources),
        'no_public_ip':       'enableNoPublicIp: true' in bicep_code,
        'vnet_injected':      'vnetInjection' in bicep_code or 'customVirtualNetworkId' in bicep_code,
    }

    # Determine overall architecture type
    if context['has_databricks'] and context['has_nat_gateway'] and context['no_public_ip']:
        context['architecture'] = 'SECURE_DATABRICKS'
    elif context['has_databricks']:
        context['architecture'] = 'DATABRICKS'
    elif context['has_vm'] and context['has_vnet']:
        context['architecture'] = 'VM_WORKLOAD'
    elif context['has_storage'] and not context['has_vm']:
        context['architecture'] = 'STORAGE_ONLY'
    else:
        context['architecture'] = 'GENERAL'

    return context


def is_service_tag(address):
    """
    Returns True if the address is an
    Azure service tag rather than a real IP.
    Service tags are safe — they scope traffic
    to specific Azure services, not the internet.
    """
    if not address:
        return False
    clean = address.strip("'\" ")
    return clean in AZURE_SERVICE_TAGS


def is_internet_exposed(source_address):
    """
    Returns True only if the source is
    actually the open internet.
    """
    if not source_address:
        return False
    clean = source_address.strip("'\" ")
    internet_patterns = ['0.0.0.0/0', '*', 'Internet']
    return clean in internet_patterns and not is_service_tag(clean)


# ─────────────────────────────────────────
# Main scanner
# ─────────────────────────────────────────
def scan_security(bicep_code, resources):
    """
    Runs all 20 security rules with
    full context awareness.
    """
    issues = []

    # Detect architecture first
    ctx = detect_architecture(bicep_code, resources)

    # Pass context to every rule
    issues += check_storage_public_access(bicep_code, resources, ctx)
    issues += check_ssh_open(bicep_code, resources, ctx)
    issues += check_http_not_https(bicep_code, resources, ctx)
    issues += check_missing_nsg(bicep_code, resources, ctx)
    issues += check_wide_open_ports(bicep_code, resources, ctx)
    issues += check_rdp_open(bicep_code, resources, ctx)
    issues += check_storage_no_firewall(bicep_code, resources, ctx)
    issues += check_storage_allows_http(bicep_code, resources, ctx)
    issues += check_storage_no_soft_delete(bicep_code, resources, ctx)
    issues += check_disk_not_encrypted(bicep_code, resources, ctx)
    issues += check_keyvault_no_soft_delete(bicep_code, resources, ctx)
    issues += check_keyvault_no_access_policies(bicep_code, resources, ctx)
    issues += check_no_resource_lock(bicep_code, resources, ctx)
    issues += check_no_diagnostic_settings(bicep_code, resources, ctx)
    issues += check_no_tags(bicep_code, resources, ctx)
    issues += check_winrm_open(bicep_code, resources, ctx)
    issues += check_all_inbound_traffic(bicep_code, resources, ctx)
    issues += check_appservice_http(bicep_code, resources, ctx)
    issues += check_no_managed_identity(bicep_code, resources, ctx)
    issues += check_keyvault_purge_protection(bicep_code, resources, ctx)

    # Add architecture summary as info finding
    if ctx['architecture'] == 'SECURE_DATABRICKS':
        issues.insert(0, {
            'severity': 'INFO',
            'resource': 'Architecture',
            'rule': 'Secure Databricks Deployment Detected',
            'message': 'NAT Gateway present, public IPs disabled, VNet injection configured. '
                       'This appears to be a secure VNet-injected Databricks setup. '
                       'Some NSG rules flagged below may be required for cluster communication.',
            'fix': 'Review Databricks-specific findings with lower severity weighting.'
        })
    elif ctx['architecture'] == 'DATABRICKS':
        issues.insert(0, {
            'severity': 'INFO',
            'resource': 'Architecture',
            'rule': 'Databricks Deployment Detected',
            'message': 'Databricks workspace detected. Some network rules are required '
                       'for cluster communication and have been severity-adjusted accordingly.',
            'fix': 'Consider adding NAT Gateway and enableNoPublicIp: true for a fully secure setup.'
        })

    return issues


# ─────────────────────────────────────────
# RULE 1 — Public blob storage
# ─────────────────────────────────────────
def check_storage_public_access(bicep_code, resources, ctx):
    issues = []
    for resource in resources:
        if 'Storage/storageAccounts' in resource['type']:
            if 'allowBlobPublicAccess: true' in bicep_code:
                issues.append({
                    'severity': 'HIGH',
                    'resource': resource['name'],
                    'rule': 'Public Blob Access Enabled',
                    'message': f"'{resource['name']}' allows public blob access. "
                               f"Anyone on the internet can read your storage data.",
                    'fix': "Set 'allowBlobPublicAccess: false' in your storage properties."
                })
    return issues


# ─────────────────────────────────────────
# RULE 2 — SSH open to internet
# ─────────────────────────────────────────
def check_ssh_open(bicep_code, resources, ctx):
    issues = []
    for resource in resources:
        if 'networkSecurityGroups' in resource['type']:
            if ("'22'" in bicep_code or '"22"' in bicep_code or
                    'destinationPortRange: 22' in bicep_code):

                source_is_internet = is_internet_exposed(
                    '0.0.0.0/0' if '0.0.0.0/0' in bicep_code else
                    'VirtualNetwork' if 'VirtualNetwork' in bicep_code else '*'
                )

                if source_is_internet:
                    issues.append({
                        'severity': 'CRITICAL',
                        'resource': resource['name'],
                        'rule': 'SSH Open To Internet',
                        'message': f"'{resource['name']}' allows SSH (port 22) from any IP (0.0.0.0/0). "
                                   f"This is a critical security risk.",
                        'fix': "Restrict SSH to specific IP ranges or use Azure Bastion instead."
                    })
    return issues


# ─────────────────────────────────────────
# RULE 3 — HTTP instead of HTTPS
# ─────────────────────────────────────────
def check_http_not_https(bicep_code, resources, ctx):
    issues = []
    for resource in resources:
        if 'sites' in resource['type'] or 'webApps' in resource['type']:
            if 'httpsOnly: false' in bicep_code:
                issues.append({
                    'severity': 'HIGH',
                    'resource': resource['name'],
                    'rule': 'HTTPS Not Enforced',
                    'message': f"'{resource['name']}' does not enforce HTTPS. Traffic can be intercepted.",
                    'fix': "Set 'httpsOnly: true' in your web app properties."
                })
    return issues


# ─────────────────────────────────────────
# RULE 4 — Missing NSG
# ─────────────────────────────────────────
def check_missing_nsg(bicep_code, resources, ctx):
    issues = []
    has_vnet = any('virtualNetworks' in r['type'] for r in resources)
    has_nsg  = any('networkSecurityGroups' in r['type'] for r in resources)

    if has_vnet and not has_nsg:
        # Databricks deployments sometimes manage NSGs automatically
        if ctx['architecture'] in ('SECURE_DATABRICKS', 'DATABRICKS'):
            issues.append({
                'severity': 'LOW',
                'resource': 'VNet',
                'rule': 'No NSG Found',
                'message': "No explicit NSG defined. For Databricks, the workspace may manage "
                           "its own NSG automatically. Verify in the Azure portal after deployment.",
                'fix': "Confirm Databricks-managed NSG is created on deployment, "
                       "or add an explicit NSG for additional control."
            })
        else:
            issues.append({
                'severity': 'MEDIUM',
                'resource': 'VNet',
                'rule': 'No NSG Found',
                'message': "A VNet was found but no NSG is defined. Your network traffic is unfiltered.",
                'fix': "Add a Network Security Group and attach it to your subnet."
            })
    return issues


# ─────────────────────────────────────────
# RULE 5 — Wildcard port ranges
# ─────────────────────────────────────────
def check_wide_open_ports(bicep_code, resources, ctx):
    issues = []
    for resource in resources:
        if 'networkSecurityGroups' in resource['type']:
            if ("destinationPortRange: '*'" in bicep_code or
                    'destinationPortRange: "*"' in bicep_code):

                # Databricks requires wildcard ports for internal cluster traffic
                if ctx['architecture'] in ('SECURE_DATABRICKS', 'DATABRICKS'):
                    issues.append({
                        'severity': 'MEDIUM',
                        'resource': resource['name'],
                        'rule': 'Wildcard Port Range',
                        'message': f"'{resource['name']}' uses wildcard port ranges. "
                                   f"For Databricks, this is commonly required for internal "
                                   f"cluster-to-cluster communication within the VNet.",
                        'fix': "Verify source is scoped to VirtualNetwork or AzureDatabricks "
                               "service tag only. Add NSG flow logs to monitor traffic."
                    })
                else:
                    issues.append({
                        'severity': 'HIGH',
                        'resource': resource['name'],
                        'rule': 'Wildcard Port Range',
                        'message': f"'{resource['name']}' uses a wildcard (*) for port ranges. "
                                   f"This opens every single port.",
                        'fix': "Specify only the exact ports your application needs."
                    })
    return issues


# ─────────────────────────────────────────
# RULE 6 — RDP open to internet
# ─────────────────────────────────────────
def check_rdp_open(bicep_code, resources, ctx):
    issues = []
    for resource in resources:
        if 'networkSecurityGroups' in resource['type']:
            if ("'3389'" in bicep_code or '"3389"' in bicep_code or
                    'destinationPortRange: 3389' in bicep_code):
                if is_internet_exposed('0.0.0.0/0' if '0.0.0.0/0' in bicep_code else '*'):
                    issues.append({
                        'severity': 'CRITICAL',
                        'resource': resource['name'],
                        'rule': 'RDP Open To Internet',
                        'message': f"'{resource['name']}' allows RDP (port 3389) from any IP. "
                                   f"This is a critical security risk.",
                        'fix': "Restrict RDP to specific IP ranges or use Azure Bastion."
                    })
    return issues


# ─────────────────────────────────────────
# RULE 7 — Storage account has no firewall
# ─────────────────────────────────────────
def check_storage_no_firewall(bicep_code, resources, ctx):
    issues = []
    for resource in resources:
        if 'Storage/storageAccounts' in resource['type']:
            if 'defaultAction: ' in bicep_code:
                if ("defaultAction: 'Allow'" in bicep_code or
                        'defaultAction: "Allow"' in bicep_code):
                    issues.append({
                        'severity': 'HIGH',
                        'resource': resource['name'],
                        'rule': 'Storage Account No Firewall',
                        'message': f"'{resource['name']}' allows access from all networks.",
                        'fix': "Set networkAcls.defaultAction to 'Deny' and whitelist specific IPs or VNets."
                    })
            else:
                issues.append({
                    'severity': 'MEDIUM',
                    'resource': resource['name'],
                    'rule': 'Storage Account No Firewall',
                    'message': f"'{resource['name']}' has no networkAcls configured.",
                    'fix': "Add networkAcls with defaultAction: 'Deny'."
                })
    return issues


# ─────────────────────────────────────────
# RULE 8 — Storage allows HTTP
# ─────────────────────────────────────────
def check_storage_allows_http(bicep_code, resources, ctx):
    issues = []
    for resource in resources:
        if 'Storage/storageAccounts' in resource['type']:
            if 'supportsHttpsTrafficOnly: false' in bicep_code:
                issues.append({
                    'severity': 'HIGH',
                    'resource': resource['name'],
                    'rule': 'Storage Allows HTTP Traffic',
                    'message': f"'{resource['name']}' allows unencrypted HTTP traffic.",
                    'fix': "Set 'supportsHttpsTrafficOnly: true'."
                })
    return issues


# ─────────────────────────────────────────
# RULE 9 — Storage no soft delete
# ─────────────────────────────────────────
def check_storage_no_soft_delete(bicep_code, resources, ctx):
    issues = []
    for resource in resources:
        if 'Storage/storageAccounts' in resource['type']:
            if 'deleteRetentionPolicy' not in bicep_code:
                issues.append({
                    'severity': 'MEDIUM',
                    'resource': resource['name'],
                    'rule': 'Storage Soft Delete Not Enabled',
                    'message': f"'{resource['name']}' has no blob soft delete policy. "
                               f"Deleted data cannot be recovered.",
                    'fix': "Enable deleteRetentionPolicy with a retention period of at least 7 days."
                })
    return issues


# ─────────────────────────────────────────
# RULE 10 — VM disk not encrypted
# ─────────────────────────────────────────
def check_disk_not_encrypted(bicep_code, resources, ctx):
    issues = []
    for resource in resources:
        if 'virtualMachines' in resource['type']:
            if 'diskEncryptionSet' not in bicep_code and 'encryptionAtHost' not in bicep_code:
                issues.append({
                    'severity': 'HIGH',
                    'resource': resource['name'],
                    'rule': 'VM Disk Encryption Not Configured',
                    'message': f"'{resource['name']}' has no disk encryption configured.",
                    'fix': "Enable encryptionAtHost or attach a diskEncryptionSet to your VM."
                })
    return issues


# ─────────────────────────────────────────
# RULE 11 — Key Vault no soft delete
# ─────────────────────────────────────────
def check_keyvault_no_soft_delete(bicep_code, resources, ctx):
    issues = []
    for resource in resources:
        if 'vaults' in resource['type'] and 'KeyVault' in resource['type']:
            if 'enableSoftDelete: false' in bicep_code:
                issues.append({
                    'severity': 'HIGH',
                    'resource': resource['name'],
                    'rule': 'Key Vault Soft Delete Disabled',
                    'message': f"'{resource['name']}' has soft delete explicitly disabled. "
                               f"Secrets can be permanently deleted.",
                    'fix': "Set 'enableSoftDelete: true' in Key Vault properties."
                })
    return issues


# ─────────────────────────────────────────
# RULE 12 — Key Vault no access policies
# ─────────────────────────────────────────
def check_keyvault_no_access_policies(bicep_code, resources, ctx):
    issues = []
    for resource in resources:
        if 'vaults' in resource['type'] and 'KeyVault' in resource['type']:
            if 'accessPolicies' not in bicep_code:
                issues.append({
                    'severity': 'MEDIUM',
                    'resource': resource['name'],
                    'rule': 'Key Vault No Access Policies',
                    'message': f"'{resource['name']}' has no access policies defined.",
                    'fix': "Define explicit accessPolicies or use Azure RBAC for Key Vault."
                })
    return issues


# ─────────────────────────────────────────
# RULE 13 — No resource lock
# ─────────────────────────────────────────
def check_no_resource_lock(bicep_code, resources, ctx):
    issues = []
    critical_types = ['storageAccounts', 'virtualMachines', 'vaults']
    has_lock = 'Microsoft.Authorization/locks' in bicep_code
    has_critical = any(
        any(ct in r['type'] for ct in critical_types) for r in resources
    )
    if has_critical and not has_lock:
        issues.append({
            'severity': 'LOW',
            'resource': 'Critical Resources',
            'rule': 'No Resource Lock Defined',
            'message': "Critical resources found but no resource lock is defined. "
                       "Resources can be accidentally deleted.",
            'fix': "Add a Microsoft.Authorization/locks resource with level 'CanNotDelete'."
        })
    return issues


# ─────────────────────────────────────────
# RULE 14 — No diagnostic settings
# ─────────────────────────────────────────
def check_no_diagnostic_settings(bicep_code, resources, ctx):
    issues = []
    if 'Microsoft.Insights/diagnosticSettings' not in bicep_code:
        if len(resources) > 0:
            issues.append({
                'severity': 'MEDIUM',
                'resource': 'All Resources',
                'rule': 'No Diagnostic Settings Configured',
                'message': "No diagnostic settings found. You have no audit logging or monitoring configured.",
                'fix': "Add Microsoft.Insights/diagnosticSettings to send logs to a Log Analytics workspace."
            })
    return issues


# ─────────────────────────────────────────
# RULE 15 — No tags
# ─────────────────────────────────────────
def check_no_tags(bicep_code, resources, ctx):
    issues = []
    if 'tags:' not in bicep_code:
        issues.append({
            'severity': 'LOW',
            'resource': 'All Resources',
            'rule': 'No Tags Defined',
            'message': "No resource tags found. Resources cannot be tracked by cost center or environment.",
            'fix': "Add tags with at minimum 'environment' and 'owner' keys to all resources."
        })
    return issues


# ─────────────────────────────────────────
# RULE 16 — WinRM open to internet
# ─────────────────────────────────────────
def check_winrm_open(bicep_code, resources, ctx):
    issues = []
    for resource in resources:
        if 'networkSecurityGroups' in resource['type']:
            if ("'5985'" in bicep_code or "'5986'" in bicep_code or
                    '"5985"' in bicep_code or '"5986"' in bicep_code):
                if is_internet_exposed('0.0.0.0/0' if '0.0.0.0/0' in bicep_code else '*'):
                    issues.append({
                        'severity': 'CRITICAL',
                        'resource': resource['name'],
                        'rule': 'WinRM Open To Internet',
                        'message': f"'{resource['name']}' allows WinRM (5985/5986) from any IP. "
                                   f"Remote management is exposed to the internet.",
                        'fix': "Restrict WinRM ports to specific management IPs only."
                    })
    return issues


# ─────────────────────────────────────────
# RULE 17 — All inbound traffic allowed
# ─────────────────────────────────────────
def check_all_inbound_traffic(bicep_code, resources, ctx):
    issues = []
    for resource in resources:
        if 'networkSecurityGroups' in resource['type']:
            if ("protocol: '*'" in bicep_code or 'protocol: "*"' in bicep_code):

                # Check if source is actually internal
                source_is_vnet = 'VirtualNetwork' in bicep_code
                source_is_databricks = 'AzureDatabricks' in bicep_code
                source_is_internet = is_internet_exposed(
                    '0.0.0.0/0' if '0.0.0.0/0' in bicep_code else
                    '*' if ("'*'" in bicep_code or '"*"' in bicep_code) else ''
                )

                if ctx['architecture'] in ('SECURE_DATABRICKS', 'DATABRICKS') and (
                        source_is_vnet or source_is_databricks):
                    issues.append({
                        'severity': 'MEDIUM',
                        'resource': resource['name'],
                        'rule': 'All Inbound Traffic Allowed',
                        'message': f"'{resource['name']}' allows all protocols — but source is scoped to "
                                   f"VirtualNetwork or AzureDatabricks service tag. "
                                   f"This is commonly required for Databricks cluster communication.",
                        'fix': "This rule may be intentional for Databricks. "
                               "Enable NSG flow logs to monitor actual traffic patterns."
                    })
                elif source_is_internet:
                    issues.append({
                        'severity': 'CRITICAL',
                        'resource': resource['name'],
                        'rule': 'All Inbound Traffic Allowed',
                        'message': f"'{resource['name']}' allows all protocols from the open internet. "
                                   f"This fully exposes your resources.",
                        'fix': "Restrict inbound rules to specific protocols, ports, and source ranges."
                    })
    return issues


# ─────────────────────────────────────────
# RULE 18 — App Service no min TLS
# ─────────────────────────────────────────
def check_appservice_http(bicep_code, resources, ctx):
    issues = []
    for resource in resources:
        if 'sites' in resource['type']:
            if 'minTlsVersion' not in bicep_code:
                issues.append({
                    'severity': 'MEDIUM',
                    'resource': resource['name'],
                    'rule': 'App Service Minimum TLS Not Set',
                    'message': f"'{resource['name']}' has no minimum TLS version configured.",
                    'fix': "Set minTlsVersion to '1.2' in your App Service siteConfig."
                })
    return issues


# ─────────────────────────────────────────
# RULE 19 — No managed identity on VM
# ─────────────────────────────────────────
def check_no_managed_identity(bicep_code, resources, ctx):
    issues = []
    for resource in resources:
        if 'virtualMachines' in resource['type']:
            if 'identity:' not in bicep_code:
                issues.append({
                    'severity': 'MEDIUM',
                    'resource': resource['name'],
                    'rule': 'No Managed Identity Assigned',
                    'message': f"'{resource['name']}' has no managed identity. "
                               f"Classic credential patterns may be used instead.",
                    'fix': "Assign a system-assigned or user-assigned managed identity to your VM."
                })
    return issues


# ─────────────────────────────────────────
# RULE 20 — Key Vault purge protection
# ─────────────────────────────────────────
def check_keyvault_purge_protection(bicep_code, resources, ctx):
    issues = []
    for resource in resources:
        if 'vaults' in resource['type'] and 'KeyVault' in resource['type']:
            if 'enablePurgeProtection' not in bicep_code:
                issues.append({
                    'severity': 'HIGH',
                    'resource': resource['name'],
                    'rule': 'Key Vault Purge Protection Not Enabled',
                    'message': f"'{resource['name']}' does not have purge protection enabled. "
                               f"Secrets can be permanently destroyed.",
                    'fix': "Set 'enablePurgeProtection: true' in Key Vault properties."
                })
    return issues


# ─────────────────────────────────────────
# Display results
# ─────────────────────────────────────────
def display_security_results(issues):
    if not issues:
        print("\n✅ No security issues found!")
        return

    info     = [i for i in issues if i['severity'] == 'INFO']
    critical = [i for i in issues if i['severity'] == 'CRITICAL']
    high     = [i for i in issues if i['severity'] == 'HIGH']
    medium   = [i for i in issues if i['severity'] == 'MEDIUM']
    low      = [i for i in issues if i['severity'] == 'LOW']

    print(f"\n🔒 Security Scan Results")
    print(f"{'─' * 40}")
    if info:
        print(f"  ℹ️  Info     : {len(info)}")
    print(f"  🔴 Critical : {len(critical)}")
    print(f"  🟠 High     : {len(high)}")
    print(f"  🟡 Medium   : {len(medium)}")
    print(f"  🔵 Low      : {len(low)}")
    print(f"{'─' * 40}\n")

    for issue in issues:
        if issue['severity'] == 'INFO':
            emoji = 'ℹ️ '
        elif issue['severity'] == 'CRITICAL':
            emoji = '🔴'
        elif issue['severity'] == 'HIGH':
            emoji = '🟠'
        elif issue['severity'] == 'MEDIUM':
            emoji = '🟡'
        else:
            emoji = '🔵'

        print(f"{emoji} {issue['severity']} — {issue['rule']}")
        print(f"   Resource : {issue['resource']}")
        print(f"   Problem  : {issue['message']}")
        print(f"   Fix      : {issue['fix']}")
        print(f"{'─' * 40}\n")


# ─────────────────────────────────────────
# Test
# ─────────────────────────────────────────
if __name__ == "__main__":
    from parser import parse_bicep

    # Databricks VNet injection test
    databricks_bicep = """
    resource vnet 'Microsoft.Network/virtualNetworks@2021-02-01' = {
      name: 'databricks-vnet'
      location: 'eastus'
      properties: {
        addressSpace: { addressPrefixes: ['10.0.0.0/16'] }
      }
    }

    resource nsg 'Microsoft.Network/networkSecurityGroups@2021-02-01' = {
      name: 'databricks-nsg'
      location: 'eastus'
      properties: {
        securityRules: [
          {
            name: 'databricks-worker-to-worker'
            properties: {
              priority: 100
              protocol: '*'
              access: 'Allow'
              direction: 'Inbound'
              sourceAddressPrefix: 'VirtualNetwork'
              sourcePortRange: '*'
              destinationAddressPrefix: 'VirtualNetwork'
              destinationPortRange: '*'
            }
          }
        ]
      }
    }

    resource natGateway 'Microsoft.Network/natGateways@2021-02-01' = {
      name: 'databricks-nat'
      location: 'eastus'
      sku: { name: 'Standard' }
    }

    resource databricksWorkspace 'Microsoft.Databricks/workspaces@2021-04-01' = {
      name: 'myWorkspace'
      location: 'eastus'
      properties: {
        managedResourceGroupId: resourceGroup().id
        parameters: {
          enableNoPublicIp: { value: true }
          customVirtualNetworkId: { value: vnet.id }
        }
      }
    }
    """

    print("Testing with Databricks VNet injection template...")
    resources = parse_bicep(databricks_bicep)
    issues = scan_security(databricks_bicep, resources)
    display_security_results(issues)