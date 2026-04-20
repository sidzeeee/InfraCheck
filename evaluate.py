import os, json
from parser import parse_bicep
from security_scanner import scan_security

VULNBICEP_DIR = r"dataset\vulnbicep"

# Ground truth — what SHOULD be detected in each file
GROUND_TRUTH = {
    "01_public_blob.bicep":             ["Public Blob Access Enabled", "Storage Account No Firewall", "Storage Soft Delete Not Enabled", "No Resource Lock Defined", "No Diagnostic Settings Configured", "No Tags Defined"],
    "02_ssh_open.bicep":                ["SSH Open To Internet", "No Diagnostic Settings Configured", "No Tags Defined"],
    "03_rdp_open.bicep":                ["RDP Open To Internet", "No Diagnostic Settings Configured", "No Tags Defined"],
    "04_http_not_https.bicep":          ["HTTPS Not Enforced", "No Diagnostic Settings Configured", "No Tags Defined"],
    "05_missing_nsg.bicep":             ["No NSG Found", "No Diagnostic Settings Configured", "No Tags Defined"],
    "06_wildcard_ports.bicep":          ["Wildcard Port Range", "No Diagnostic Settings Configured", "No Tags Defined"],
    "07_storage_no_firewall.bicep":     ["Storage Account No Firewall", "Storage Soft Delete Not Enabled", "No Resource Lock Defined", "No Diagnostic Settings Configured", "No Tags Defined"],
    "08_storage_http.bicep":            ["Storage Allows HTTP Traffic", "Storage Account No Firewall", "Storage Soft Delete Not Enabled", "No Resource Lock Defined", "No Diagnostic Settings Configured", "No Tags Defined"],
    "09_no_soft_delete.bicep":          ["Storage Soft Delete Not Enabled", "Storage Account No Firewall", "No Resource Lock Defined", "No Diagnostic Settings Configured", "No Tags Defined"],
    "10_disk_not_encrypted.bicep":      ["VM Disk Encryption Not Configured", "No Managed Identity Assigned", "No Resource Lock Defined", "No Diagnostic Settings Configured", "No Tags Defined"],
    "11_keyvault_no_softdelete.bicep":  ["Key Vault Soft Delete Disabled", "Key Vault No Access Policies", "Key Vault Purge Protection Not Enabled", "No Resource Lock Defined", "No Diagnostic Settings Configured", "No Tags Defined"],
    "12_keyvault_no_access_policies.bicep": ["Key Vault No Access Policies", "Key Vault Purge Protection Not Enabled", "No Resource Lock Defined", "No Diagnostic Settings Configured", "No Tags Defined"],
    "13_no_resource_lock.bicep":        ["No Resource Lock Defined", "Storage Account No Firewall", "Storage Soft Delete Not Enabled", "No Diagnostic Settings Configured", "No Tags Defined"],
    "14_no_diagnostic_settings.bicep":  ["No Diagnostic Settings Configured", "Storage Account No Firewall", "Storage Soft Delete Not Enabled", "No Resource Lock Defined", "No Tags Defined"],
    "15_no_tags.bicep":                 ["No Tags Defined", "Storage Account No Firewall", "Storage Soft Delete Not Enabled", "No Resource Lock Defined", "No Diagnostic Settings Configured"],
    "16_winrm_open.bicep":              ["WinRM Open To Internet", "No Diagnostic Settings Configured", "No Tags Defined"],
    "17_all_inbound.bicep":             ["All Inbound Traffic Allowed", "Wildcard Port Range", "No Diagnostic Settings Configured", "No Tags Defined"],
    "18_appservice_no_tls.bicep":       ["App Service Minimum TLS Not Set", "No Diagnostic Settings Configured", "No Tags Defined"],
    "19_no_managed_identity.bicep":     ["No Managed Identity Assigned", "VM Disk Encryption Not Configured", "No Resource Lock Defined", "No Diagnostic Settings Configured", "No Tags Defined"],
    "20_keyvault_no_purge.bicep":       ["Key Vault Purge Protection Not Enabled", "No Resource Lock Defined", "No Diagnostic Settings Configured", "No Tags Defined"],
    "21_clean_storage.bicep":           ["No Diagnostic Settings Configured"],
    "22_clean_keyvault.bicep":          ["No Resource Lock Defined", "No Diagnostic Settings Configured"],
    "23_clean_nsg.bicep":               ["No Diagnostic Settings Configured"],
    "24_clean_vm.bicep":                ["No Resource Lock Defined", "No Diagnostic Settings Configured"],
    "25_clean_webapp.bicep":            ["No Diagnostic Settings Configured"],
}

def evaluate():
    TP = 0
    FP = 0
    FN = 0

    results = []

    for filename, expected_rules in GROUND_TRUTH.items():
        filepath = os.path.join(VULNBICEP_DIR, filename)
        if not os.path.exists(filepath):
            print(f"MISSING: {filename}")
            continue

        with open(filepath, 'r') as f:
            bicep_code = f.read()

        resources = parse_bicep(bicep_code)
        issues = scan_security(bicep_code, resources)
        detected_rules = [i['rule'] for i in issues]

        file_tp = sum(1 for r in expected_rules if r in detected_rules)
        file_fp = sum(1 for r in detected_rules if r not in expected_rules)
        file_fn = sum(1 for r in expected_rules if r not in detected_rules)

        TP += file_tp
        FP += file_fp
        FN += file_fn

        results.append({
            "file": filename,
            "expected": expected_rules,
            "detected": detected_rules,
            "TP": file_tp,
            "FP": file_fp,
            "FN": file_fn
        })

    precision = TP / (TP + FP) if (TP + FP) > 0 else 0
    recall    = TP / (TP + FN) if (TP + FN) > 0 else 0
    f1        = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0

    print("\n📊 Evaluation Results — VulnBicep Ground Truth")
    print("─" * 50)
    print(f"  True Positives  (TP) : {TP}")
    print(f"  False Positives (FP) : {FP}")
    print(f"  False Negatives (FN) : {FN}")
    print("─" * 50)
    print(f"  Precision : {precision:.2%}")
    print(f"  Recall    : {recall:.2%}")
    print(f"  F1 Score  : {f1:.2%}")
    print("─" * 50)

    print("\n📋 Per-File Breakdown:")
    for r in results:
        status = "✅" if r['FP'] == 0 and r['FN'] == 0 else "⚠️"
        print(f"  {status} {r['file']}")
        if r['FN'] > 0:
            missed = [x for x in r['expected'] if x not in r['detected']]
            print(f"     ❌ Missed : {missed}")
        if r['FP'] > 0:
            extra = [x for x in r['detected'] if x not in r['expected']]
            print(f"     ➕ Extra  : {extra}")

    with open("evaluation_results.json", "w") as f:
        json.dump({
            "TP": TP, "FP": FP, "FN": FN,
            "precision": precision,
            "recall": recall,
            "f1": f1,
            "per_file": results
        }, f, indent=2)

    print("\n✅ Results saved to evaluation_results.json")

if __name__ == "__main__":
    evaluate()