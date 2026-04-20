import os, json
from parser import parse_bicep
from security_scanner import scan_security

DATASET_DIR = r"dataset\raw"

def evaluate_dataset():
    results = []
    total_files = 0
    failed_files = 0
    flagged_files = 0

    rule_counts = {}

    for filename in os.listdir(DATASET_DIR):
        if not filename.endswith(".bicep"):
            continue

        total_files += 1
        filepath = os.path.join(DATASET_DIR, filename)

        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                bicep_code = f.read()

            resources = parse_bicep(bicep_code)
            issues = scan_security(bicep_code, resources)

            if issues:
                flagged_files += 1

            for issue in issues:
                rule = issue['rule']
                rule_counts[rule] = rule_counts.get(rule, 0) + 1

            results.append({
                "file": filename,
                "resources_found": len(resources),
                "issues_found": len(issues),
                "rules_triggered": [i['rule'] for i in issues]
            })

        except Exception as e:
            failed_files += 1
            results.append({"file": filename, "error": str(e)})

    print("\n[RESULTS] Dataset Evaluation")
    print("-" * 50)
    print(f"  Total files scanned : {total_files}")
    print(f"  Files with issues   : {flagged_files}")
    print(f"  Clean files         : {total_files - flagged_files - failed_files}")
    print(f"  Failed to parse     : {failed_files}")
    print("-" * 50)
    print("\n[TOP 10] Most Common Issues:")
    sorted_rules = sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)
    for i, (rule, count) in enumerate(sorted_rules[:10], 1):
        pct = count / total_files * 100
        print(f"  {i:2}. {rule:<45} {count:4} files ({pct:.1f}%)")

    with open("dataset_evaluation_results.json", "w") as f:
        json.dump({
            "total_files": total_files,
            "flagged_files": flagged_files,
            "failed_files": failed_files,
            "rule_counts": rule_counts,
            "per_file": results
        }, f, indent=2)

    print("\n[DONE] Full results saved to dataset_evaluation_results.json")

if __name__ == "__main__":
    evaluate_dataset()