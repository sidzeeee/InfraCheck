# InfraCheck

> Deploy with certainty. Not with hope.

InfraCheck is an open-source static analysis framework for Microsoft Bicep templates that combines **security misconfiguration detection** with **real-time cost estimation** — without requiring an Azure subscription or deployed resources.

---

## What It Does

Paste your Bicep code. InfraCheck returns:

- 🔒 **Security scan** — 20 rules across 4 categories (Network Exposure, Access Control, Encryption, Best Practices)
- 💰 **Cost estimation** — Live prices from the Azure Retail Pricing API
- ✅ **Deploy verdict** — Safe to Deploy / Deploy with Caution / Do Not Deploy
- 🧠 **Context awareness** — Detects Databricks, VNet injection, and Azure service tags to reduce false positives

All in under 5 seconds. No Azure account needed.

---

## Why It Exists

Engineers testing Bicep code typically need a separate non-production Azure subscription — costing $100–$1,000+/month depending on team size.

InfraCheck eliminates that requirement entirely by running static analysis locally and fetching live pricing data from Microsoft's public API.

---

## Security Rules

| # | Rule | Category | Severity |
|---|------|----------|----------|
| 1 | Public Blob Access Enabled | Access Control | High |
| 2 | SSH Open To Internet | Network | Critical |
| 3 | RDP Open To Internet | Network | Critical |
| 4 | HTTPS Not Enforced | Network | High |
| 5 | No NSG Found | Network | Medium |
| 6 | Wildcard Port Range | Network | High |
| 7 | Storage Account No Firewall | Access Control | High |
| 8 | Storage Allows HTTP | Network | High |
| 9 | Storage Soft Delete Not Enabled | Best Practices | Medium |
| 10 | VM Disk Encryption Not Configured | Encryption | High |
| 11 | Key Vault Soft Delete Disabled | Best Practices | High |
| 12 | Key Vault No Access Policies | Access Control | Medium |
| 13 | No Resource Lock Defined | Best Practices | Low |
| 14 | No Diagnostic Settings | Best Practices | Medium |
| 15 | No Tags Defined | Best Practices | Low |
| 16 | WinRM Open To Internet | Network | Critical |
| 17 | All Inbound Traffic Allowed | Network | Critical |
| 18 | App Service Minimum TLS Not Set | Encryption | Medium |
| 19 | No Managed Identity Assigned | Access Control | Medium |
| 20 | KV Purge Protection Not Enabled | Best Practices | High |

---

## Key Findings

From evaluating 796 real-world Bicep templates from the Azure Quickstart Templates repository:

- **96.4%** contain at least one misconfiguration
- **87.8%** have no diagnostic settings configured
- **76.6%** have no resource tags defined
- Cost estimation achieves **MAPE = 0%** against published Azure retail prices

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend | Python, FastAPI |
| Security Engine | Custom rule-based static analyser |
| Cost Estimation | Azure Retail Pricing API |
| Frontend | HTML, CSS, JavaScript |
| Auth | Auth0 |

---

## Running Locally

**1. Clone the repo**
```bash
git clone https://github.com/sidzeeee/InfraCheck.git
cd InfraCheck
```

**2. Create virtual environment**
```bash
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Mac/Linux
```

**3. Install dependencies**
```bash
pip install -r requirements.txt
```

**4. Start the backend**
```bash
uvicorn api:app --reload
```

**5. Open the frontend**
```
Open index.html in your browser
or serve via: python -m http.server 8080
```

---

## Project Structure

```
InfraCheck/
├── parser.py              # Bicep parser — extracts resources
├── security_scanner.py    # 20-rule security engine
├── cost_estimator.py      # Cost calculation module
├── pricing_api.py         # Azure Retail Pricing API integration
├── engine.py              # Orchestration layer
├── api.py                 # FastAPI REST backend
├── index.html             # Frontend UI
├── requirements.txt       # Python dependencies
└── Procfile               # Deployment config
```

---

## Dataset — VulnBicep

`VulnBicep` is a manually labeled ground-truth dataset of 25 Bicep templates created for benchmarking IaC security scanners.

- 20 templates each contain exactly one injected misconfiguration
- 5 templates are fully compliant (negative controls)
- InfraCheck achieves **precision = 1.0, recall = 1.0, F1 = 1.0** on this dataset

---

## Roadmap

- [ ] Terraform support
- [ ] ARM template support
- [ ] Bicep AST parser (replace regex)
- [ ] VS Code extension
- [ ] GitHub Action
- [ ] Multi-cloud cost comparison

---

## Author

**Siddharth Sarkar**
Cloud Platform Engineer — Capgemini, Mumbai
[GitHub](https://github.com/sidzeeee)

---

## License

MIT License — free to use, modify, and distribute.