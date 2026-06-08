# AegisRecon AI 🛡️
**Intelligent Hybrid Vulnerability Scanner**  
*Powered by Python + Flask · PECA 2016 Compliance · Ollama AI Support*

---

## Project Structure

```
aegisrecon/
├── app.py                    ← Flask app factory + core routes
├── config.py                 ← All configuration (DB, scan, PECA, Ollama)
├── extensions.py             ← db, migrate instances (avoids circular imports)
├── company_config.json       ← Branding, report text, labels
├── requirements.txt
│
├── models/
│   └── scan.py               ← ScanTarget, ScanFinding, ReconData, RiskScore, ScanReport
│
├── routes/
│   ├── scan_routes.py        ← /scan/new, /scan/<id>/status
│   ├── report_routes.py      ← /reports/generate/<id>/<type>
│   └── api_routes.py         ← /api/scans, /api/scan/<id>/findings
│
├── services/                 ← Phase 2: recon + scan logic
│   ├── passive_recon.py      ← WHOIS, DNS, crt.sh, Wayback
│   ├── active_scan.py        ← Nmap, HTTP headers, SSL
│   ├── vuln_engine.py        ← Version → CVE lookup
│   ├── risk_calculator.py    ← Business Risk Score + PECA fines
│   ├── ai_service.py         ← Ollama integration
│   └── pdf_service.py        ← ReportLab PDF generation
│
├── utils/                    ← Phase 2: helpers
│   ├── validators.py
│   ├── formatters.py
│   └── logger.py
│
├── templates/
│   ├── base.html             ← Master layout (dark cyber theme)
│   ├── index.html            ← Dashboard
│   ├── new_scan.html         ← Scan form
│   ├── scan_detail.html      ← Results + findings
│   ├── history.html          ← Paginated scan history
│   ├── errors/
│   │   ├── 404.html
│   │   └── 500.html
│   └── reports/              ← Phase 3: PDF templates
│
├── static/
│   ├── css/
│   ├── js/
│   └── img/
│
└── instance/
    ├── aegisrecon.db         ← SQLite (auto-created)
    └── reports/              ← Generated PDFs
```

---

## Quick Start

### 1. Clone / Setup

```bash
cd aegisrecon
python -m venv venv
source venv/bin/activate   # Windows: venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Install Nmap (required for active scanning)

```bash
# Ubuntu/Debian
sudo apt install nmap

# macOS
brew install nmap

# Windows: https://nmap.org/download.html
```

### 3. Run

```bash
python app.py
# Open: http://127.0.0.1:5000
```

### 4. (Optional) Enable Ollama AI

```bash
# Install Ollama: https://ollama.com
ollama pull llama3
export OLLAMA_ENABLED=true
python app.py
```

---

## Build Phases

| Phase | What Gets Built |
|-------|----------------|
| ✅ Phase 1 | Project structure, models, config, base templates, routes |
| 🔜 Phase 2 | Services: passive recon, active scan, vuln engine, risk calculator |
| 🔜 Phase 3 | PDF reports (English + Urdu), AI summaries, predictive risk |

---

## Legal Notice

> This tool is for **authorized security testing only**.  
> Unauthorized use violates **PECA 2016** (Prevention of Electronic Crimes Act, Pakistan).  
> Always obtain written permission before scanning any target.
