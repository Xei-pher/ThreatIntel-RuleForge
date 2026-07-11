# ThreatIntel RuleForge MVP

A local web application that ingests PDF threat reports, extracts text and IOCs, maps basic MITRE ATT&CK techniques, generates Sigma rules, and exports CSV/YAML/Markdown assets as a ZIP.

## MVP Features

- PDF upload
- PDF text extraction
- IOC extraction
- MITRE ATT&CK heuristic mapping
- Sigma rule generation
- Human review/editing in the UI
- Export to ZIP containing:
  - `iocs.csv`
  - `mitre_mapping.yaml`
  - `summary.md`
  - Sigma rule YAML files

## Project Structure

```text
threatintel-ruleforge/
  backend/
    app/
      main.py
      models.py
      schemas.py
      database.py
      services/
        pdf_service.py
        ioc_service.py
        mitre_service.py
        rule_service.py
        export_service.py
    requirements.txt
  frontend/
    src/
      main.jsx
      styles.css
      api/client.js
    package.json
```

## Run Backend

```bash
cd backend
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Backend health check:

```text
http://localhost:8000/health
```

API docs:

```text
http://localhost:8000/docs
```

## Run Frontend

```bash
cd frontend
npm install
npm run dev
```

Open:

```text
http://localhost:5173
```

## Important Notes

This MVP intentionally does not use an LLM yet. The extraction and mapping are rule-based so you can test the workflow without API keys.

Next serious upgrade:

1. Add Sigma validation using `sigma-cli` or pySigma.
2. Add OCR fallback for scanned reports.
3. Add authentication and project workspaces.

## Current Limitations

- MITRE mapping is keyword-based.
- Sigma generation is IOC-based and generic.
- OCR is not implemented yet.
- No user authentication yet.
- No production deployment configuration yet.

This is a strong MVP foundation, not the final commercial-grade product.

## Optional LLM Integration

The backend now supports OpenAI-powered extraction and detection generation. The app still works without an API key because the original regex/keyword/Sigma fallback logic remains in place.

### Enable LLM mode

From the backend folder:

```powershell
copy .env.example .env
notepad .env
```

Add your key:

```env
OPENAI_API_KEY=sk-your-key-here
OPENAI_MODEL=gpt-4.1-mini
LLM_MAX_REPORT_CHARS=60000
```

Then reinstall backend dependencies:

```powershell
cd backend
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
uvicorn app.main:app --reload
```

### What the LLM now powers

- `ioc_service.py`: regex extraction plus LLM extraction for contextual IOCs such as mutexes, filenames, user agents, service names, and process names.
- `mitre_service.py`: keyword mapping plus LLM-based ATT&CK mapping with evidence and confidence.
- `rule_service.py`: LLM-generated Sigma rules first; validated fallback Sigma rules if the LLM fails or no API key exists.
- `llm_service.py`: shared OpenAI client, JSON-only prompting, error-safe fallback behavior.

### Important behavior

If the LLM call fails, the app does not crash. It prints `[LLM_DISABLED_OR_FAILED]` in the backend terminal and falls back to the deterministic MVP logic.


## LLM debugging

After adding your `OPENAI_API_KEY` to `backend/.env`, restart the backend and test:

```powershell
curl http://127.0.0.1:8000/health
curl http://127.0.0.1:8000/llm/health
```

Expected `llm/health` result:

```json
{
  "enabled": true,
  "ok": true,
  "message": "llm reachable"
}
```

If LLM calls fail, the backend now prints full debug logs in the Uvicorn terminal for these tasks:

- `ioc_extraction`
- `mitre_mapping`
- `sigma_generation`
- `health_check`

Important: keep `LOG_LEVEL=DEBUG` and `LLM_DEBUG=true` while troubleshooting. Turn `LLM_DEBUG=false` later because it can log model outputs.

## IOC Quality Filtering + VirusTotal Enrichment

This build filters noisy/non-actionable IOCs before saving them and before rule generation.

Filtered by default:
- Private/non-public IPv4 addresses, including 10.x.x.x, 172.16-31.x.x, 192.168.x.x, loopback, link-local, multicast, reserved, documentation/test ranges, etc.
- Common report publisher/reference domains such as dfirreport.com, MITRE, VirusTotal, GitHub raw links, and similar sources.
- Duplicate IOCs.

To customize domain filtering, edit `backend/.env`:

```env
IOC_DOMAIN_DENYLIST=dfirreport.com,www.dfirreport.com,thedfirreport.com,www.thedfirreport.com,attack.mitre.org,mitre.org,virustotal.com,www.virustotal.com,github.com,raw.githubusercontent.com
IOC_DOMAIN_ALLOWLIST=
```

### VirusTotal API key

Add your VirusTotal key in `backend/.env`:

```env
VIRUSTOTAL_API_KEY=your_virustotal_key_here
VT_TIMEOUT_SECONDS=20
```

Only public IPv4 IOCs are enriched in this version. Private/local IPs are filtered out and never sent to VirusTotal.

Check config:

```powershell
curl http://127.0.0.1:8000/virustotal/health
curl http://127.0.0.1:8000/health
```

Reprocess a report after adding the API key to populate enrichment fields.


## Network Error Troubleshooting

The frontend now displays the exact backend URL it is trying to reach in the sidebar. By default it uses:

```text
http://127.0.0.1:8000
```

Before using the UI, confirm these URLs work in your browser:

```text
http://127.0.0.1:8000/health
http://127.0.0.1:8000/docs
```

If the frontend is running from a different host/port, set this in `frontend/.env`:

```env
VITE_API_URL=http://127.0.0.1:8000
```

Then restart Vite.

For CORS changes, set this in `backend/.env`:

```env
CORS_ALLOW_ORIGINS=http://localhost:5173,http://127.0.0.1:5173,http://0.0.0.0:5173
```


## Export contents

The ZIP export includes `iocs.csv`, `mitre_mapping.yaml`, `mitre_mapping.json`, `attack_navigator_layer.json`, `summary.md`, and Sigma rule YAML files. Upload `attack_navigator_layer.json` directly into MITRE ATT&CK Navigator.
