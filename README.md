# ThreatIntel RuleForge

ThreatIntel RuleForge is a local analyst workbench that converts PDF threat-intelligence reports into reviewable detection-engineering artifacts. It extracts report text and indicators, maps observed behavior to MITRE ATT&CK, generates draft Sigma rules, and exports the results as a portable ZIP package.

> **Project status:** early-stage and intended for analyst-assisted use. Generated IOCs, ATT&CK mappings, enrichment, and Sigma rules must be reviewed before production use.

## What it does

- Extracts text from PDF threat reports.
- Extracts common IOCs with deterministic patterns and optional LLM-assisted extraction.
- Filters common publisher/reference noise and non-public IPv4 values.
- Optionally enriches public IPv4 indicators with VirusTotal.
- Maps report behavior to MITRE ATT&CK with evidence and confidence.
- Generates draft Sigma rules with deterministic fallback behavior.
- Applies an optional independent LLM judge pass before results are stored.
- Lets analysts approve IOCs and edit generated Sigma rules in the UI.
- Exports IOC CSV, ATT&CK YAML/JSON, ATT&CK Navigator JSON, a Markdown summary, and Sigma YAML files.

## Architecture

```text
threatintel-ruleforge/
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── database.py
│   │   ├── models.py
│   │   ├── schemas.py
│   │   └── services/
│   ├── storage/
│   ├── tests/
│   ├── .env.example
│   ├── requirements.txt
│   └── requirements-dev.txt
├── frontend/
│   ├── src/
│   ├── index.html
│   ├── package.json
│   └── package-lock.json
├── .github/
├── docs/
├── CONTRIBUTING.md
├── SECURITY.md
└── LICENSE
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the processing flow and trust boundaries.

## Requirements

- Python 3.12+
- Node.js 22.12+ (24 recommended)
- npm

API keys are optional. Without an OpenAI key, the application uses deterministic extraction/mapping/rule fallbacks and marks judge output for analyst review. VirusTotal enrichment is skipped when its key is not configured.

## Quick start

### 1. Backend

```bash
cd backend
python -m venv .venv
```

Activate the environment:

```bash
# Linux/macOS
source .venv/bin/activate

# Windows PowerShell
.\.venv\Scripts\Activate.ps1
```

Install dependencies and create local configuration:

```bash
pip install -r requirements.txt
cp .env.example .env  # Windows: copy .env.example .env
```

Start the API:

```bash
uvicorn app.main:app --reload --port 8000
```

Useful endpoints:

- API: `http://127.0.0.1:8000`
- Health: `http://127.0.0.1:8000/health`
- OpenAPI docs: `http://127.0.0.1:8000/docs`

### 2. Frontend

In a second terminal:

```bash
cd frontend
npm ci
npm run dev
```

Open `http://127.0.0.1:5173`.

To point the UI at a different backend, create `frontend/.env`:

```env
VITE_API_URL=http://127.0.0.1:8000
```

## Configuration

Copy `backend/.env.example` to `backend/.env` and set only the integrations you want to use.

Important settings:

| Variable | Purpose |
| --- | --- |
| `OPENAI_API_KEY` | Enables LLM-assisted overview, IOC extraction, ATT&CK mapping, Sigma generation, and judge functions. |
| `OPENAI_MODEL` | OpenAI model used by the backend. |
| `VIRUSTOTAL_API_KEY` | Enables VirusTotal enrichment for public IPv4 indicators. |
| `JUDGE_ENABLED` | Enables/disables the independent LLM QA pass. |
| `MAX_UPLOAD_MB` | Maximum accepted PDF upload size. |
| `CORS_ALLOW_ORIGINS` | Comma-separated frontend origins allowed by the API. |
| `LLM_DEBUG` | Logs model output when `true`; keep disabled unless actively troubleshooting. |

Never commit `.env` files or API keys.

## Export format

A processed report exports a ZIP containing:

```text
iocs.csv
mitre_mapping.yaml
mitre_mapping.json
attack_navigator_layer.json
summary.md
sigma_rules/
  *.yml
```

The Navigator layer targets Enterprise ATT&CK v19.1 and ATT&CK Navigator v5.3.2/layer format v4.5.

## Development checks

Backend tests:

```bash
cd backend
pip install -r requirements-dev.txt
pytest
```

Frontend production build:

```bash
cd frontend
npm ci
npm run build
```

The same checks run in GitHub Actions on pushes and pull requests.

## Security and data handling

Threat reports can contain sensitive or customer-confidential information. When LLM or VirusTotal integrations are enabled, relevant report data or public indicators may be sent to those third-party services. Review their terms and your organization's data-handling requirements before enabling integrations.

The application is designed for local analyst workflows and does not currently provide authentication, multi-user authorization, or a hardened production deployment profile.

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## Contributing

Issues and pull requests are welcome. Read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting changes.

## License

MIT. See [LICENSE](LICENSE).
