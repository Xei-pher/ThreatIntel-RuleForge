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

1. Add LLM structured extraction for intelligence fields.
2. Add LLM-assisted Sigma generation with schema validation.
3. Add Sigma validation using `sigma-cli` or pySigma.
4. Add OCR fallback for scanned reports.
5. Add IOC enrichment with VirusTotal, OTX, AbuseIPDB, URLhaus.
6. Add authentication and project workspaces.

## Current Limitations

- MITRE mapping is keyword-based.
- Sigma generation is IOC-based and generic.
- OCR is not implemented yet.
- No user authentication yet.
- No production deployment configuration yet.

This is a strong MVP foundation, not the final commercial-grade product.
