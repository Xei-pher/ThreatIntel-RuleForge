# Architecture

ThreatIntel RuleForge is a two-process local web application: a FastAPI backend and a React/Vite frontend.

## Processing flow

1. The frontend uploads a PDF to the backend.
2. The backend stores the file under `backend/storage/reports/` and extracts page text with PyMuPDF.
3. Deterministic IOC extraction runs first; optional LLM extraction adds contextual artifacts.
4. IOC quality filters remove duplicates, non-public IPv4 values, and configured publisher/reference domains.
5. Optional VirusTotal enrichment runs only for public IPv4 indicators.
6. ATT&CK mappings are produced from deterministic behavior keywords and optional LLM mapping.
7. Sigma rules are generated from report evidence. Deterministic IOC-based rules are used if LLM generation is unavailable.
8. When enabled, the judge layer scores generated IOCs, mappings, and rules before persistence.
9. Results are stored in local SQLite and exposed for analyst review in the frontend.
10. Approved/reviewed results can be exported to CSV, YAML, JSON, Markdown, and Sigma YAML.

## Trust boundaries

- **Uploaded reports:** untrusted input. Filenames are sanitized and uploads are size-limited.
- **LLM output:** untrusted generated data. Structured JSON is requested and Sigma YAML receives basic validation, but analyst review is still required.
- **External enrichment:** optional. VirusTotal receives only public IPv4 values in the current implementation.
- **Local database:** contains report text and derived intelligence. Treat `backend/ruleforge.db` as potentially sensitive.
- **Exports:** may contain operational indicators and report-derived content. Handle them according to the source report's classification.

## Current constraints

- SQLite schema upgrades use a lightweight local migration shim rather than Alembic.
- PDF OCR is not implemented for image-only reports.
- Authentication and tenant isolation are not implemented.
- Sigma validation is structural/basic rather than full pySigma validation.
- Processing is synchronous and intended for local/small-team workflows.
