# ThreatIntel RuleForge

A local web application that ingests PDF threat intelligence reports, runs them through a **supervisor-controlled multi-agent LLM pipeline**, and exports analysis-ready assets.

## Features

- PDF upload and text extraction (PyMuPDF)
- **Multi-agent pipeline** — six specialised agents orchestrated by a supervisor:
  - **PDFReaderAgent** — extracts raw text from uploaded PDFs
  - **IOCExtractorAgent** — LLM-powered extraction of all IOC categories (IPs, domains, URLs, hashes, paths, mutexes, user agents, process names, CVEs, and more)
  - **MITREAgent** — maps observed TTPs to MITRE ATT&CK Enterprise techniques
  - **SigmaRuleAgent** — generates production-quality Sigma detection rules
  - **ReportGeneratorAgent** — produces a SOC analyst-ready Markdown report
  - **JudgeAgent** — evaluates and scores all outputs against the source material; triggers selective redo of failing agents until a 90 % accuracy threshold is met
- VirusTotal enrichment for public IPv4 IOCs
- IOC quality filtering (private IPs, publisher domains, duplicates)
- Human review and inline editing of IOCs and Sigma rules in the UI
- Export to ZIP containing:
  - `iocs.csv`
  - `mitre_mapping.yaml` / `mitre_mapping.json`
  - `attack_navigator_layer.json` (MITRE ATT&CK Navigator)
  - `sigma_rules/` directory of individual Sigma YAML files
  - `summary.md`
  - `soc_report.md` — full SOC analyst report (new)

## Project Structure

```text
threatintel-ruleforge/
  backend/
    app/
      main.py               # FastAPI application and API routes
      models.py             # SQLAlchemy ORM models (Report, IOC, MitreMapping, DetectionRule, AgentRun)
      schemas.py            # Pydantic response schemas
      database.py           # SQLite engine and session
      agents/               # Multi-agent pipeline
        base.py             # AgentContext, AgentResult, JudgeVerdict, BaseAgent
        pdf_reader.py       # PDFReaderAgent
        ioc_extractor.py    # IOCExtractorAgent
        mitre_agent.py      # MITREAgent
        sigma_agent.py      # SigmaRuleAgent
        report_generator.py # ReportGeneratorAgent
        judge.py            # JudgeAgent
        supervisor.py       # AgentSupervisor (orchestration + iteration loop)
      providers/            # Provider-agnostic LLM abstraction
        base.py             # LLMProvider ABC, LLMMessage, LLMProviderError
        openai_provider.py  # OpenAI (GPT-4o, GPT-4.1-mini, …)
        anthropic_provider.py # Anthropic Claude
        groq_provider.py    # Groq (OpenAI-compatible)
        fireworks_provider.py # Fireworks AI (OpenAI-compatible)
        ollama_provider.py  # Ollama (local, stdlib urllib)
        factory.py          # get_provider() factory
      services/
        pdf_service.py      # PyMuPDF text extraction helper
        ioc_service.py      # IOC normalisation helper
        ioc_filter_service.py # IOC quality filter
        virustotal_service.py # VirusTotal IP enrichment
        export_service.py   # ZIP export builder
        llm_service.py      # LLM status and health-check utilities
    requirements.txt
    .env.example
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
```

Copy and configure the environment file:

```bash
cp .env.example .env
# Edit .env and set LLM_PROVIDER + the corresponding API key (required)
```

Start the server:

```bash
uvicorn app.main:app --reload --port 8000
```

Backend health check:

```
http://localhost:8000/health
```

API docs:

```
http://localhost:8000/docs
```

## Run Frontend

```bash
cd frontend
npm install
npm run dev
```

Open:

```
http://localhost:5173
```

## LLM Provider Configuration

**An LLM provider is required.** Reports cannot be processed without one.

Set `LLM_PROVIDER` in `backend/.env` to one of:

| Value | Provider | Required env var |
|---|---|---|
| `openai` (default) | OpenAI | `OPENAI_API_KEY` |
| `anthropic` | Anthropic Claude | `ANTHROPIC_API_KEY` |
| `groq` | Groq | `GROQ_API_KEY` |
| `fireworks` | Fireworks AI | `FIREWORKS_API_KEY` |
| `ollama` | Ollama (local) | `OLLAMA_BASE_URL` (no key needed) |

Example for OpenAI:

```env
LLM_PROVIDER=openai
OPENAI_API_KEY=sk-your-key-here
OPENAI_MODEL=gpt-4o-mini
```

Example for Ollama:

```env
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.1
```

Check provider connectivity:

```
http://localhost:8000/llm/health
```

## Agent Supervisor Configuration

```env
# Enable or disable the Judge Agent.
# Set to false to skip scoring and run the pipeline as a single pass (useful when hitting rate limits).
JUDGE_AGENT_ACTIVE=true

# Minimum Judge score (0–100) required to accept pipeline output (default: 90)
JUDGE_PASS_SCORE=90.0

# Maximum judge-supervised iterations before accepting best result (default: 3)
JUDGE_MAX_ITERATIONS=3
```

The supervisor runs agents sequentially. After all agents complete an iteration, the JudgeAgent evaluates all outputs and scores them against the source material. If the score is below `JUDGE_PASS_SCORE`, only the agents flagged by the Judge are re-executed with the critique injected into their prompts. This continues until the score passes or `JUDGE_MAX_ITERATIONS` is reached.

Set `JUDGE_AGENT_ACTIVE=false` to disable the Judge entirely. The pipeline will run once and accept the result without scoring — this eliminates the additional LLM call per iteration and is recommended when working under tight API rate limits.

## Rate Limit Handling

All LLM calls include automatic retry with exponential backoff when a rate-limit or quota error is detected (HTTP 429, `rate limit`, `too many requests`, `tokens per minute`, etc.). The retry behaviour is fully configurable:

```env
# Maximum number of retries after a rate-limit error (default: 4)
LLM_RATE_LIMIT_MAX_RETRIES=4

# Seconds to wait before the first retry (default: 5)
LLM_RATE_LIMIT_INITIAL_WAIT=5.0

# Multiplier applied to the wait time on each subsequent retry (default: 2 = exponential backoff)
LLM_RATE_LIMIT_BACKOFF_FACTOR=2.0

# Maximum wait ceiling in seconds between retries (default: 60)
LLM_RATE_LIMIT_MAX_WAIT=60.0
```

With defaults the wait sequence is: 5 s → 10 s → 20 s → 40 s → 60 s (capped). If all retries are exhausted the agent falls back gracefully and the pipeline continues. Non-rate-limit errors are not retried.

## API Endpoints

### Existing (unchanged response schema)

| Method | Path | Description |
|---|---|---|
| `GET` | `/health` | Health + LLM + VirusTotal status |
| `GET` | `/llm/health` | LLM provider connectivity check |
| `POST` | `/reports/upload` | Upload a PDF |
| `GET` | `/reports` | List all reports |
| `GET` | `/reports/{id}` | Get report detail |
| `POST` | `/reports/{id}/process` | Run the multi-agent pipeline |
| `GET` | `/reports/{id}/iocs` | List IOCs |
| `PATCH` | `/iocs/{id}` | Update an IOC |
| `GET` | `/reports/{id}/detections` | List Sigma rules |
| `PATCH` | `/detections/{id}` | Update a Sigma rule |
| `POST` | `/reports/{id}/export` | Download ZIP export |

### New

| Method | Path | Description |
|---|---|---|
| `GET` | `/reports/{id}/agent-runs` | Full agent execution audit log (all iterations) |
| `GET` | `/reports/{id}/report-md` | SOC analyst Markdown report (`text/markdown`) |

## VirusTotal Enrichment

```env
VIRUSTOTAL_API_KEY=your_virustotal_key_here
VT_TIMEOUT_SECONDS=20
```

Only public IPv4 IOCs are enriched. Private, loopback, and reserved IPs are filtered out before enrichment.

## IOC Filtering

```env
# Additional domains to block (comma-separated)
IOC_DOMAIN_DENYLIST=

# Domains to always keep regardless of other rules
IOC_DOMAIN_ALLOWLIST=
```

## Debugging

```env
LOG_LEVEL=DEBUG
LLM_DEBUG=true   # logs raw LLM outputs (may log sensitive data — disable in production)
```

## Current Limitations

- OCR not implemented — scanned/image-based PDFs are flagged as `[OCR_REQUIRED]`
- VirusTotal enrichment covers IPv4 only (domain, URL, hash enrichment not yet implemented)
- No user authentication
- Processing is synchronous — large reports with multiple judge iterations may take several minutes
- Parallel agent execution is not supported
- API rate limits: set `JUDGE_AGENT_ACTIVE=false` and/or increase `LLM_RATE_LIMIT_INITIAL_WAIT` if you are consistently hitting provider rate limits

## Export ZIP Contents

```
report_{id}_export.zip
  iocs.csv                    IOC table with enrichment data
  mitre_mapping.yaml          MITRE ATT&CK mappings (YAML)
  mitre_mapping.json          MITRE ATT&CK mappings (JSON)
  attack_navigator_layer.json ATT&CK Navigator layer (upload to navigator.attack.mitre.org)
  sigma_rules/                Individual Sigma YAML files (one per rule)
  summary.md                  Legacy overview summary
  soc_report.md               Full SOC analyst report (generated by ReportGeneratorAgent)
```
