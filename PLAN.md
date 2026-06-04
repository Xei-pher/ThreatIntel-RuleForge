# ThreatIntel RuleForge — Multi-Agent Refactoring Plan

**Prepared by:** Senior Software Engineer  
**Date:** 2026-06-05  
**Scope:** Backend only (`backend/`)  
**Status:** Awaiting supervisor approval before implementation

---

## 1. Executive Summary

The current backend processes threat intelligence PDFs through a sequential pipeline of standalone service functions called imperatively from a single FastAPI route handler (`POST /reports/{report_id}/process`). The LLM integration is tightly coupled to the OpenAI client in `llm_service.py`, and there is no mechanism for evaluating output quality or iterating on poor results.

This plan refactors the backend to a **supervisor-controlled multi-agent architecture** that:

- Encapsulates each processing concern in a discrete, testable agent class.
- Introduces a provider-agnostic LLM abstraction layer that supports OpenAI, Anthropic, Groq, Fireworks AI, and Ollama with a single switchable configuration value.
- Adds a **Judge Agent** that scores the pipeline's output against the source material and triggers selective re-execution of failing agents until a 90 % accuracy threshold is reached or a configurable maximum iteration count is exhausted.
- Retains existing API response schemas to preserve frontend compatibility. Backend implementation, processing logic, and database schema (additive only) are refactored freely to meet the multi-agent goal. **A configured LLM provider is required; the application will not process reports without one.**

No external multi-agent framework (LangGraph, CrewAI, AutoGen, etc.) is used. The agent abstraction is a lightweight, custom implementation.

---

## 2. Current Architecture Analysis

### 2.1 Processing Flow (as-is)

```
POST /reports/{id}/process
  │
  ├─ extract_text_from_pdf()       ← pdf_service.py  (PyMuPDF)
  ├─ generate_overview_with_llm()  ← llm_service.py  (OpenAI direct call)
  ├─ extract_iocs()                ← ioc_service.py  (regex + OpenAI)
  │     └─ enrich_ip()             ← virustotal_service.py
  ├─ map_mitre()                   ← mitre_service.py (keyword + OpenAI)
  ├─ generate_sigma_rules()        ← rule_service.py  (OpenAI + YAML fallback)
  └─ [save to DB]
```

### 2.2 Key Observations

| Observation | Implication for Refactor |
|---|---|
| All LLM calls use `openai.OpenAI` directly | Must be replaced by the provider abstraction |
| `.env.example` already declares five providers | Abstraction layer maps to these existing env vars |
| `agents/` and `providers/` directories exist but are empty | Use them as the target location for new modules |
| Services contain both business logic and LLM call logic | Services will be split: business/regex logic stays in `services/`; LLM prompt logic moves to agents |
| No quality-feedback loop | Requires new Judge Agent + supervisor iteration loop |
| `processing_status` column exists on `Report` | Extend to track per-iteration status |
| No `AgentRun` audit trail | New model needed (additive migration) |

### 2.3 Existing Services Retained as Helpers

The following service modules will **not be deleted**. They will be refactored minimally to act as utility helpers called by the relevant agent:

- `pdf_service.py` — text extraction helper (no LLM, unchanged)
- `ioc_filter_service.py` — filtering logic helper (no LLM, unchanged)
- `virustotal_service.py` — VirusTotal enrichment helper (no LLM, unchanged)
- `export_service.py` — ZIP export helper (unchanged)

The following service modules will be **fully refactored** — all processing logic (both LLM and deterministic) moves into the corresponding agent class. The service files are either stripped to thin utilities or removed entirely:

- `ioc_service.py` — fully superseded by `IOCExtractorAgent`; file reduced to IOC normalisation helper only
- `mitre_service.py` — fully superseded by `MITREAgent`; file removed
- `rule_service.py` — fully superseded by `SigmaRuleAgent`; file removed
- `llm_service.py` — retains schema constants and `test_llm_connection()`; direct `OpenAI` client calls replaced by the provider abstraction

---

## 3. Target Architecture

### 3.1 High-Level Diagram

```
POST /reports/{id}/process
        │
        ▼
  AgentSupervisor.run(report_id, db)
        │
        ├─── [iteration loop, max N times] ──────────────────────────────┐
        │                                                                  │
        │   AgentContext (shared state)                                    │
        │       │                                                          │
        │       ├─→ PDFReaderAgent.run()          → context.raw_text      │
        │       ├─→ IOCExtractorAgent.run()        → context.iocs          │
        │       ├─→ MITREAgent.run()               → context.mitre         │
        │       ├─→ SigmaRuleAgent.run()           → context.sigma_rules   │
        │       ├─→ ReportGeneratorAgent.run()     → context.report_md     │
        │       └─→ JudgeAgent.run()               → JudgeVerdict          │
        │               │                                                   │
        │               ├── score >= 90 %  ──────────────────── DONE ──────┘
        │               └── score <  90 %  → mark agents for redo ────────┐
        │                                                                   │
        └───────────────────────────────────────────────────────── retry ──┘
        │
        ▼
  [Persist results to DB]
  [Return ReportDetail]
```

### 3.2 Sequential Execution Guarantee

Agents always run in the fixed order shown above. The supervisor never runs agents concurrently. On a redo iteration only the agents flagged by the Judge are re-executed; agents whose output was accepted are skipped and their previous context values are reused.

---

## 4. Component Specifications

### 4.1 LLM Provider Abstraction (`app/providers/`)

#### `app/providers/base.py`

```python
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

class LLMMessage:
    role: str   # "system" | "user" | "assistant"
    content: str

class LLMProvider(ABC):
    """Minimal interface every provider adapter must implement."""

    @abstractmethod
    def complete(
        self,
        messages: List[LLMMessage],
        json_schema: Optional[Dict[str, Any]] = None,
        temperature: float = 0.1,
    ) -> str:
        """Return the raw response string (JSON or plain text)."""
        ...
```

**Contract rules:**
- `complete()` always returns a string. JSON parsing is the caller's responsibility.
- On any API error the provider raises `LLMProviderError` (custom exception defined in `base.py`).
- Each provider reads its own env vars (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, etc.).
- `json_schema` is passed as a structured output / response format hint where the provider supports it; ignored silently where it does not.

#### Provider Implementations

| File | Provider | Env vars used | Notes |
|---|---|---|---|
| `openai_provider.py` | OpenAI | `OPENAI_API_KEY`, `OPENAI_MODEL` | Supports `response_format` structured output |
| `anthropic_provider.py` | Anthropic Claude | `ANTHROPIC_API_KEY`, `ANTHROPIC_MODEL` | Uses `anthropic` SDK; tool-use for JSON schema |
| `groq_provider.py` | Groq | `GROQ_API_KEY`, `GROQ_MODEL` | OpenAI-compatible endpoint |
| `fireworks_provider.py` | Fireworks AI | `FIREWORKS_API_KEY`, `FIREWORKS_MODEL` | OpenAI-compatible endpoint |
| `ollama_provider.py` | Ollama (local) | `OLLAMA_BASE_URL`, `OLLAMA_MODEL` | HTTP REST; no external SDK needed |

#### `app/providers/factory.py`

```python
def get_provider() -> LLMProvider:
    provider_name = os.getenv("LLM_PROVIDER", "openai").lower()
    registry = {
        "openai": OpenAIProvider,
        "anthropic": AnthropicProvider,
        "groq": GroqProvider,
        "fireworks": FireworksProvider,
        "ollama": OllamaProvider,
    }
    cls = registry.get(provider_name)
    if cls is None:
        raise ValueError(f"Unknown LLM_PROVIDER: {provider_name!r}")
    return cls()
```

`get_provider()` is called once at supervisor initialization (not on every LLM call) so the provider instance is shared and connection pooling is respected.

---

### 4.2 Agent Base Class (`app/agents/base.py`)

```python
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

@dataclass
class AgentContext:
    """Mutable shared state passed through the pipeline."""
    report_id: int
    pdf_path: str
    raw_text: str = ""
    iocs: List[Dict] = field(default_factory=list)
    mitre_mappings: List[Dict] = field(default_factory=list)
    sigma_rules: List[Dict] = field(default_factory=list)
    report_markdown: str = ""
    overview: Dict = field(default_factory=dict)
    judge_feedback: Optional["JudgeVerdict"] = None
    iteration: int = 0

@dataclass
class AgentResult:
    agent_name: str
    success: bool
    output: Any
    notes: str = ""

@dataclass
class JudgeVerdict:
    score: float                    # 0.0 – 100.0
    passed: bool                    # True if score >= threshold
    failed_agents: List[str]        # agent names requiring redo
    critique: str                   # human-readable explanation
    iteration: int

class BaseAgent:
    name: str = "base"

    def __init__(self, provider):
        self._provider = provider

    def run(self, context: AgentContext) -> AgentResult:
        raise NotImplementedError

    def _call_llm(self, system: str, user: str, schema=None, fallback=None) -> Dict:
        """Shared LLM call helper with JSON parsing and safe fallback."""
        ...
```

**Design decisions:**
- `AgentContext` is a plain dataclass (not a Pydantic model) to keep it lightweight and mutable within the supervisor loop.
- `BaseAgent._call_llm()` encapsulates JSON-safe parsing, truncation to `LLM_MAX_REPORT_CHARS`, debug logging, and error-to-fallback behaviour — the same logic currently in `llm_service.call_json()`, promoted to the base class.
- Agents do not hold database sessions; they work exclusively on the `AgentContext`. The supervisor persists results.

---

### 4.3 Individual Agent Specifications

#### PDFReaderAgent (`app/agents/pdf_reader.py`)

- **Inputs:** `context.pdf_path`
- **Outputs:** `context.raw_text`
- **LLM used:** No. Delegates to `pdf_service.extract_text_from_pdf()` (PyMuPDF).
- **Fallback:** If PyMuPDF returns `[OCR_REQUIRED]`, the agent sets `context.raw_text` to the placeholder string and marks the result with `notes="ocr_required"`. Subsequent agents handle the degraded state gracefully.
- **Redo-able:** No. PDF content does not change between iterations; the Judge will never target this agent.

#### IOCExtractorAgent (`app/agents/ioc_extractor.py`)

- **Inputs:** `context.raw_text`, `context.judge_feedback` (for redo hints)
- **Outputs:** `context.iocs` (list of normalized IOC dicts, enriched)
- **LLM used:** Yes — structured extraction prompt extracting all IOC types: network indicators (IPs, domains, URLs), file artefacts (hashes, paths), and contextual indicators (mutexes, user agents, service names, process names, behavioural indicators).
- **Post-processing:** `ioc_filter_service.filter_iocs()` and `virustotal_service.enrich_ip()` applied to the LLM output.
- **Redo behaviour:** On redo the agent re-runs the full extraction. The Judge critique is appended to the LLM user prompt as additional context: *"Previous extraction was critiqued as follows: {critique}. Ensure you address these gaps."*

#### MITREAgent (`app/agents/mitre_agent.py`)

- **Inputs:** `context.raw_text`, `context.judge_feedback`
- **Outputs:** `context.mitre_mappings`
- **LLM used:** Yes — structured mapping prompt returning `technique_id`, `technique_name`, `tactic`, `evidence`, `confidence`.
- **Redo behaviour:** Judge critique injected into user prompt on redo.

#### SigmaRuleAgent (`app/agents/sigma_agent.py`)

- **Inputs:** `context.raw_text`, `context.iocs`, `context.mitre_mappings`, `context.judge_feedback`
- **Outputs:** `context.sigma_rules`
- **LLM used:** Yes — prompt acts as a detection engineer generating valid Sigma YAML. Each rule is validated with `yaml.safe_load()` and checked for required keys (`title`, `detection`). Rules that fail validation are discarded and the agent is flagged for redo by the Judge.
- **Redo behaviour:** Judge critique + list of rejected/invalid rule titles injected into redo prompt.

#### ReportGeneratorAgent (`app/agents/report_generator.py`)

- **Inputs:** `context.raw_text`, `context.overview`, `context.iocs`, `context.mitre_mappings`, `context.sigma_rules`, `context.judge_feedback`
- **Outputs:** `context.report_markdown`
- **LLM used:** Yes — prompt produces a structured Markdown report for a SOC analyst containing:
  - Executive summary
  - Threat actor / campaign overview
  - IOC table (type, value, confidence, enrichment)
  - MITRE ATT&CK technique table with evidence
  - Sigma rule index (title, severity, MITRE tags)
  - Detection recommendations
  - Analyst notes
- **Redo behaviour:** Judge critique injected; specific sections flagged for revision.

> **Note:** This agent replaces and supersedes `generate_overview_with_llm()` in `llm_service.py`. The overview JSON currently stored in `report.summary` will now be derived from the `ReportGeneratorAgent` output. The `overview` sub-field in context is populated from the existing `llm_service.generate_overview_with_llm()` call during the first pass and retained across iterations (the overview is not re-generated unless the Judge flags `ReportGeneratorAgent`).

#### JudgeAgent (`app/agents/judge.py`)

- **Inputs:** All of `context` (full state)
- **Outputs:** `JudgeVerdict`
- **LLM used:** Yes — evaluation prompt provides the source PDF text, all agent outputs, and the accuracy threshold. The LLM responds with structured JSON.
- **Error handling:** If the Judge LLM call fails entirely (network error, provider outage, malformed response), the supervisor treats the current iteration as passed (score = 100), logs a `JUDGE_CALL_FAILED` warning, and returns the best context achieved. This prevents a Judge-side failure from permanently blocking report processing.

**Judge prompt design:**

```
System:
  You are an expert cyber threat intelligence quality auditor.
  Your role is to evaluate the accuracy and completeness of analysis
  artifacts produced from a threat intelligence report.

User:
  SOURCE MATERIAL (truncated to {MAX_CHARS} chars):
  {context.raw_text}

  PRODUCED ARTIFACTS:
  --- IOCs ---
  {json(context.iocs)}
  --- MITRE Mappings ---
  {json(context.mitre_mappings)}
  --- Sigma Rules ---
  {context.sigma_rules[*].rule_content joined}
  --- SOC Report ---
  {context.report_markdown}

  Evaluate each artifact against the source material.
  Return JSON matching the schema provided.
```

**Judge response schema:**

```json
{
  "score": <float 0-100>,
  "passed": <bool>,
  "failed_agents": [<"IOCExtractorAgent" | "MITREAgent" | "SigmaRuleAgent" | "ReportGeneratorAgent">],
  "critique": "<plain-English explanation of all inaccuracies and gaps>",
  "ioc_issues": "<specific IOC problems>",
  "mitre_issues": "<specific MITRE mapping problems>",
  "sigma_issues": "<specific Sigma rule problems>",
  "report_issues": "<specific report problems>"
}
```

**Accuracy threshold:** `JUDGE_PASS_SCORE` env var, default `90.0`.  
**Maximum iterations:** `JUDGE_MAX_ITERATIONS` env var, default `3`.

---

### 4.4 Supervisor (`app/agents/supervisor.py`)

```python
class AgentSupervisor:
    def __init__(self, provider: LLMProvider):
        self.provider = provider
        self.pass_score = float(os.getenv("JUDGE_PASS_SCORE", "90.0"))
        self.max_iterations = int(os.getenv("JUDGE_MAX_ITERATIONS", "3"))
        self._agents = [
            PDFReaderAgent(provider),
            IOCExtractorAgent(provider),
            MITREAgent(provider),
            SigmaRuleAgent(provider),
            ReportGeneratorAgent(provider),
        ]
        self._judge = JudgeAgent(provider)

    def run(self, report_id: int, pdf_path: str, db: Session) -> AgentContext:
        context = AgentContext(report_id=report_id, pdf_path=pdf_path)
        agents_to_run = set(a.name for a in self._agents)

        for iteration in range(1, self.max_iterations + 1):
            context.iteration = iteration
            for agent in self._agents:
                if agent.name in agents_to_run:
                    result = agent.run(context)
                    _log_agent_run(db, report_id, agent.name, iteration, result)

            verdict = self._judge.run(context)
            _log_agent_run(db, report_id, self._judge.name, iteration, verdict)
            context.judge_feedback = verdict

            if verdict.passed or iteration == self.max_iterations:
                break

            agents_to_run = set(verdict.failed_agents)

        return context
```

**Key supervisor behaviours:**

1. `PDFReaderAgent` is always in the initial `agents_to_run` set but is **never** added back to a redo set — its output is immutable once extracted.
2. The supervisor logs each agent's run to a new `AgentRun` DB table (see §5) so the full iteration history is auditable.
3. After the loop the supervisor does **not** persist results to the database itself; `main.py` receives the final `AgentContext` and handles all ORM writes — this keeps the supervisor free of database concerns.
4. If `max_iterations` is reached without passing, the supervisor returns the best context achieved (the most recent one) and logs a `JUDGE_MAX_ITERATIONS_REACHED` warning.

---

## 5. Database Changes

### 5.1 New Table: `agent_runs`

Tracks every agent execution per report per iteration. Additive migration only; existing tables are unmodified.

```python
class AgentRun(Base):
    __tablename__ = "agent_runs"
    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(Integer, ForeignKey("reports.id"), nullable=False)
    agent_name = Column(String, nullable=False)
    iteration = Column(Integer, nullable=False)
    success = Column(Boolean, default=True)
    notes = Column(Text, nullable=True)
    score = Column(Float, nullable=True)        # populated for JudgeAgent runs
    critique = Column(Text, nullable=True)      # populated for JudgeAgent runs
    created_at = Column(DateTime, default=datetime.utcnow)
    report = relationship("Report", back_populates="agent_runs")
```

### 5.2 Additive Columns on `reports`

| Column | Type | Purpose |
|---|---|---|
| `judge_score` | `Float` | Final Judge score from last iteration |
| `judge_iterations` | `Integer` | Number of judge iterations performed |
| `agent_run_log` | `Text` (JSON) | Compact run summary for API exposure |

These columns are added via the existing `ensure_sqlite_columns()` pattern in `main.py` (safe, idempotent, dev-friendly migration).

### 5.3 `Report` Model Update

```python
agent_runs = relationship("AgentRun", back_populates="report", cascade="all, delete-orphan")
```

---

## 6. API Changes

### 6.1 Modified Endpoint

**`POST /reports/{report_id}/process`** — internal implementation replaced; request/response contract unchanged.

Before:
```python
text = extract_text_from_pdf(...)
iocs = extract_iocs(text)
mappings = map_mitre(text)
rules = generate_sigma_rules(iocs, mappings, text)
```

After:
```python
supervisor = AgentSupervisor(get_provider())
context = supervisor.run(report_id, report.file_path, db)
# persist context.iocs, context.mitre_mappings, etc. to DB models
```

The `ReportDetail` response schema is unchanged.

### 6.2 New Endpoints

**`GET /reports/{report_id}/agent-runs`**  
Returns the full `AgentRun` history for a report. Useful for debugging and supervisor review.

Response schema:
```json
[
  {
    "id": 1,
    "agent_name": "PDFReaderAgent",
    "iteration": 1,
    "success": true,
    "notes": "",
    "score": null,
    "critique": null,
    "created_at": "2026-06-05T12:00:00"
  },
  {
    "id": 6,
    "agent_name": "JudgeAgent",
    "iteration": 1,
    "success": true,
    "notes": "",
    "score": 72.5,
    "critique": "IOC extraction missed three mutex indicators...",
    "created_at": "2026-06-05T12:00:05"
  }
]
```

**`GET /reports/{report_id}/report-md`**  
Returns the SOC analyst report as `text/markdown`. Exposes `context.report_markdown` that the `ReportGeneratorAgent` produces. (This content is also included in the ZIP export — see §7.)

---

## 7. Export Changes

`export_service.py` will be updated to include `soc_report.md` (the `ReportGeneratorAgent` output) in the ZIP alongside the existing `iocs.csv`, `mitre_mapping.yaml`, Sigma YAML files, and ATT&CK Navigator layer.

The `report.summary` field will continue to store the JSON overview for frontend rendering. `report_markdown` will be stored in a new `report.report_markdown` column (Text, additive migration).

---

## 8. New Environment Variables

The following variables are added to `.env.example`. Existing variables are unchanged.

```env
# ── Agent Supervisor ──────────────────────────────────────────────────────────
# Minimum Judge score (0-100) required to accept pipeline output.
JUDGE_PASS_SCORE=90.0

# Maximum number of judge-supervised iterations before accepting best result.
JUDGE_MAX_ITERATIONS=3
```

---

## 9. Dependency Changes (`requirements.txt`)

| Package | Change | Reason |
|---|---|---|
| `anthropic>=0.28.0` | Add | Anthropic Claude provider |
| `openai>=1.99.0` | Keep | OpenAI provider (already present) |

Groq, Fireworks, and Ollama providers use either the `openai` SDK (OpenAI-compatible endpoints) or the stdlib `urllib` (Ollama REST), so no additional packages are required for those providers.

---

## 10. File Structure (to-be)

```
backend/app/
├── main.py                        (modified — process route uses supervisor)
├── models.py                      (modified — AgentRun model added)
├── schemas.py                     (modified — AgentRunOut schema added)
├── database.py                    (unchanged)
├── agents/
│   ├── __init__.py
│   ├── base.py                    (NEW — BaseAgent, AgentContext, AgentResult, JudgeVerdict)
│   ├── pdf_reader.py              (NEW — PDFReaderAgent)
│   ├── ioc_extractor.py           (NEW — IOCExtractorAgent)
│   ├── mitre_agent.py             (NEW — MITREAgent)
│   ├── sigma_agent.py             (NEW — SigmaRuleAgent)
│   ├── report_generator.py        (NEW — ReportGeneratorAgent)
│   ├── judge.py                   (NEW — JudgeAgent)
│   └── supervisor.py              (NEW — AgentSupervisor)
├── providers/
│   ├── __init__.py
│   ├── base.py                    (NEW — LLMProvider ABC, LLMMessage, LLMProviderError)
│   ├── openai_provider.py         (NEW — OpenAIProvider)
│   ├── anthropic_provider.py      (NEW — AnthropicProvider)
│   ├── groq_provider.py           (NEW — GroqProvider)
│   ├── fireworks_provider.py      (NEW — FireworksProvider)
│   ├── ollama_provider.py         (NEW — OllamaProvider)
│   └── factory.py                 (NEW — get_provider())
└── services/
    ├── pdf_service.py             (unchanged — text extraction helper)
    ├── ioc_service.py             (modified — reduced to IOC normalisation helper only; all extraction removed)
    ├── mitre_service.py           (REMOVED — fully superseded by MITREAgent)
    ├── rule_service.py            (REMOVED — fully superseded by SigmaRuleAgent)
    ├── export_service.py          (modified — adds soc_report.md to ZIP)
    ├── ioc_filter_service.py      (unchanged)
    ├── virustotal_service.py      (unchanged)
    └── llm_service.py             (modified — call_json() delegates to provider factory;
                                              direct OpenAI client removed;
                                              schema constants and test_llm_connection() retained)
```

---

## 11. Implementation Phases

### Phase 1 — Provider Abstraction (no breaking changes)
1. Create `app/providers/base.py` with `LLMProvider` ABC, `LLMMessage`, `LLMProviderError`.
2. Implement `OpenAIProvider` wrapping current `openai.OpenAI` logic from `llm_service.py`.
3. Implement `AnthropicProvider`, `GroqProvider`, `FireworksProvider`, `OllamaProvider`.
4. Create `factory.py` with `get_provider()`.
5. Refactor `llm_service.call_json()` to delegate to `get_provider().complete()` internally.
6. Add `anthropic` to `requirements.txt`.
7. **Test:** `LLM_PROVIDER=openai` path executes successfully; switch to `LLM_PROVIDER=ollama` and verify the Ollama path executes.

### Phase 2 — Agent Base + Non-LLM Agents
1. Create `app/agents/__init__.py`, `base.py` (all dataclasses and `BaseAgent`).
2. Implement `PDFReaderAgent` (delegates to `pdf_service`).
3. Implement `AgentSupervisor` skeleton (no Judge, single-pass, no redo logic yet).
4. Replace the imperative service calls in `POST /reports/{id}/process` with the supervisor directly.
5. **Test:** Single-pass supervisor run produces a correctly populated `AgentContext`; verify DB persistence maps correctly to the existing response schema.

### Phase 3 — LLM Agents
1. Implement `IOCExtractorAgent` — all IOC extraction logic (previously split across `ioc_service.py` and `llm_service.py`) consolidated into the agent; `ioc_service.py` reduced to the IOC normalisation helper only.
2. Implement `MITREAgent` — all MITRE mapping logic consolidated into the agent; `mitre_service.py` removed.
3. Implement `SigmaRuleAgent` — all Sigma generation logic consolidated into the agent; `rule_service.py` removed.
4. Implement `ReportGeneratorAgent` — new LLM prompt producing SOC Markdown report; moves `generate_overview_with_llm()` as a sub-task.
5. Update `main.py` process route to use supervisor for agent persistence.
6. Add `AgentRun` model and additive DB migration.
7. **Test:** Full pipeline with all four LLM agents; verify context is correctly populated.

### Phase 4 — Judge Agent + Iteration Loop
1. Implement `JudgeAgent` with structured scoring prompt and `JudgeVerdict` output.
2. Add full iteration logic to `AgentSupervisor.run()` (redo set tracking, critique injection, max-iteration cap).
3. Add `JUDGE_PASS_SCORE` and `JUDGE_MAX_ITERATIONS` to `.env.example`.
4. Add `GET /reports/{id}/agent-runs` endpoint.
5. **Test:** Upload a report with a known ground truth; confirm Judge triggers redo when score < 90; confirm it converges and terminates correctly.

### Phase 5 — Cleanup & Export
1. Remove `ioc_service.py` (superseded), `mitre_service.py` (superseded), and `rule_service.py` (superseded). Update all import sites.
2. Strip `llm_service.py` to schema constants and `test_llm_connection()` only.
3. Update `export_service.py` to include `soc_report.md` in ZIP.
4. Add `GET /reports/{id}/report-md` endpoint.
5. Add `report_markdown` and `judge_score` / `judge_iterations` columns via `ensure_sqlite_columns()`.
6. Update `README.md` to document the new agent architecture and new env vars.

---

## 12. Backward Compatibility Guarantees

| Concern | Guarantee |
|---|---|
| Existing API response schemas | Unchanged — same paths, methods, and JSON response shapes. Frontend requires no changes. |
| New or modified API routes | Permitted — new endpoints may be added; internal implementation of existing endpoints may change freely |
| Existing SQLite databases | Additive column/table migrations only; no destructive schema changes |
| Export ZIP format | Backward compatible; `soc_report.md` is a new addition only |
| `.env` files | All existing variables remain; new variables are optional with safe defaults |
| LLM provider requirement | **A valid LLM API key is now required.** The application will return an error if no provider is configured and a process request is received. |

---

## 13. Risk Register

| Risk | Likelihood | Mitigation |
|---|---|---|
| Judge LLM call is expensive (large context) | Medium | Text truncated to `LLM_MAX_REPORT_CHARS`; Judge prompt uses compact JSON serialisation of artifacts |
| Judge enters infinite loop | Low | Hard cap via `JUDGE_MAX_ITERATIONS`; supervisor always terminates |
| Provider abstraction adds latency | Low | `get_provider()` instantiated once per request; no per-call overhead |
| Anthropic/Groq JSON schema support differs from OpenAI | Medium | Each provider implements its own schema-to-format mapping; integration tested per provider |
| No LLM API key configured | High (intentional) | Application now requires a provider; startup health check at `GET /health` reports provider status. Operators must configure a valid `LLM_PROVIDER` and corresponding API key before processing reports. |
| SQLite migration on first run fails | Low | `ensure_sqlite_columns()` pattern already proven in codebase; new columns follow same pattern |

---

## 14. Out of Scope

The following are explicitly excluded from this refactoring and remain as listed in the existing README's "Current Limitations" and "Next serious upgrade" sections:

- OCR support for scanned PDFs
- VirusTotal enrichment for domain, URL, hash IOC types (only IP enrichment is currently implemented)
- User authentication
- Production deployment configuration
- Frontend changes
- Async/background processing (Celery, ARQ, etc.) — the processing endpoint remains synchronous
- Parallel agent execution

---

*End of plan. Awaiting supervisor review before Phase 1 implementation begins.*
