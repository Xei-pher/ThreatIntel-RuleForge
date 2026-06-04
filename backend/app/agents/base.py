import json
import logging
import os
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

logger = logging.getLogger("ruleforge.agents")

MAX_REPORT_CHARS: int = int(os.getenv("LLM_MAX_REPORT_CHARS", "60000"))
LLM_DEBUG: bool = os.getenv("LLM_DEBUG", "false").lower() in {"1", "true", "yes", "y"}

# Rate-limit retry settings
_RATE_LIMIT_MAX_RETRIES: int = int(os.getenv("LLM_RATE_LIMIT_MAX_RETRIES", "4"))
_RATE_LIMIT_INITIAL_WAIT: float = float(os.getenv("LLM_RATE_LIMIT_INITIAL_WAIT", "5.0"))
_RATE_LIMIT_BACKOFF_FACTOR: float = float(os.getenv("LLM_RATE_LIMIT_BACKOFF_FACTOR", "2.0"))
_RATE_LIMIT_MAX_WAIT: float = float(os.getenv("LLM_RATE_LIMIT_MAX_WAIT", "60.0"))


def _is_rate_limit_error(exc: Exception) -> bool:
    """Return True when the exception looks like an API rate-limit / quota error."""
    msg = str(exc).lower()
    # Common signal words across OpenAI, Anthropic, Groq, Fireworks
    rate_limit_signals = (
        "rate limit",
        "rate_limit",
        "ratelimit",
        "429",
        "too many requests",
        "quota",
        "requests per minute",
        "requests per day",
        "tokens per minute",
        "tokens per day",
        "capacity",
        "overloaded",
        "retry after",
    )
    return any(signal in msg for signal in rate_limit_signals)


# ---------------------------------------------------------------------------
# Shared data structures
# ---------------------------------------------------------------------------


@dataclass
class JudgeVerdict:
    """Verdict returned by the JudgeAgent after evaluating a pipeline iteration."""

    score: float           # 0.0 – 100.0
    passed: bool           # True when score >= JUDGE_PASS_SCORE
    failed_agents: List[str]   # agent names requiring redo
    critique: str          # overall human-readable explanation
    ioc_issues: str
    mitre_issues: str
    sigma_issues: str
    report_issues: str
    iteration: int


@dataclass
class AgentContext:
    """Mutable shared state passed through the agent pipeline by the supervisor."""

    report_id: int
    pdf_path: str
    raw_text: str = ""
    iocs: List[Dict] = field(default_factory=list)
    mitre_mappings: List[Dict] = field(default_factory=list)
    sigma_rules: List[Dict] = field(default_factory=list)
    report_markdown: str = ""
    overview: Dict = field(default_factory=dict)
    judge_feedback: Optional[JudgeVerdict] = None
    iteration: int = 0


@dataclass
class AgentResult:
    """Result produced by a non-judge agent after ``run()``."""

    agent_name: str
    success: bool
    output: Any
    notes: str = ""


# ---------------------------------------------------------------------------
# JSON parsing helper
# ---------------------------------------------------------------------------


def _safe_json_loads(content: str) -> Any:
    """Parse JSON from model output, stripping any surrounding prose."""
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        # Try to extract the first {...} or [...] block
        for open_ch, close_ch in [("{", "}"), ("[", "]")]:
            start = content.find(open_ch)
            end = content.rfind(close_ch)
            if start != -1 and end != -1 and end > start:
                try:
                    return json.loads(content[start: end + 1])
                except json.JSONDecodeError:
                    pass
        raise


# ---------------------------------------------------------------------------
# Base agent
# ---------------------------------------------------------------------------


class BaseAgent:
    """Abstract base for all pipeline agents."""

    name: str = "base"

    def __init__(self, provider: Any) -> None:
        self._provider = provider

    def run(self, context: AgentContext) -> AgentResult:
        raise NotImplementedError

    def _call_llm(
        self,
        system: str,
        user: str,
        fallback: Any,
        task_name: str,
        schema: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Call the configured LLM provider and return parsed JSON.

        Automatically retries on rate-limit / quota errors using exponential
        backoff (controlled by LLM_RATE_LIMIT_* env vars).  On any
        non-retriable error, or after all retries are exhausted, the
        ``fallback`` value is returned so the pipeline is not blocked.
        """
        from ..providers.base import LLMMessage, LLMProviderError

        messages = [
            LLMMessage(role="system", content=system),
            LLMMessage(role="user", content=user[:MAX_REPORT_CHARS]),
        ]

        wait = _RATE_LIMIT_INITIAL_WAIT
        attempt = 0

        while True:
            attempt += 1
            started = time.perf_counter()
            logger.info(
                "Agent %s task=%s LLM call attempt=%d", self.name, task_name, attempt
            )
            try:
                raw = self._provider.complete(messages, json_schema=schema)
                elapsed_ms = round((time.perf_counter() - started) * 1000)
                logger.info(
                    "Agent %s task=%s LLM success attempt=%d elapsed_ms=%s output_chars=%s",
                    self.name,
                    task_name,
                    attempt,
                    elapsed_ms,
                    len(raw),
                )
                if LLM_DEBUG:
                    logger.debug(
                        "Agent %s task=%s raw output: %s",
                        self.name,
                        task_name,
                        raw[:4000],
                    )
                return _safe_json_loads(raw)

            except Exception as exc:
                elapsed_ms = round((time.perf_counter() - started) * 1000)

                if _is_rate_limit_error(exc) and attempt <= _RATE_LIMIT_MAX_RETRIES:
                    capped_wait = min(wait, _RATE_LIMIT_MAX_WAIT)
                    logger.warning(
                        "Agent %s task=%s rate-limit hit attempt=%d/%d — "
                        "retrying in %.1fs (error: %s)",
                        self.name,
                        task_name,
                        attempt,
                        _RATE_LIMIT_MAX_RETRIES,
                        capped_wait,
                        exc,
                    )
                    time.sleep(capped_wait)
                    wait = min(wait * _RATE_LIMIT_BACKOFF_FACTOR, _RATE_LIMIT_MAX_WAIT)
                    continue

                logger.exception(
                    "Agent %s task=%s LLM failed attempt=%d elapsed_ms=%s error=%s",
                    self.name,
                    task_name,
                    attempt,
                    elapsed_ms,
                    exc,
                )
                return fallback
