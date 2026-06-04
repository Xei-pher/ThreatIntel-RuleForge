"""llm_service.py — Minimal LLM status and health-check utilities.

All LLM inference logic has been moved to the agent layer (app/agents/).
This module retains only the status helpers used by the /health and /llm/health
API endpoints.
"""
import json
import logging
import os
from typing import Any, Dict

from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("ruleforge.llm")


def _mask_key(key: str) -> str:
    if not key:
        return "missing"
    if len(key) <= 12:
        return "set-but-too-short"
    return f"{key[:7]}...{key[-4:]}"


def llm_status() -> Dict[str, Any]:
    """Return a provider-agnostic LLM configuration summary for the health endpoint."""
    provider = os.getenv("LLM_PROVIDER", "openai").lower()
    key_env_map = {
        "openai": "OPENAI_API_KEY",
        "anthropic": "ANTHROPIC_API_KEY",
        "groq": "GROQ_API_KEY",
        "fireworks": "FIREWORKS_API_KEY",
        "ollama": None,  # Ollama is local; no API key required
    }
    model_env_map = {
        "openai": ("OPENAI_MODEL", "gpt-4o-mini"),
        "anthropic": ("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022"),
        "groq": ("GROQ_MODEL", "llama-3.1-70b-versatile"),
        "fireworks": ("FIREWORKS_MODEL", "accounts/fireworks/models/llama-v3p1-70b-instruct"),
        "ollama": ("OLLAMA_MODEL", "llama3.1"),
    }
    key_env = key_env_map.get(provider)
    api_key = os.getenv(key_env, "") if key_env else "n/a (local)"
    enabled = bool(api_key) if key_env else True  # Ollama needs no key

    model_env, model_default = model_env_map.get(provider, ("", "unknown"))
    model = os.getenv(model_env, model_default) if model_env else model_default

    return {
        "provider": provider,
        "enabled": enabled,
        "api_key": _mask_key(api_key) if key_env else "n/a",
        "model": model,
        "max_report_chars": int(os.getenv("LLM_MAX_REPORT_CHARS", "60000")),
        "timeout_seconds": float(os.getenv("LLM_TIMEOUT_SECONDS", "60")),
        "debug": os.getenv("LLM_DEBUG", "false").lower() in {"1", "true", "yes", "y"},
    }


def test_llm_connection() -> Dict[str, Any]:
    """Attempt a minimal LLM call and return a status dict for the /llm/health endpoint."""
    status = llm_status()
    if not status["enabled"]:
        return {
            **status,
            "ok": False,
            "error": f"LLM provider '{status['provider']}' is disabled or missing API key.",
        }
    try:
        from ..providers.factory import get_provider
        from ..providers.base import LLMMessage

        provider = get_provider()
        raw = provider.complete(
            messages=[
                LLMMessage(role="system", content="Return JSON only."),
                LLMMessage(
                    role="user",
                    content='Return exactly this JSON: {"ok": true, "message": "llm reachable"}',
                ),
            ],
            json_schema={
                "type": "object",
                "properties": {
                    "ok": {"type": "boolean"},
                    "message": {"type": "string"},
                },
                "required": ["ok", "message"],
                "additionalProperties": False,
            },
        )
        data = json.loads(raw)
        return {**status, **data}
    except Exception as exc:
        logger.exception("LLM health check failed: %s", exc)
        return {**status, "ok": False, "error": str(exc)}
