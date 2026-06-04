import json
import logging
import os
import time
from typing import Any, Dict, List, Optional
from urllib.error import URLError
from urllib.request import Request, urlopen

from .base import LLMMessage, LLMProvider, LLMProviderError

logger = logging.getLogger("ruleforge.providers.ollama")


class OllamaProvider(LLMProvider):
    """Ollama local provider via the Ollama HTTP REST API (/api/chat)."""

    def __init__(self) -> None:
        self._base_url = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
        self._model = os.getenv("OLLAMA_MODEL", "llama3.1")
        self._timeout = float(os.getenv("LLM_TIMEOUT_SECONDS", "60"))
        logger.info(
            "OllamaProvider initialised base_url=%s model=%s",
            self._base_url,
            self._model,
        )

    def complete(
        self,
        messages: List[LLMMessage],
        json_schema: Optional[Dict[str, Any]] = None,
        temperature: float = 0.1,
    ) -> str:
        payload = {
            "model": self._model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "stream": False,
            "options": {"temperature": temperature},
            "format": "json",
        }
        body = json.dumps(payload).encode("utf-8")
        req = Request(
            f"{self._base_url}/api/chat",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        started = time.perf_counter()
        try:
            with urlopen(req, timeout=self._timeout) as response:
                raw = response.read().decode("utf-8")
            data = json.loads(raw)
            content = data.get("message", {}).get("content", "{}")
            elapsed_ms = round((time.perf_counter() - started) * 1000)
            logger.info(
                "Ollama call success elapsed_ms=%s output_chars=%s",
                elapsed_ms,
                len(content),
            )
            return content
        except (URLError, json.JSONDecodeError) as exc:
            elapsed_ms = round((time.perf_counter() - started) * 1000)
            logger.exception(
                "Ollama call failed elapsed_ms=%s error=%s", elapsed_ms, exc
            )
            raise LLMProviderError(f"Ollama call failed: {exc}") from exc
        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - started) * 1000)
            logger.exception(
                "Ollama unexpected error elapsed_ms=%s error=%s", elapsed_ms, exc
            )
            raise LLMProviderError(f"Ollama call failed: {exc}") from exc
