import logging
import os
import time
from typing import Any, Dict, List, Optional

from .base import LLMMessage, LLMProvider, LLMProviderError

logger = logging.getLogger("ruleforge.providers.groq")


class GroqProvider(LLMProvider):
    """Groq provider — OpenAI-compatible endpoint (https://api.groq.com/openai/v1)."""

    def __init__(self) -> None:
        try:
            from openai import OpenAI as _OpenAI
        except ImportError as exc:
            raise LLMProviderError(
                "openai package is not installed. Run: pip install openai"
            ) from exc

        api_key = os.getenv("GROQ_API_KEY", "")
        if not api_key:
            raise LLMProviderError(
                "GROQ_API_KEY is not set. Configure it in backend/.env"
            )

        timeout = float(os.getenv("LLM_TIMEOUT_SECONDS", "60"))
        self._client = _OpenAI(
            api_key=api_key,
            base_url="https://api.groq.com/openai/v1",
            timeout=timeout,
        )
        self._model = os.getenv("GROQ_MODEL", "llama-3.1-70b-versatile")
        logger.info("GroqProvider initialised model=%s", self._model)

    def complete(
        self,
        messages: List[LLMMessage],
        json_schema: Optional[Dict[str, Any]] = None,
        temperature: float = 0.1,
    ) -> str:
        # Groq supports json_object mode but not strict json_schema; schema is ignored
        started = time.perf_counter()
        try:
            response = self._client.chat.completions.create(
                model=self._model,
                temperature=temperature,
                response_format={"type": "json_object"},
                messages=[{"role": m.role, "content": m.content} for m in messages],
            )
            elapsed_ms = round((time.perf_counter() - started) * 1000)
            content = response.choices[0].message.content or "{}"
            logger.info(
                "Groq call success elapsed_ms=%s output_chars=%s", elapsed_ms, len(content)
            )
            return content
        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - started) * 1000)
            logger.exception(
                "Groq call failed elapsed_ms=%s error=%s", elapsed_ms, exc
            )
            raise LLMProviderError(f"Groq call failed: {exc}") from exc
