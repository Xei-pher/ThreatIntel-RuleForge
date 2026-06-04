import logging
import os
import time
from typing import Any, Dict, List, Optional

from .base import LLMMessage, LLMProvider, LLMProviderError

logger = logging.getLogger("ruleforge.providers.openai")


class OpenAIProvider(LLMProvider):
    """OpenAI provider — GPT-4o, GPT-4.1-mini, etc."""

    def __init__(self) -> None:
        try:
            from openai import OpenAI as _OpenAI
        except ImportError as exc:
            raise LLMProviderError(
                "openai package is not installed. Run: pip install openai"
            ) from exc

        api_key = os.getenv("OPENAI_API_KEY", "")
        if not api_key:
            raise LLMProviderError(
                "OPENAI_API_KEY is not set. Configure it in backend/.env"
            )

        timeout = float(os.getenv("LLM_TIMEOUT_SECONDS", "60"))
        self._client = _OpenAI(api_key=api_key, timeout=timeout)
        self._model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        logger.info("OpenAIProvider initialised model=%s", self._model)

    def complete(
        self,
        messages: List[LLMMessage],
        json_schema: Optional[Dict[str, Any]] = None,
        temperature: float = 0.1,
    ) -> str:
        if json_schema:
            response_format: Dict[str, Any] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "ruleforge_response",
                    "strict": True,
                    "schema": json_schema,
                },
            }
        else:
            response_format = {"type": "json_object"}

        started = time.perf_counter()
        try:
            response = self._client.chat.completions.create(
                model=self._model,
                temperature=temperature,
                response_format=response_format,
                messages=[{"role": m.role, "content": m.content} for m in messages],
            )
            elapsed_ms = round((time.perf_counter() - started) * 1000)
            content = response.choices[0].message.content or "{}"
            logger.info(
                "OpenAI call success elapsed_ms=%s output_chars=%s",
                elapsed_ms,
                len(content),
            )
            return content
        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - started) * 1000)
            logger.exception(
                "OpenAI call failed elapsed_ms=%s error=%s", elapsed_ms, exc
            )
            raise LLMProviderError(f"OpenAI call failed: {exc}") from exc
