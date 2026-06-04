import logging
import os
import time
from typing import Any, Dict, List, Optional

from .base import LLMMessage, LLMProvider, LLMProviderError

logger = logging.getLogger("ruleforge.providers.fireworks")


class FireworksProvider(LLMProvider):
    """Fireworks AI provider — OpenAI-compatible endpoint (https://api.fireworks.ai/inference/v1)."""

    def __init__(self) -> None:
        try:
            from openai import OpenAI as _OpenAI
        except ImportError as exc:
            raise LLMProviderError(
                "openai package is not installed. Run: pip install openai"
            ) from exc

        api_key = os.getenv("FIREWORKS_API_KEY", "")
        if not api_key:
            raise LLMProviderError(
                "FIREWORKS_API_KEY is not set. Configure it in backend/.env"
            )

        timeout = float(os.getenv("LLM_TIMEOUT_SECONDS", "60"))
        self._client = _OpenAI(
            api_key=api_key,
            base_url="https://api.fireworks.ai/inference/v1",
            timeout=timeout,
        )
        self._model = os.getenv(
            "FIREWORKS_MODEL",
            "accounts/fireworks/models/llama-v3p1-70b-instruct",
        )
        logger.info("FireworksProvider initialised model=%s", self._model)

    def complete(
        self,
        messages: List[LLMMessage],
        json_schema: Optional[Dict[str, Any]] = None,
        temperature: float = 0.1,
    ) -> str:
        # Fireworks supports json_object mode; strict json_schema not universally supported
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
                "Fireworks call success elapsed_ms=%s output_chars=%s",
                elapsed_ms,
                len(content),
            )
            return content
        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - started) * 1000)
            logger.exception(
                "Fireworks call failed elapsed_ms=%s error=%s", elapsed_ms, exc
            )
            raise LLMProviderError(f"Fireworks call failed: {exc}") from exc
