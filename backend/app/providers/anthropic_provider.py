import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

from .base import LLMMessage, LLMProvider, LLMProviderError

logger = logging.getLogger("ruleforge.providers.anthropic")


class AnthropicProvider(LLMProvider):
    """Anthropic Claude provider."""

    def __init__(self) -> None:
        try:
            import anthropic as _anthropic
            self._anthropic = _anthropic
        except ImportError as exc:
            raise LLMProviderError(
                "anthropic package is not installed. Run: pip install anthropic"
            ) from exc

        api_key = os.getenv("ANTHROPIC_API_KEY", "")
        if not api_key:
            raise LLMProviderError(
                "ANTHROPIC_API_KEY is not set. Configure it in backend/.env"
            )

        timeout = float(os.getenv("LLM_TIMEOUT_SECONDS", "60"))
        self._client = _anthropic.Anthropic(api_key=api_key, timeout=timeout)
        self._model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
        logger.info("AnthropicProvider initialised model=%s", self._model)

    def complete(
        self,
        messages: List[LLMMessage],
        json_schema: Optional[Dict[str, Any]] = None,
        temperature: float = 0.1,
    ) -> str:
        # Anthropic separates system messages from the conversation
        system_content = ""
        user_messages = []
        for m in messages:
            if m.role == "system":
                system_content = m.content
            else:
                user_messages.append({"role": m.role, "content": m.content})

        # Inject JSON schema hint into the last user message (Anthropic lacks response_format)
        if user_messages:
            if json_schema:
                hint = (
                    f"\n\nYou MUST respond with valid JSON only that conforms exactly to this schema:\n"
                    f"{json.dumps(json_schema, indent=2)}"
                )
            else:
                hint = "\n\nRespond with valid JSON only."
            user_messages[-1]["content"] += hint

        started = time.perf_counter()
        try:
            response = self._client.messages.create(
                model=self._model,
                max_tokens=8096,
                temperature=temperature,
                system=system_content,
                messages=user_messages,
            )
            elapsed_ms = round((time.perf_counter() - started) * 1000)
            content = response.content[0].text if response.content else "{}"
            logger.info(
                "Anthropic call success elapsed_ms=%s output_chars=%s",
                elapsed_ms,
                len(content),
            )
            return content
        except Exception as exc:
            elapsed_ms = round((time.perf_counter() - started) * 1000)
            logger.exception(
                "Anthropic call failed elapsed_ms=%s error=%s", elapsed_ms, exc
            )
            raise LLMProviderError(f"Anthropic call failed: {exc}") from exc
