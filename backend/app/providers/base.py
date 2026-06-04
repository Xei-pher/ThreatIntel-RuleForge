from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


class LLMProviderError(Exception):
    """Raised when a provider call fails unrecoverably."""


@dataclass
class LLMMessage:
    role: str   # "system" | "user" | "assistant"
    content: str


class LLMProvider(ABC):
    """Minimal interface every provider adapter must implement.

    Contract:
    - ``complete()`` always returns a raw string. JSON parsing is the caller's responsibility.
    - On any unrecoverable API / network error the provider raises ``LLMProviderError``.
    - Each provider reads its own env vars (OPENAI_API_KEY, ANTHROPIC_API_KEY, etc.).
    - ``json_schema`` is a structured output / response-format hint. Providers that do not
      support strict structured output may use it as a prompt hint and ignore the schema
      enforcement, but must still return JSON.
    """

    @abstractmethod
    def complete(
        self,
        messages: List[LLMMessage],
        json_schema: Optional[Dict[str, Any]] = None,
        temperature: float = 0.1,
    ) -> str:
        """Call the LLM and return the raw response string.

        Args:
            messages: Ordered conversation messages (system, user, …).
            json_schema: Optional JSON Schema dict requesting structured output.
            temperature: Sampling temperature; default 0.1 for deterministic outputs.

        Returns:
            Raw string content from the model (expected to be JSON).

        Raises:
            LLMProviderError: On any unrecoverable API or network error.
        """
        ...
