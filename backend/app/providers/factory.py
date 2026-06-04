import logging
import os

from .base import LLMProvider
from .openai_provider import OpenAIProvider
from .anthropic_provider import AnthropicProvider
from .groq_provider import GroqProvider
from .fireworks_provider import FireworksProvider
from .ollama_provider import OllamaProvider

logger = logging.getLogger("ruleforge.providers.factory")

_REGISTRY = {
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
    "groq": GroqProvider,
    "fireworks": FireworksProvider,
    "ollama": OllamaProvider,
}


def get_provider() -> LLMProvider:
    """Instantiate and return the LLM provider configured via LLM_PROVIDER env var.

    Raises:
        ValueError: If LLM_PROVIDER names an unknown provider.
        LLMProviderError: If the provider cannot be initialised (missing API key, etc.).
    """
    provider_name = os.getenv("LLM_PROVIDER", "openai").lower().strip()
    cls = _REGISTRY.get(provider_name)
    if cls is None:
        raise ValueError(
            f"Unknown LLM_PROVIDER: {provider_name!r}. "
            f"Valid options: {', '.join(_REGISTRY)}"
        )
    logger.info("Initialising LLM provider: %s", provider_name)
    return cls()
