"""ioc_service.py — IOC normalisation helper.

Full IOC extraction (LLM + regex) has been moved to IOCExtractorAgent
(app/agents/ioc_extractor.py).  This module retains only the normalisation
utility used by that agent and any other callers that need a canonical IOC dict.
"""
from typing import Dict


def normalize_ioc(item: Dict) -> Dict:
    """Return a normalised IOC dict with consistent field types and values."""
    return {
        "ioc_type": str(item.get("ioc_type", "unknown")).lower().strip(),
        "value": str(item.get("value", "")).strip().rstrip(".,;:"),
        "description": str(item.get("description", "Extracted from report text.")).strip(),
        "confidence": str(item.get("confidence", "medium")).lower().strip(),
        "source_context": str(item.get("source_context", "")).replace("\n", " ").strip(),
    }
