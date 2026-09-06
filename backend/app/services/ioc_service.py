import logging
import re
from typing import Dict, List
from .llm_service import extract_iocs_with_llm
from .ioc_filter_service import filter_iocs

PATTERNS = {
    "ipv4": r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b",
    "domain": r"\b(?:[a-zA-Z0-9-]{1,63}\.)+(?:com|net|org|io|biz|info|ru|cn|top|xyz|co|us|uk|ph|de|fr|jp|kr|site|online)\b",
    "url": r"https?://[^\s\)\]\}\"'<>]+",
    "md5": r"\b[a-fA-F0-9]{32}\b",
    "sha1": r"\b[a-fA-F0-9]{40}\b",
    "sha256": r"\b[a-fA-F0-9]{64}\b",
    "email": r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b",
    "windows_path": r"\b[A-Za-z]:\\(?:[^\\/:*?\"<>|\r\n]+\\)*[^\\/:*?\"<>|\r\n]*",
    "registry_key": r"\bHKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\\[^\r\n]+",
}


def _context(text: str, start: int, end: int, radius: int = 120) -> str:
    return text[max(0, start - radius): min(len(text), end + radius)].replace("\n", " ").strip()


def _normalize_ioc(item: Dict) -> Dict:
    return {
        "ioc_type": str(item.get("ioc_type", "unknown")).lower().strip(),
        "value": str(item.get("value", "")).strip().rstrip(".,;:"),
        "description": str(item.get("description", "Extracted from report text.")).strip(),
        "confidence": str(item.get("confidence", "medium")).lower().strip(),
        "source_context": str(item.get("source_context", "")).replace("\n", " ").strip(),
    }


def extract_iocs(text: str) -> List[Dict]:
    results = []
    seen = set()
    for ioc_type, pattern in PATTERNS.items():
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            value = match.group(0).strip().rstrip(".,;:")
            confidence = "high" if ioc_type in {"sha256", "sha1", "md5", "url"} else "medium"
            key = (ioc_type, value.lower())
            if key in seen:
                continue
            seen.add(key)
            results.append({
                "ioc_type": ioc_type,
                "value": value,
                "description": f"Extracted {ioc_type} from report text.",
                "confidence": confidence,
                "source_context": _context(text, match.start(), match.end()),
            })
    # LLM extraction adds contextual artifacts such as mutexes, user agents,
    # malware filenames, services, process names, and behavioral indicators that
    # regex extraction usually misses. Regex results remain as deterministic fallback.
    for item in extract_iocs_with_llm(text):
        normalized = _normalize_ioc(item)
        if not normalized["value"] or normalized["ioc_type"] == "unknown":
            continue
        key = (normalized["ioc_type"], normalized["value"].lower())
        if key in seen:
            continue
        seen.add(key)
        results.append(normalized)


    filtered, removed = filter_iocs(results)
    if removed:
        logging.getLogger("ruleforge.ioc").info("IOC quality filter removed count=%s", len(removed))
    return filtered
