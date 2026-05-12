import re
from typing import Dict, List

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

PRIVATE_IP_PREFIXES = ("10.", "127.", "169.254.", "192.168.")

def _context(text: str, start: int, end: int, radius: int = 120) -> str:
    return text[max(0, start - radius): min(len(text), end + radius)].replace("\n", " ").strip()


def extract_iocs(text: str) -> List[Dict]:
    results = []
    seen = set()
    for ioc_type, pattern in PATTERNS.items():
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            value = match.group(0).strip().rstrip(".,;:")
            if ioc_type == "ipv4" and value.startswith(PRIVATE_IP_PREFIXES):
                confidence = "low"
            else:
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
    return results
