import ipaddress
import os
import re
from typing import Dict, List, Tuple
from urllib.parse import urlparse

# Domains commonly present because they published/hosted reports, not because they are threat infrastructure.
DEFAULT_DOMAIN_DENYLIST = {
    "dfirreport.com",
    "www.dfirreport.com",
    "thedfirreport.com",
    "www.thedfirreport.com",
    "mandiant.com",
    "www.mandiant.com",
    "cloud.google.com",
    "microsoft.com",
    "www.microsoft.com",
    "attack.mitre.org",
    "mitre.org",
    "virustotal.com",
    "www.virustotal.com",
    "github.com",
    "raw.githubusercontent.com",
    "thehackernews.com",
    "www.thehackernews.com",
    "bleepingcomputer.com",
    "www.bleepingcomputer.com",
}

NOISE_VALUE_PATTERNS = [
    re.compile(r"^example\.", re.I),
    re.compile(r"\.example$", re.I),
    re.compile(r"^localhost$", re.I),
]


def _env_set(name: str) -> set[str]:
    return {x.strip().lower() for x in os.getenv(name, "").split(",") if x.strip()}


def _domain_from_value(value: str) -> str:
    value = (value or "").strip().lower().rstrip("/.,;:")
    if value.startswith(("http://", "https://")):
        try:
            return (urlparse(value).hostname or "").lower().strip(".")
        except Exception:
            return ""
    return value.strip(".")


def _is_public_ipv4(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.strip())
        # is_global excludes private, loopback, link-local, multicast, reserved, documentation, unspecified, etc.
        return ip.version == 4 and ip.is_global
    except ValueError:
        return False


def _is_noise_domain(value: str) -> Tuple[bool, str]:
    domain = _domain_from_value(value)
    denylist = DEFAULT_DOMAIN_DENYLIST | _env_set("IOC_DOMAIN_DENYLIST")
    allowlist = _env_set("IOC_DOMAIN_ALLOWLIST")

    if not domain:
        return True, "invalid domain"
    if domain in allowlist:
        return False, ""
    if domain in denylist or any(domain.endswith("." + d) for d in denylist):
        return True, "domain is in publisher/noise denylist"
    if any(p.search(domain) for p in NOISE_VALUE_PATTERNS):
        return True, "domain matches example/noise pattern"
    if domain.count(".") == 0:
        return True, "not a fully qualified domain"
    return False, ""


def should_keep_ioc(ioc: Dict) -> Tuple[bool, str]:
    ioc_type = str(ioc.get("ioc_type", "")).lower().strip()
    value = str(ioc.get("value", "")).strip()

    if not value:
        return False, "empty value"

    if ioc_type in {"ipv4", "ip", "ip_address"}:
        if not _is_public_ipv4(value):
            return False, "non-public IPv4 address"
        return True, ""

    if ioc_type in {"domain", "url"}:
        noisy, reason = _is_noise_domain(value)
        if noisy:
            return False, reason
        return True, ""

    return True, ""


def filter_iocs(iocs: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
    kept: List[Dict] = []
    removed: List[Dict] = []
    seen = set()

    for item in iocs:
        ioc_type = str(item.get("ioc_type", "")).lower().strip()
        value = str(item.get("value", "")).strip().rstrip(".,;:")
        if ioc_type == "ip":
            ioc_type = "ipv4"
        item = {**item, "ioc_type": ioc_type, "value": value}
        key = (ioc_type, value.lower())
        if key in seen:
            removed.append({**item, "filter_reason": "duplicate IOC"})
            continue
        seen.add(key)

        keep, reason = should_keep_ioc(item)
        if keep:
            kept.append(item)
        else:
            removed.append({**item, "filter_reason": reason})

    return kept, removed
