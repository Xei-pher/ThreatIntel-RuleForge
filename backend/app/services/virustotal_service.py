import json
import logging
import os
import time
import ipaddress
from typing import Any, Dict, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger("ruleforge.virustotal")
VT_BASE_URL = "https://www.virustotal.com/api/v3"
VT_TIMEOUT_SECONDS = float(os.getenv("VT_TIMEOUT_SECONDS", "20"))


def vt_status() -> Dict[str, Any]:
    key = os.getenv("VIRUSTOTAL_API_KEY", "")
    return {
        "enabled": bool(key),
        "configured": bool(key),
        "timeout_seconds": VT_TIMEOUT_SECONDS,
    }


def _is_public_ip(value: str) -> bool:
    try:
        ip = ipaddress.ip_address(value.strip())
        return ip.version == 4 and ip.is_global
    except ValueError:
        return False


def enrich_ip(value: str) -> Optional[Dict[str, Any]]:
    """Basic VirusTotal IP enrichment. Returns None if disabled or non-public IP."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY", "")
    if not api_key:
        logger.info("VirusTotal skipped for ip=%s reason=missing_api_key", value)
        return None
    if not _is_public_ip(value):
        logger.info("VirusTotal skipped for ip=%s reason=non_public_ip", value)
        return None

    url = f"{VT_BASE_URL}/ip_addresses/{value.strip()}"
    req = Request(url, headers={"x-apikey": api_key, "accept": "application/json"})
    started = time.perf_counter()
    try:
        with urlopen(req, timeout=VT_TIMEOUT_SECONDS) as response:
            body = response.read().decode("utf-8")
            payload = json.loads(body)
        attrs = payload.get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {}) or {}
        enrichment = {
            "source": "virustotal",
            "malicious": int(stats.get("malicious", 0) or 0),
            "suspicious": int(stats.get("suspicious", 0) or 0),
            "harmless": int(stats.get("harmless", 0) or 0),
            "undetected": int(stats.get("undetected", 0) or 0),
            "country": attrs.get("country"),
            "asn": attrs.get("asn"),
            "as_owner": attrs.get("as_owner"),
            "reputation": attrs.get("reputation"),
            "link": f"https://www.virustotal.com/gui/ip-address/{value.strip()}",
        }
        logger.info(
            "VirusTotal success ip=%s elapsed_ms=%s malicious=%s suspicious=%s",
            value,
            round((time.perf_counter() - started) * 1000),
            enrichment["malicious"],
            enrichment["suspicious"],
        )
        return enrichment
    except HTTPError as exc:
        logger.warning("VirusTotal HTTP error ip=%s status=%s reason=%s", value, exc.code, exc.reason)
    except (URLError, TimeoutError, json.JSONDecodeError) as exc:
        logger.warning("VirusTotal failed ip=%s error_type=%s error=%s", value, type(exc).__name__, exc)
    except Exception as exc:
        logger.exception("VirusTotal unexpected failure ip=%s error=%s", value, exc)
    return None
