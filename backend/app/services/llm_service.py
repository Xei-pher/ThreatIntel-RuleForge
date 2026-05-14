import json
import logging
import os
import time
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

load_dotenv()

try:
    from openai import OpenAI
except ImportError:  # Keeps the app runnable before requirements are installed.
    OpenAI = None

logger = logging.getLogger("ruleforge.llm")

DEFAULT_MODEL = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
MAX_REPORT_CHARS = int(os.getenv("LLM_MAX_REPORT_CHARS", "60000"))
LLM_TIMEOUT_SECONDS = float(os.getenv("LLM_TIMEOUT_SECONDS", "60"))
LLM_DEBUG = os.getenv("LLM_DEBUG", "false").lower() in {"1", "true", "yes", "y"}


def _mask_key(key: str) -> str:
    if not key:
        return "missing"
    if len(key) <= 12:
        return "set-but-too-short"
    return f"{key[:7]}...{key[-4:]}"


def llm_status() -> Dict[str, Any]:
    api_key = os.getenv("OPENAI_API_KEY", "")
    return {
        "enabled": bool(api_key) and OpenAI is not None,
        "openai_package_installed": OpenAI is not None,
        "api_key": _mask_key(api_key),
        "model": DEFAULT_MODEL,
        "max_report_chars": MAX_REPORT_CHARS,
        "timeout_seconds": LLM_TIMEOUT_SECONDS,
        "debug": LLM_DEBUG,
    }


def llm_is_enabled() -> bool:
    return bool(os.getenv("OPENAI_API_KEY")) and OpenAI is not None


def _client() -> Optional[Any]:
    if not llm_is_enabled():
        logger.warning("LLM disabled. status=%s", llm_status())
        return None
    return OpenAI(api_key=os.getenv("OPENAI_API_KEY"), timeout=LLM_TIMEOUT_SECONDS)


def _safe_json_loads(content: str) -> Dict[str, Any]:
    """Parse model JSON even if the provider wraps it in extra text."""
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        start = content.find("{")
        end = content.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(content[start:end + 1])
        raise


def call_json(
    system_prompt: str,
    user_prompt: str,
    fallback: Dict[str, Any],
    task_name: str,
    schema: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Call the LLM and return parsed JSON. Logs every failure and falls back safely."""
    client = _client()
    if not client:
        logger.warning("LLM skipped for task=%s because client is not available.", task_name)
        return fallback

    started = time.perf_counter()
    prompt_chars = min(len(user_prompt), MAX_REPORT_CHARS)
    logger.info("LLM start task=%s model=%s prompt_chars=%s", task_name, DEFAULT_MODEL, prompt_chars)

    response_format: Dict[str, Any]
    if schema:
        response_format = {
            "type": "json_schema",
            "json_schema": {
                "name": f"ruleforge_{task_name}",
                "strict": True,
                "schema": schema,
            },
        }
    else:
        response_format = {"type": "json_object"}

    try:
        response = client.chat.completions.create(
            model=DEFAULT_MODEL,
            temperature=0.1,
            response_format=response_format,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt[:MAX_REPORT_CHARS]},
            ],
        )
        elapsed_ms = round((time.perf_counter() - started) * 1000)
        content = response.choices[0].message.content or "{}"
        usage = getattr(response, "usage", None)
        logger.info(
            "LLM success task=%s elapsed_ms=%s output_chars=%s usage=%s",
            task_name,
            elapsed_ms,
            len(content),
            usage,
        )
        if LLM_DEBUG:
            logger.debug("LLM raw output task=%s content=%s", task_name, content[:4000])
        return _safe_json_loads(content)
    except Exception as exc:
        elapsed_ms = round((time.perf_counter() - started) * 1000)
        logger.exception(
            "LLM failed task=%s model=%s elapsed_ms=%s error_type=%s error=%s",
            task_name,
            DEFAULT_MODEL,
            elapsed_ms,
            type(exc).__name__,
            exc,
        )
        return fallback


def test_llm_connection() -> Dict[str, Any]:
    """Small health check endpoint helper. Does not consume report text."""
    status = llm_status()
    if not status["enabled"]:
        return {**status, "ok": False, "error": "LLM is disabled. Check OPENAI_API_KEY and openai package install."}
    data = call_json(
        "Return JSON only.",
        'Return exactly this JSON object: {"ok": true, "message": "llm reachable"}',
        {"ok": False, "message": "fallback"},
        task_name="health_check",
        schema={
            "type": "object",
            "properties": {
                "ok": {"type": "boolean"},
                "message": {"type": "string"},
            },
            "required": ["ok", "message"],
            "additionalProperties": False,
        },
    )
    return {**status, **data}


OVERVIEW_SCHEMA = {
    "type": "object",
    "properties": {
        "title": {"type": "string"},
        "executive_summary": {"type": "string"},
        "threat_actor": {"type": "string"},
        "malware_families": {"type": "array", "items": {"type": "string"}},
        "targeting": {"type": "string"},
        "attack_chain": {"type": "array", "items": {"type": "string"}},
        "key_findings": {"type": "array", "items": {"type": "string"}},
        "detection_opportunities": {"type": "array", "items": {"type": "string"}},
        "analyst_notes": {"type": "array", "items": {"type": "string"}},
        "confidence": {"type": "string"},
    },
    "required": [
        "title",
        "executive_summary",
        "threat_actor",
        "malware_families",
        "targeting",
        "attack_chain",
        "key_findings",
        "detection_opportunities",
        "analyst_notes",
        "confidence",
    ],
    "additionalProperties": False,
}


def generate_overview_with_llm(report_text: str, filename: str = "") -> Dict[str, Any]:
    system = """You are a senior cyber threat intelligence analyst.
Create a concise analyst-ready overview from a threat report.
Focus on what a SOC analyst or detection engineer needs to understand quickly.
Return strict JSON only. Do not invent facts that are not supported by the report."""
    user = f"""
Create a threat intelligence overview from this report.

Return this JSON shape exactly:
{{
  "title": "clean report title",
  "executive_summary": "3-5 sentence plain-English summary of the threat/report",
  "threat_actor": "known/suspected actor, or Unknown if not stated",
  "malware_families": ["malware/tool names found in the report"],
  "targeting": "targeted sectors, countries, platforms, or victims if stated",
  "attack_chain": ["ordered steps of the intrusion or campaign"],
  "key_findings": ["important findings for analysts"],
  "detection_opportunities": ["practical places to detect this activity"],
  "analyst_notes": ["caveats, confidence issues, or assumptions to review"],
  "confidence": "low|medium|high"
}}

Filename: {filename}

Report text:
{report_text}
"""
    fallback = {
        "title": filename.rsplit('.', 1)[0] if filename else "Threat Report Overview",
        "executive_summary": (report_text[:900] + ("..." if len(report_text) > 900 else "")) if report_text else "No report text extracted.",
        "threat_actor": "Unknown",
        "malware_families": [],
        "targeting": "Not identified",
        "attack_chain": [],
        "key_findings": [],
        "detection_opportunities": [],
        "analyst_notes": ["LLM overview unavailable; displaying basic extracted-text fallback."],
        "confidence": "low",
    }
    data = call_json(system, user, fallback, task_name="overview_generation", schema=OVERVIEW_SCHEMA)
    if not isinstance(data, dict):
        logger.warning("LLM overview returned non-dict payload. Falling back.")
        return fallback
    logger.info(
        "LLM overview task returned title=%s attack_chain_steps=%s findings=%s",
        data.get("title"),
        len(data.get("attack_chain", []) or []),
        len(data.get("key_findings", []) or []),
    )
    return data


IOC_SCHEMA = {
    "type": "object",
    "properties": {
        "iocs": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "ioc_type": {"type": "string"},
                    "value": {"type": "string"},
                    "description": {"type": "string"},
                    "confidence": {"type": "string"},
                    "source_context": {"type": "string"},
                },
                "required": ["ioc_type", "value", "description", "confidence", "source_context"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["iocs"],
    "additionalProperties": False,
}

MITRE_SCHEMA = {
    "type": "object",
    "properties": {
        "mappings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "technique_id": {"type": "string"},
                    "technique_name": {"type": "string"},
                    "evidence": {"type": "string"},
                    "confidence": {"type": "string"},
                },
                "required": ["technique_id", "technique_name", "evidence", "confidence"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["mappings"],
    "additionalProperties": False,
}

SIGMA_SCHEMA = {
    "type": "object",
    "properties": {
        "rules": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "rule_type": {"type": "string"},
                    "title": {"type": "string"},
                    "description": {"type": "string"},
                    "severity": {"type": "string"},
                    "mitre_technique": {"type": "string"},
                    "rule_content": {"type": "string"},
                    "status": {"type": "string"},
                },
                "required": ["rule_type", "title", "description", "severity", "mitre_technique", "rule_content", "status"],
                "additionalProperties": False,
            },
        }
    },
    "required": ["rules"],
    "additionalProperties": False,
}


def extract_iocs_with_llm(report_text: str) -> List[Dict[str, str]]:
    system = """You are a senior cyber threat intelligence analyst.
Extract only security-relevant indicators of compromise from threat reports, keep in mind the context or any false positives
Return strict JSON only. Do not invent indicators. Use evidence from the report text only."""
    user = f"""
Extract IOCs from this threat report.

Return this JSON shape exactly:
{{
  "iocs": [
    {{
      "ioc_type": "ipv4|ipv6|domain|url|md5|sha1|sha256|email|windows_path|linux_path|registry_key|mutex|user_agent|process|service|filename",
      "value": "indicator value",
      "description": "why this is relevant",
      "confidence": "low|medium|high",
      "source_context": "short quote or paraphrased context from the report"
    }}
  ]
}}

Report text:
{report_text}
"""
    data = call_json(system, user, {"iocs": []}, task_name="ioc_extraction", schema=IOC_SCHEMA)
    iocs = data.get("iocs", []) if isinstance(data.get("iocs"), list) else []
    logger.info("LLM IOC task returned count=%s", len(iocs))
    return iocs


def map_mitre_with_llm(report_text: str) -> List[Dict[str, str]]:
    system = """You are a detection engineer mapping threat report behavior to MITRE ATT&CK Enterprise.
Return strict JSON only. Do not map techniques unless there is behavioral evidence in the report."""
    user = f"""
Map the observed behaviors in this report to MITRE ATT&CK Enterprise techniques.

Return this JSON shape exactly:
{{
  "mappings": [
    {{
      "technique_id": "T#### or T####.###",
      "technique_name": "MITRE technique name",
      "evidence": "specific behavior or report evidence",
      "confidence": "low|medium|high"
    }}
  ]
}}

Report text:
{report_text}
"""
    data = call_json(system, user, {"mappings": []}, task_name="mitre_mapping", schema=MITRE_SCHEMA)
    mappings = data.get("mappings", []) if isinstance(data.get("mappings"), list) else []
    logger.info("LLM MITRE task returned count=%s", len(mappings))
    return mappings


def generate_sigma_with_llm(iocs: List[Dict], mitre: List[Dict], report_text: str) -> List[Dict[str, str]]:
    system = """You are a senior detection engineer.
Generate practical Sigma rules from threat report intelligence.
Rules must be draft-quality, conservative, readable, and reviewable by a human.
Return strict JSON only."""
    user = f"""
Generate Sigma rules using the IOCs, MITRE mappings, and report text below.
Prefer behavior-based rules when report evidence supports them. Generate IOC-based rules when behavior is not enough.
Do not create rules for weak evidence.

Return this JSON shape exactly:
{{
  "rules": [
    {{
      "rule_type": "sigma",
      "title": "rule title",
      "description": "what the rule detects",
      "severity": "low|medium|high|critical",
      "mitre_technique": "comma-separated technique IDs or none",
      "rule_content": "valid Sigma YAML as a string",
      "status": "draft"
    }}
  ]
}}

IOCs:
{json.dumps(iocs[:200], indent=2)}

MITRE mappings:
{json.dumps(mitre[:50], indent=2)}

Report text:
{report_text[:MAX_REPORT_CHARS]}
"""
    data = call_json(system, user, {"rules": []}, task_name="sigma_generation", schema=SIGMA_SCHEMA)
    rules = data.get("rules", []) if isinstance(data.get("rules"), list) else []
    logger.info("LLM Sigma task returned count=%s", len(rules))
    return rules
