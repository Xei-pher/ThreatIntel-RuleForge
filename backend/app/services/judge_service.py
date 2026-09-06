import json
import logging
import os
from typing import Any, Dict, List, Tuple

from .llm_service import call_json, llm_is_enabled, MAX_REPORT_CHARS

logger = logging.getLogger("ruleforge.judge")

JUDGE_ENABLED = os.getenv("JUDGE_ENABLED", "true").lower() in {"1", "true", "yes", "y"}
JUDGE_ACCEPT_SCORE = int(os.getenv("JUDGE_ACCEPT_SCORE", "70"))
JUDGE_REVIEW_SCORE = int(os.getenv("JUDGE_REVIEW_SCORE", "50"))


def judge_status() -> Dict[str, Any]:
    return {
        "enabled": JUDGE_ENABLED and llm_is_enabled(),
        "configured": JUDGE_ENABLED,
        "accept_score": JUDGE_ACCEPT_SCORE,
        "review_score": JUDGE_REVIEW_SCORE,
    }


EVALUATION_ITEM = {
    "type": "object",
    "properties": {
        "index": {"type": "integer"},
        "decision": {"type": "string"},
        "score": {"type": "integer"},
        "reason": {"type": "string"},
        "recommended_confidence": {"type": "string"},
    },
    "required": ["index", "decision", "score", "reason", "recommended_confidence"],
    "additionalProperties": False,
}

JUDGE_SCHEMA = {
    "type": "object",
    "properties": {
        "evaluations": {
            "type": "array",
            "items": EVALUATION_ITEM,
        }
    },
    "required": ["evaluations"],
    "additionalProperties": False,
}


def _default_pass(items: List[Dict], reason: str = "Judge unavailable; passed through for analyst review.") -> List[Dict]:
    judged = []
    for item in items:
        copy = dict(item)
        copy.setdefault("judge_decision", "review")
        copy.setdefault("judge_score", 60)
        copy.setdefault("judge_reason", reason)
        judged.append(copy)
    return judged


def _apply_evaluations(items: List[Dict], evaluations: List[Dict], item_kind: str) -> Tuple[List[Dict], int]:
    eval_by_index = {}
    for ev in evaluations:
        try:
            idx = int(ev.get("index"))
            eval_by_index[idx] = ev
        except Exception:
            continue

    kept: List[Dict] = []
    rejected = 0
    for idx, item in enumerate(items):
        ev = eval_by_index.get(idx)
        if not ev:
            copy = dict(item)
            copy["judge_decision"] = "review"
            copy["judge_score"] = 55
            copy["judge_reason"] = "Judge did not return an evaluation for this item."
            kept.append(copy)
            continue

        decision = str(ev.get("decision", "review")).lower().strip()
        try:
            score = max(0, min(100, int(ev.get("score", 50))))
        except Exception:
            score = 50
        reason = str(ev.get("reason", "No judge reason provided.")).strip()
        recommended_confidence = str(ev.get("recommended_confidence", item.get("confidence", "medium"))).lower().strip()

        if score >= JUDGE_ACCEPT_SCORE and decision in {"accept", "accepted", "keep"}:
            normalized_decision = "accepted"
        elif score < JUDGE_REVIEW_SCORE or decision in {"reject", "rejected", "drop"}:
            normalized_decision = "rejected"
        else:
            normalized_decision = "review"

        if normalized_decision == "rejected":
            rejected += 1
            logger.info("Judge rejected %s idx=%s score=%s reason=%s", item_kind, idx, score, reason)
            continue

        copy = dict(item)
        copy["judge_decision"] = normalized_decision
        copy["judge_score"] = score
        copy["judge_reason"] = reason
        if recommended_confidence in {"low", "medium", "high", "critical"} and "confidence" in copy:
            copy["confidence"] = recommended_confidence if recommended_confidence != "critical" else "high"
        if item_kind == "sigma_rule" and normalized_decision == "review":
            copy["status"] = "review"
        if item_kind == "ioc" and normalized_decision == "review":
            copy["is_approved"] = False
        kept.append(copy)

    return kept, rejected


def _judge(kind: str, report_text: str, items: List[Dict], rubric: str) -> List[Dict]:
    if not items:
        return []
    if not JUDGE_ENABLED or not llm_is_enabled():
        logger.warning("Judge skipped kind=%s status=%s", kind, judge_status())
        return _default_pass(items)

    indexed_items = [{"index": idx, **item} for idx, item in enumerate(items)]
    system = """You are an independent senior detection engineering QA judge.
Evaluate candidate outputs produced by another AI agent against the source threat report.
Your job is to reduce hallucinations, false positives, weak ATT&CK mappings, and unusable rules.
Return strict JSON only. Do not create new items. Only evaluate the provided indexed items."""
    user = f"""
Evaluate these candidate {kind} items.

Decision rules:
- accept: well-supported by the report and useful for detection/analysis.
- review: possibly useful, but needs analyst verification or is weak/ambiguous.
- reject: unsupported, generic, likely false positive, benign reference, malformed, or not detection-useful.

Scoring:
- 90-100: excellent and directly supported.
- 70-89: acceptable.
- 50-69: needs analyst review.
- 0-49: reject.

Rubric:
{rubric}

Return this JSON shape exactly:
{{
  "evaluations": [
    {{
      "index": 0,
      "decision": "accept|review|reject",
      "score": 0,
      "reason": "specific short reason",
      "recommended_confidence": "low|medium|high"
    }}
  ]
}}

Candidate items:
{json.dumps(indexed_items[:250], indent=2)}

Source report excerpt:
{report_text[:MAX_REPORT_CHARS]}
"""
    data = call_json(system, user, {"evaluations": []}, task_name=f"judge_{kind}", schema=JUDGE_SCHEMA)
    evaluations = data.get("evaluations", []) if isinstance(data, dict) and isinstance(data.get("evaluations"), list) else []
    if not evaluations:
        logger.warning("Judge returned no evaluations kind=%s; passing all items to review.", kind)
        return _default_pass(items, "Judge returned no evaluations; passed through for analyst review.")
    kept, rejected = _apply_evaluations(items, evaluations, kind)
    logger.info("Judge complete kind=%s input=%s kept=%s rejected=%s", kind, len(items), len(kept), rejected)
    return kept


def judge_iocs(report_text: str, iocs: List[Dict]) -> List[Dict]:
    rubric = """
For IOCs, reject private/local IPs, documentation domains, report publisher domains, vendor/reference sites, example values, generic process names, and values not clearly used by the threat. Accept only malware infrastructure, hashes, URLs, filenames, registry keys, paths, mutexes, user agents, or artifacts with clear threat context. Put weak but plausible indicators in review.
"""
    return _judge("ioc", report_text, iocs, rubric)


def judge_mitre_mappings(report_text: str, mappings: List[Dict]) -> List[Dict]:
    rubric = """
For MITRE mappings, accept only mappings with behavioral evidence in the report. Reject mappings based only on generic words, vague campaign descriptions, or unsupported assumptions. Review broad parent techniques when a more specific sub-technique may be needed.
"""
    return _judge("mitre_mapping", report_text, mappings, rubric)


def judge_sigma_rules(report_text: str, rules: List[Dict]) -> List[Dict]:
    rubric = """
For Sigma rules, accept rules that are syntactically plausible, detection-useful, and supported by report behaviors or strong indicators. Reject rules that key on benign reference domains, overly broad process names, invalid YAML, missing detection sections, hallucinated fields, or very high false-positive patterns. Review rules that are useful but need environment-specific tuning.
"""
    return _judge("sigma_rule", report_text, rules, rubric)
