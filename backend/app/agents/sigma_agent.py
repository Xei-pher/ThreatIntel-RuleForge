import json
import logging
from typing import Any, Dict, List

import yaml

from .base import AgentContext, AgentResult, BaseAgent, MAX_REPORT_CHARS

logger = logging.getLogger("ruleforge.agents.sigma")

_SIGMA_SCHEMA: Dict[str, Any] = {
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
                "required": [
                    "rule_type", "title", "description", "severity",
                    "mitre_technique", "rule_content", "status",
                ],
                "additionalProperties": False,
            },
        }
    },
    "required": ["rules"],
    "additionalProperties": False,
}


def _is_valid_sigma(rule: Dict) -> bool:
    """Return True when the dict represents a structurally valid Sigma rule."""
    required = {"rule_type", "title", "description", "severity", "rule_content", "status"}
    if not isinstance(rule, dict) or not required.issubset(rule.keys()):
        return False
    if str(rule.get("rule_type", "")).lower() != "sigma":
        return False
    try:
        parsed = yaml.safe_load(rule.get("rule_content") or "")
        return isinstance(parsed, dict) and "title" in parsed and "detection" in parsed
    except Exception:
        return False


class SigmaRuleAgent(BaseAgent):
    """Generates Sigma detection rules from report intelligence using an LLM."""

    name = "SigmaRuleAgent"

    def run(self, context: AgentContext) -> AgentResult:
        logger.info("SigmaRuleAgent starting iteration=%s", context.iteration)

        critique_hint = ""
        if context.judge_feedback and context.judge_feedback.sigma_issues:
            critique_hint = (
                f"\n\nThe previous Sigma rules were critiqued as follows:\n"
                f"{context.judge_feedback.sigma_issues}\n"
                "Address all identified issues in this generation."
            )

        system = (
            "You are a senior detection engineer.\n"
            "Generate practical, production-quality Sigma rules from threat report intelligence.\n"
            "Prefer behaviour-based rules when report evidence supports them; "
            "fall back to IOC-based rules when behavioural context is insufficient.\n"
            "Every rule_content field must be a complete, valid Sigma YAML string.\n"
            "Return strict JSON only."
        )
        user = (
            f"Generate Sigma rules using the IOCs, MITRE mappings, and report text below.\n\n"
            f"Return this JSON shape exactly:\n"
            f'{{"rules": [{{'
            f'"rule_type": "sigma", '
            f'"title": "rule title", '
            f'"description": "what the rule detects", '
            f'"severity": "low|medium|high|critical", '
            f'"mitre_technique": "comma-separated technique IDs or empty string", '
            f'"rule_content": "valid Sigma YAML as a string", '
            f'"status": "draft"'
            f'}}]}}\n'
            f"{critique_hint}\n"
            f"IOCs:\n{json.dumps(context.iocs[:200], indent=2)}\n\n"
            f"MITRE mappings:\n{json.dumps(context.mitre_mappings[:50], indent=2)}\n\n"
            f"Report text:\n{context.raw_text[:MAX_REPORT_CHARS]}"
        )

        data = self._call_llm(
            system, user, {"rules": []}, task_name="sigma_generation", schema=_SIGMA_SCHEMA
        )
        raw: List[Dict] = (
            data.get("rules", [])
            if isinstance(data, dict) and isinstance(data.get("rules"), list)
            else []
        )
        logger.info("SigmaRuleAgent LLM returned %d raw rules", len(raw))

        valid_rules: List[Dict] = []
        rejected: List[str] = []
        for rule in raw:
            if _is_valid_sigma(rule):
                valid_rules.append({
                    "rule_type": "sigma",
                    "title": str(rule.get("title", ""))[:255],
                    "description": str(rule.get("description", "")),
                    "severity": str(rule.get("severity", "medium")).lower(),
                    "mitre_technique": rule.get("mitre_technique") or "",
                    "rule_content": rule.get("rule_content", ""),
                    "status": str(rule.get("status", "draft")).lower(),
                })
            else:
                rejected.append(str(rule.get("title", "unnamed")))

        if rejected:
            logger.warning(
                "SigmaRuleAgent discarded %d invalid rules: %s",
                len(rejected),
                rejected[:10],
            )

        context.sigma_rules = valid_rules
        logger.info("SigmaRuleAgent complete valid_rules=%d discarded=%d", len(valid_rules), len(rejected))
        return AgentResult(
            agent_name=self.name,
            success=True,
            output=valid_rules,
            notes=f"discarded={len(rejected)}",
        )
