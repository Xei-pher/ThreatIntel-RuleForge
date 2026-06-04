import logging
from typing import Any, Dict, List

from .base import AgentContext, AgentResult, BaseAgent, MAX_REPORT_CHARS

logger = logging.getLogger("ruleforge.agents.mitre")

_MITRE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "mappings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "technique_id": {"type": "string"},
                    "technique_name": {"type": "string"},
                    "tactic": {"type": "string"},
                    "evidence": {"type": "string"},
                    "confidence": {"type": "string"},
                },
                "required": [
                    "technique_id", "technique_name", "tactic", "evidence", "confidence"
                ],
                "additionalProperties": False,
            },
        }
    },
    "required": ["mappings"],
    "additionalProperties": False,
}


def _normalize(item: Dict) -> Dict:
    return {
        "technique_id": str(item.get("technique_id", "")).upper().strip(),
        "technique_name": str(item.get("technique_name", "")).strip(),
        "tactic": str(item.get("tactic", "")).strip(),
        "evidence": str(item.get("evidence", "")).replace("\n", " ").strip(),
        "confidence": str(item.get("confidence", "medium")).lower().strip(),
    }


class MITREAgent(BaseAgent):
    """Maps threat report behaviours to MITRE ATT&CK Enterprise techniques using an LLM."""

    name = "MITREAgent"

    def run(self, context: AgentContext) -> AgentResult:
        logger.info("MITREAgent starting iteration=%s", context.iteration)

        critique_hint = ""
        if context.judge_feedback and context.judge_feedback.mitre_issues:
            critique_hint = (
                f"\n\nThe previous MITRE mapping was critiqued as follows:\n"
                f"{context.judge_feedback.mitre_issues}\n"
                "Address all identified gaps in this mapping."
            )

        system = (
            "You are a detection engineer mapping threat report behaviour to MITRE ATT&CK Enterprise.\n"
            "Map every observable TTP to the most specific applicable technique and sub-technique.\n"
            "Include the tactic (e.g. Initial Access, Execution, Persistence, …) for every mapping.\n"
            "Return strict JSON only. Do not map techniques unless there is behavioural "
            "evidence in the report text."
        )
        user = (
            f"Map all observed behaviours in this report to MITRE ATT&CK Enterprise techniques.\n\n"
            f"Return this JSON shape exactly:\n"
            f'{{"mappings": [{{'
            f'"technique_id": "T#### or T####.###", '
            f'"technique_name": "MITRE technique name", '
            f'"tactic": "tactic name", '
            f'"evidence": "specific behaviour or quote from report", '
            f'"confidence": "low|medium|high"'
            f'}}]}}\n'
            f"{critique_hint}\n"
            f"Report text:\n{context.raw_text[:MAX_REPORT_CHARS]}"
        )

        data = self._call_llm(
            system, user, {"mappings": []}, task_name="mitre_mapping", schema=_MITRE_SCHEMA
        )
        raw: List[Dict] = (
            data.get("mappings", [])
            if isinstance(data, dict) and isinstance(data.get("mappings"), list)
            else []
        )
        logger.info("MITREAgent LLM returned %d raw mappings", len(raw))

        seen = set()
        mappings: List[Dict] = []
        for item in raw:
            n = _normalize(item)
            tid = n["technique_id"]
            if not tid or not tid.startswith("T") or tid in seen:
                continue
            seen.add(tid)
            mappings.append(n)

        context.mitre_mappings = mappings
        logger.info("MITREAgent complete mappings=%d", len(mappings))
        return AgentResult(agent_name=self.name, success=True, output=mappings)
