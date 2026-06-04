import json
import logging
from typing import Any, Dict

from .base import AgentContext, AgentResult, BaseAgent, MAX_REPORT_CHARS

logger = logging.getLogger("ruleforge.agents.report_generator")

_OVERVIEW_SCHEMA: Dict[str, Any] = {
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
        "title", "executive_summary", "threat_actor", "malware_families",
        "targeting", "attack_chain", "key_findings",
        "detection_opportunities", "analyst_notes", "confidence",
    ],
    "additionalProperties": False,
}

_REPORT_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "report": {"type": "string"},
    },
    "required": ["report"],
    "additionalProperties": False,
}


class ReportGeneratorAgent(BaseAgent):
    """Generates a SOC analyst-ready Markdown report and a structured overview JSON."""

    name = "ReportGeneratorAgent"

    # ------------------------------------------------------------------
    # Overview (structured JSON for frontend rendering)
    # ------------------------------------------------------------------

    def _generate_overview(self, context: AgentContext) -> Dict:
        system = (
            "You are a senior cyber threat intelligence analyst.\n"
            "Create a concise analyst-ready overview from a threat report.\n"
            "Focus on what a SOC analyst or detection engineer needs to understand quickly.\n"
            "Return strict JSON only. Do not invent facts not supported by the report."
        )
        user = (
            f"Create a threat intelligence overview from this report.\n\n"
            f"Return this JSON shape exactly:\n"
            f'{{"title": "clean report title", '
            f'"executive_summary": "3-5 sentence plain-English summary", '
            f'"threat_actor": "known/suspected actor or Unknown if not stated", '
            f'"malware_families": ["malware or tool names found in the report"], '
            f'"targeting": "targeted sectors, countries, platforms, or victims", '
            f'"attack_chain": ["ordered steps of the intrusion or campaign"], '
            f'"key_findings": ["important findings for analysts"], '
            f'"detection_opportunities": ["practical places to detect this activity"], '
            f'"analyst_notes": ["caveats, confidence issues, or assumptions"], '
            f'"confidence": "low|medium|high"}}\n\n'
            f"Report text:\n{context.raw_text[:MAX_REPORT_CHARS]}"
        )
        fallback: Dict = {
            "title": "Threat Report Overview",
            "executive_summary": "Overview generation failed.",
            "threat_actor": "Unknown",
            "malware_families": [],
            "targeting": "Not identified",
            "attack_chain": [],
            "key_findings": [],
            "detection_opportunities": [],
            "analyst_notes": [],
            "confidence": "low",
        }
        result = self._call_llm(
            system, user, fallback, task_name="overview_generation", schema=_OVERVIEW_SCHEMA
        )
        return result if isinstance(result, dict) else fallback

    # ------------------------------------------------------------------
    # Markdown report
    # ------------------------------------------------------------------

    def _generate_markdown(self, context: AgentContext) -> str:
        critique_hint = ""
        if context.judge_feedback and context.judge_feedback.report_issues:
            critique_hint = (
                f"\n\nThe previous report was critiqued as follows:\n"
                f"{context.judge_feedback.report_issues}\n"
                "Address every point raised in this revision."
            )

        system = (
            "You are a senior SOC analyst and threat intelligence report writer.\n"
            "Produce a comprehensive, well-structured Markdown report that a SOC analyst "
            "can act on immediately.\n"
            "Do not fabricate information. Every claim must be supported by the provided "
            "artefacts or source material.\n"
            'Return JSON with a single key "report" whose value is the full Markdown string.'
        )

        ioc_count = len(context.iocs)
        mitre_count = len(context.mitre_mappings)
        rule_count = len(context.sigma_rules)

        user = (
            f"Generate a SOC analyst-ready Markdown report using the artefacts below.\n\n"
            f"The report must include ALL of the following sections:\n"
            f"1. Executive Summary\n"
            f"2. Threat Actor / Campaign Overview\n"
            f"3. IOC Table (type, value, confidence, enrichment)\n"
            f"4. MITRE ATT&CK Technique Table (technique ID, name, tactic, evidence, confidence)\n"
            f"5. Sigma Detection Rules Index (title, severity, MITRE tags)\n"
            f"6. Detection Recommendations\n"
            f"7. Analyst Notes\n"
            f"{critique_hint}\n"
            f"--- Overview ---\n{json.dumps(context.overview, indent=2)}\n\n"
            f"--- IOCs ({ioc_count} total, first 150 shown) ---\n"
            f"{json.dumps(context.iocs[:150], indent=2)}\n\n"
            f"--- MITRE Mappings ({mitre_count} total) ---\n"
            f"{json.dumps(context.mitre_mappings[:50], indent=2)}\n\n"
            f"--- Sigma Rules ({rule_count} total, titles only) ---\n"
            f"{json.dumps([r.get('title') for r in context.sigma_rules[:50]], indent=2)}\n\n"
            f"--- Source Material (first 15 000 chars) ---\n{context.raw_text[:15000]}"
        )

        data = self._call_llm(
            system, user, {}, task_name="report_generation", schema=_REPORT_SCHEMA
        )
        if isinstance(data, dict) and isinstance(data.get("report"), str):
            return data["report"]
        # Fallback: deterministic assembly from context
        return self._assemble_from_context(context)

    # ------------------------------------------------------------------
    # Deterministic fallback assembly
    # ------------------------------------------------------------------

    def _assemble_from_context(self, context: AgentContext) -> str:
        ov = context.overview
        lines = [
            f"# {ov.get('title', 'Threat Intelligence Report')}\n",
            f"## Executive Summary\n\n{ov.get('executive_summary', 'Not available.')}\n",
            f"**Threat Actor:** {ov.get('threat_actor', 'Unknown')}  ",
            f"**Confidence:** {ov.get('confidence', 'low')}\n",
        ]
        if context.iocs:
            lines.append("\n## IOCs\n\n| Type | Value | Confidence |")
            lines.append("|---|---|---|")
            for ioc in context.iocs[:100]:
                lines.append(
                    f"| {ioc.get('ioc_type')} | `{ioc.get('value')}` | {ioc.get('confidence')} |"
                )
        if context.mitre_mappings:
            lines.append("\n## MITRE ATT&CK\n\n| Technique ID | Name | Tactic | Confidence |")
            lines.append("|---|---|---|---|")
            for m in context.mitre_mappings:
                lines.append(
                    f"| {m.get('technique_id')} | {m.get('technique_name')} "
                    f"| {m.get('tactic', '')} | {m.get('confidence')} |"
                )
        if context.sigma_rules:
            lines.append("\n## Sigma Detection Rules\n")
            for r in context.sigma_rules:
                lines.append(f"- **{r.get('title')}** [{r.get('severity')}]")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def run(self, context: AgentContext) -> AgentResult:
        logger.info("ReportGeneratorAgent starting iteration=%s", context.iteration)

        # Generate/refresh overview on first pass or when this agent is re-run by Judge
        if not context.overview or (
            context.judge_feedback
            and self.name in context.judge_feedback.failed_agents
        ):
            context.overview = self._generate_overview(context)
            logger.info(
                "ReportGeneratorAgent overview generated title=%s",
                context.overview.get("title"),
            )

        markdown = self._generate_markdown(context)
        context.report_markdown = markdown
        logger.info(
            "ReportGeneratorAgent complete report_chars=%d", len(markdown)
        )
        return AgentResult(agent_name=self.name, success=True, output=markdown)
