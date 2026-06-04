import json
import logging
from typing import Any, Dict, List, Optional

from .base import AgentContext, AgentResult, BaseAgent, MAX_REPORT_CHARS

logger = logging.getLogger("ruleforge.agents.ioc_extractor")

_IOC_SCHEMA: Dict[str, Any] = {
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
                "required": [
                    "ioc_type", "value", "description", "confidence", "source_context"
                ],
                "additionalProperties": False,
            },
        }
    },
    "required": ["iocs"],
    "additionalProperties": False,
}


def _normalize(item: Dict) -> Dict:
    return {
        "ioc_type": str(item.get("ioc_type", "unknown")).lower().strip(),
        "value": str(item.get("value", "")).strip().rstrip(".,;:"),
        "description": str(item.get("description", "Extracted from report text.")).strip(),
        "confidence": str(item.get("confidence", "medium")).lower().strip(),
        "source_context": str(item.get("source_context", "")).replace("\n", " ").strip(),
    }


class IOCExtractorAgent(BaseAgent):
    """Extracts all IOCs from the report text using an LLM, then filters and enriches them."""

    name = "IOCExtractorAgent"

    def run(self, context: AgentContext) -> AgentResult:
        from ..services.ioc_filter_service import filter_iocs
        from ..services.virustotal_service import enrich_ip

        logger.info("IOCExtractorAgent starting iteration=%s", context.iteration)

        critique_hint = ""
        if context.judge_feedback and context.judge_feedback.ioc_issues:
            critique_hint = (
                f"\n\nThe previous extraction was critiqued as follows:\n"
                f"{context.judge_feedback.ioc_issues}\n"
                "Address all identified gaps in this extraction."
            )

        system = (
            "You are a senior cyber threat intelligence analyst.\n"
            "Extract every security-relevant indicator of compromise (IOC) from the threat report.\n"
            "Cover ALL categories:\n"
            "  • Network indicators: IPv4, IPv6, domain, URL\n"
            "  • File artefacts: md5, sha1, sha256, windows_path, linux_path, filename\n"
            "  • Contextual indicators: mutex, user_agent, process, service, registry_key, "
            "email, cve, yara_rule\n"
            "Return strict JSON only. Do not invent indicators. "
            "Use evidence from the report text only."
        )
        user = (
            f"Extract all IOCs from this threat report.\n\n"
            f"Return this JSON shape exactly:\n"
            f'{{"iocs": [{{'
            f'"ioc_type": "ipv4|ipv6|domain|url|md5|sha1|sha256|email|windows_path|linux_path|'
            f'registry_key|mutex|user_agent|process|service|filename|cve", '
            f'"value": "indicator value", '
            f'"description": "why this is relevant", '
            f'"confidence": "low|medium|high", '
            f'"source_context": "short quote from the report"'
            f'}}]}}\n'
            f"{critique_hint}\n"
            f"Report text:\n{context.raw_text[:MAX_REPORT_CHARS]}"
        )

        data = self._call_llm(
            system, user, {"iocs": []}, task_name="ioc_extraction", schema=_IOC_SCHEMA
        )
        raw_iocs: List[Dict] = (
            data.get("iocs", []) if isinstance(data, dict) and isinstance(data.get("iocs"), list) else []
        )
        logger.info("IOCExtractorAgent LLM returned %d raw IOCs", len(raw_iocs))

        # Normalise and deduplicate
        normalized: List[Dict] = []
        seen = set()
        for item in raw_iocs:
            n = _normalize(item)
            if not n["value"] or n["ioc_type"] == "unknown":
                continue
            key = (n["ioc_type"], n["value"].lower())
            if key in seen:
                continue
            seen.add(key)
            normalized.append(n)

        # Quality filter
        filtered, removed = filter_iocs(normalized)
        if removed:
            logger.info("IOC filter removed %d noisy indicators", len(removed))

        # VirusTotal enrichment for public IPv4 addresses
        enriched: List[Dict] = []
        for ioc in filtered:
            if ioc.get("ioc_type") in {"ipv4", "ip", "ip_address"}:
                vt = enrich_ip(ioc.get("value", ""))
                if vt:
                    enrichment_summary = (
                        f"VT malicious={vt.get('malicious', 0)}, "
                        f"suspicious={vt.get('suspicious', 0)}, "
                        f"AS={vt.get('as_owner') or 'unknown'}, "
                        f"country={vt.get('country') or 'unknown'}"
                    )
                    ioc = {
                        **ioc,
                        "enrichment_source": vt.get("source"),
                        "enrichment_summary": enrichment_summary,
                        "enrichment_json": json.dumps(vt, ensure_ascii=False),
                    }
            enriched.append(ioc)

        context.iocs = enriched
        logger.info("IOCExtractorAgent complete iocs=%d", len(enriched))
        return AgentResult(agent_name=self.name, success=True, output=enriched)
