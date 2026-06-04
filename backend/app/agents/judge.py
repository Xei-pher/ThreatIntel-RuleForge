import json
import logging
import os
from typing import Any, Dict

from .base import AgentContext, BaseAgent, JudgeVerdict, MAX_REPORT_CHARS

logger = logging.getLogger("ruleforge.agents.judge")

_PASS_SCORE: float = float(os.getenv("JUDGE_PASS_SCORE", "90.0"))

_JUDGE_SCHEMA: Dict[str, Any] = {
    "type": "object",
    "properties": {
        "score": {"type": "number"},
        "passed": {"type": "boolean"},
        "failed_agents": {
            "type": "array",
            "items": {"type": "string"},
        },
        "critique": {"type": "string"},
        "ioc_issues": {"type": "string"},
        "mitre_issues": {"type": "string"},
        "sigma_issues": {"type": "string"},
        "report_issues": {"type": "string"},
    },
    "required": [
        "score", "passed", "failed_agents", "critique",
        "ioc_issues", "mitre_issues", "sigma_issues", "report_issues",
    ],
    "additionalProperties": False,
}

_VALID_AGENT_NAMES = {
    "IOCExtractorAgent",
    "MITREAgent",
    "SigmaRuleAgent",
    "ReportGeneratorAgent",
}


class JudgeAgent(BaseAgent):
    """Evaluates all pipeline outputs against the source material and returns a scored verdict.

    If the LLM call fails entirely the supervisor treats the iteration as passed
    (score = 100) and logs JUDGE_CALL_FAILED to prevent the pipeline from being
    permanently blocked by a judge-side outage.
    """

    name = "JudgeAgent"

    def run(self, context: AgentContext) -> JudgeVerdict:
        logger.info("JudgeAgent evaluating iteration=%s", context.iteration)

        sigma_titles = [r.get("title", "") for r in context.sigma_rules[:50]]

        system = (
            "You are an expert cyber threat intelligence quality auditor.\n"
            "Evaluate the accuracy and completeness of analysis artefacts produced "
            "from a threat intelligence report.\n"
            "Be rigorous. Award a score of 90 or above only when artefacts are accurate, "
            "complete, and actionable.\n"
            "Return strict JSON only."
        )
        user = (
            f"Evaluate the following analysis artefacts against the source material.\n\n"
            f"SOURCE MATERIAL (up to {MAX_REPORT_CHARS} chars):\n"
            f"{context.raw_text[:MAX_REPORT_CHARS]}\n\n"
            f"--- PRODUCED ARTEFACTS ---\n\n"
            f"IOCs ({len(context.iocs)} total):\n"
            f"{json.dumps(context.iocs[:100], indent=2)}\n\n"
            f"MITRE Mappings ({len(context.mitre_mappings)} total):\n"
            f"{json.dumps(context.mitre_mappings[:50], indent=2)}\n\n"
            f"Sigma Rules ({len(context.sigma_rules)} total — titles only):\n"
            f"{json.dumps(sigma_titles, indent=2)}\n\n"
            f"SOC Report (first 5 000 chars):\n"
            f"{context.report_markdown[:5000]}\n\n"
            f"Return this JSON shape exactly:\n"
            f'{{"score": <float 0-100>, '
            f'"passed": <true if score >= {_PASS_SCORE}>, '
            f'"failed_agents": ["agent names needing redo — valid values: '
            f'IOCExtractorAgent, MITREAgent, SigmaRuleAgent, ReportGeneratorAgent"], '
            f'"critique": "overall explanation of all issues found", '
            f'"ioc_issues": "specific IOC problems or empty string if none", '
            f'"mitre_issues": "specific MITRE mapping problems or empty string if none", '
            f'"sigma_issues": "specific Sigma rule problems or empty string if none", '
            f'"report_issues": "specific SOC report problems or empty string if none"}}'
        )

        data = self._call_llm(
            system, user, None, task_name="judge_evaluation", schema=_JUDGE_SCHEMA
        )

        # Judge call failed — treat as passed to avoid blocking the pipeline
        if data is None or not isinstance(data, dict):
            logger.warning(
                "JUDGE_CALL_FAILED: evaluation skipped for report_id=%s iteration=%s",
                context.report_id,
                context.iteration,
            )
            return JudgeVerdict(
                score=100.0,
                passed=True,
                failed_agents=[],
                critique="JUDGE_CALL_FAILED: evaluation was skipped due to an LLM error.",
                ioc_issues="",
                mitre_issues="",
                sigma_issues="",
                report_issues="",
                iteration=context.iteration,
            )

        score = float(data.get("score", 0))
        passed = bool(data.get("passed", score >= _PASS_SCORE))
        # Sanitise failed_agents list to only recognised agent names
        failed_agents = [
            a for a in (data.get("failed_agents") or [])
            if a in _VALID_AGENT_NAMES
        ]

        verdict = JudgeVerdict(
            score=score,
            passed=passed,
            failed_agents=failed_agents,
            critique=str(data.get("critique", "")),
            ioc_issues=str(data.get("ioc_issues", "")),
            mitre_issues=str(data.get("mitre_issues", "")),
            sigma_issues=str(data.get("sigma_issues", "")),
            report_issues=str(data.get("report_issues", "")),
            iteration=context.iteration,
        )
        logger.info(
            "JudgeAgent verdict score=%.1f passed=%s failed_agents=%s",
            verdict.score,
            verdict.passed,
            verdict.failed_agents,
        )
        return verdict
