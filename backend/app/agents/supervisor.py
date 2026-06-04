import logging
import os
from typing import Set

from sqlalchemy.orm import Session

from .base import AgentContext, AgentResult, JudgeVerdict
from .pdf_reader import PDFReaderAgent
from .ioc_extractor import IOCExtractorAgent
from .mitre_agent import MITREAgent
from .sigma_agent import SigmaRuleAgent
from .report_generator import ReportGeneratorAgent
from .judge import JudgeAgent

logger = logging.getLogger("ruleforge.agents.supervisor")


def _log_agent_run(
    db: Session,
    report_id: int,
    agent_name: str,
    iteration: int,
    result: object,
) -> None:
    """Persist an AgentRun audit record to the database."""
    from ..models import AgentRun

    if isinstance(result, JudgeVerdict):
        run = AgentRun(
            report_id=report_id,
            agent_name=agent_name,
            iteration=iteration,
            success=True,
            notes="",
            score=result.score,
            critique=result.critique,
        )
    elif isinstance(result, AgentResult):
        run = AgentRun(
            report_id=report_id,
            agent_name=agent_name,
            iteration=iteration,
            success=result.success,
            notes=result.notes or "",
            score=None,
            critique=None,
        )
    else:
        run = AgentRun(
            report_id=report_id,
            agent_name=agent_name,
            iteration=iteration,
            success=True,
            notes=str(result),
            score=None,
            critique=None,
        )

    db.add(run)
    db.commit()


class AgentSupervisor:
    """Orchestrates the multi-agent pipeline under a judge-supervised iteration loop.

    Execution order is always:
        PDFReaderAgent → IOCExtractorAgent → MITREAgent → SigmaRuleAgent
        → ReportGeneratorAgent → JudgeAgent

    On each iteration the JudgeAgent scores the output. If the score is below the
    pass threshold and iterations remain, only the agents flagged by the Judge are
    re-executed. The PDFReaderAgent is excluded from all redo sets — its output is
    immutable.
    """

    def __init__(self, provider: object) -> None:
        self._provider = provider
        self._pass_score = float(os.getenv("JUDGE_PASS_SCORE", "90.0"))
        self._max_iterations = int(os.getenv("JUDGE_MAX_ITERATIONS", "3"))
        self._judge_active: bool = (
            os.getenv("JUDGE_AGENT_ACTIVE", "true").lower() in {"1", "true", "yes", "y"}
        )
        self._pipeline = [
            PDFReaderAgent(provider),
            IOCExtractorAgent(provider),
            MITREAgent(provider),
            SigmaRuleAgent(provider),
            ReportGeneratorAgent(provider),
        ]
        self._judge = JudgeAgent(provider)
        logger.info(
            "AgentSupervisor initialised pass_score=%.1f max_iterations=%d "
            "judge_active=%s agents=%s",
            self._pass_score,
            self._max_iterations,
            self._judge_active,
            [a.name for a in self._pipeline],
        )

    def run(self, report_id: int, pdf_path: str, db: Session) -> AgentContext:
        """Run the full supervised pipeline and return the final AgentContext.

        The context holds all accumulated agent outputs. The caller (main.py) is
        responsible for persisting results to the database.
        """
        context = AgentContext(report_id=report_id, pdf_path=pdf_path)
        # All pipeline agents run on the first iteration
        agents_to_run: Set[str] = {a.name for a in self._pipeline}

        for iteration in range(1, self._max_iterations + 1):
            context.iteration = iteration
            logger.info(
                "Supervisor iteration %d/%d starting report_id=%d",
                iteration,
                self._max_iterations,
                report_id,
            )

            for agent in self._pipeline:
                if agent.name in agents_to_run:
                    logger.info(
                        "Running agent=%s iteration=%d", agent.name, iteration
                    )
                    result = agent.run(context)
                    _log_agent_run(db, report_id, agent.name, iteration, result)
                else:
                    logger.info(
                        "Skipping agent=%s (not in redo set for iteration %d)",
                        agent.name,
                        iteration,
                    )

            # Judge evaluation — skipped when JUDGE_AGENT_ACTIVE=false
            if not self._judge_active:
                logger.info(
                    "Supervisor iteration %d/%d complete — Judge disabled "
                    "(JUDGE_AGENT_ACTIVE=false). Accepting result. report_id=%d",
                    iteration,
                    self._max_iterations,
                    report_id,
                )
                break

            verdict = self._judge.run(context)
            _log_agent_run(db, report_id, self._judge.name, iteration, verdict)
            context.judge_feedback = verdict

            logger.info(
                "Supervisor iteration %d/%d complete score=%.1f passed=%s report_id=%d",
                iteration,
                self._max_iterations,
                verdict.score,
                verdict.passed,
                report_id,
            )

            if verdict.passed:
                break

            if iteration == self._max_iterations:
                logger.warning(
                    "JUDGE_MAX_ITERATIONS_REACHED report_id=%d best_score=%.1f",
                    report_id,
                    verdict.score,
                )
                break

            # Build redo set for next iteration; PDFReaderAgent is always excluded
            agents_to_run = {
                name for name in verdict.failed_agents
                if name != PDFReaderAgent.name
            }
            if not agents_to_run:
                # Judge passed no redo agents despite failing — avoid infinite loop
                logger.warning(
                    "Judge score=%.1f but failed_agents is empty. Accepting result.",
                    verdict.score,
                )
                break
            logger.info("Supervisor redo set for iteration %d: %s", iteration + 1, agents_to_run)

        return context
