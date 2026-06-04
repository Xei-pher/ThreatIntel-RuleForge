from fastapi import FastAPI, UploadFile, File, Depends, HTTPException
from fastapi.responses import FileResponse, PlainTextResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pathlib import Path
import json
import logging
import os
import shutil
from sqlalchemy import text as sql_text

from .database import Base, engine, get_db
from .models import Report, IOC, MitreMapping, DetectionRule, AgentRun
from .schemas import (
    ReportOut, ReportDetail, IOCOut, IOCUpdate,
    DetectionOut, DetectionUpdate, AgentRunOut,
)
from .services.export_service import export_report
from .services.llm_service import llm_status, test_llm_connection
from .services.virustotal_service import vt_status

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("ruleforge.api")
logging.getLogger("python_multipart.multipart").setLevel(logging.WARNING)

Base.metadata.create_all(bind=engine)


def ensure_sqlite_columns() -> None:
    """Lightweight idempotent migration for existing local SQLite DBs."""
    with engine.begin() as conn:
        try:
            # iocs table
            ioc_cols = {row[1] for row in conn.execute(sql_text("PRAGMA table_info(iocs)"))}
            for col, ddl in {
                "enrichment_source": "ALTER TABLE iocs ADD COLUMN enrichment_source VARCHAR",
                "enrichment_summary": "ALTER TABLE iocs ADD COLUMN enrichment_summary TEXT",
                "enrichment_json":    "ALTER TABLE iocs ADD COLUMN enrichment_json TEXT",
            }.items():
                if col not in ioc_cols:
                    conn.execute(sql_text(ddl))
                    logger.info("DB migration: added iocs.%s", col)

            # reports table — multi-agent fields
            report_cols = {row[1] for row in conn.execute(sql_text("PRAGMA table_info(reports)"))}
            for col, ddl in {
                "report_markdown":  "ALTER TABLE reports ADD COLUMN report_markdown TEXT",
                "judge_score":      "ALTER TABLE reports ADD COLUMN judge_score REAL",
                "judge_iterations": "ALTER TABLE reports ADD COLUMN judge_iterations INTEGER",
            }.items():
                if col not in report_cols:
                    conn.execute(sql_text(ddl))
                    logger.info("DB migration: added reports.%s", col)

            # mitre_mappings — tactic column added by MITREAgent
            mitre_cols = {row[1] for row in conn.execute(sql_text("PRAGMA table_info(mitre_mappings)"))}
            if "tactic" not in mitre_cols:
                conn.execute(sql_text("ALTER TABLE mitre_mappings ADD COLUMN tactic VARCHAR"))
                logger.info("DB migration: added mitre_mappings.tactic")

        except Exception as exc:
            logger.warning("DB migration skipped/error: %s", exc)


ensure_sqlite_columns()

app = FastAPI(title="ThreatIntel RuleForge API", version="0.2.0")

allowed_origins = os.getenv(
    "CORS_ALLOW_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173,http://0.0.0.0:5173",
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[origin.strip() for origin in allowed_origins if origin.strip()],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STORAGE_DIR = Path(__file__).resolve().parents[1] / "storage" / "reports"
STORAGE_DIR.mkdir(parents=True, exist_ok=True)


# ---------------------------------------------------------------------------
# Root / health
# ---------------------------------------------------------------------------

@app.get("/")
def root():
    return {
        "name": "ThreatIntel RuleForge API",
        "version": "0.2.0",
        "status": "ok",
        "docs": "/docs",
        "health": "/health",
    }


@app.get("/health")
def health():
    return {"status": "ok", "llm": llm_status(), "virustotal": vt_status()}


@app.get("/llm/health")
def llm_health():
    return test_llm_connection()


@app.get("/virustotal/health")
def virustotal_health():
    return vt_status()


# ---------------------------------------------------------------------------
# Report management
# ---------------------------------------------------------------------------

@app.post("/reports/upload", response_model=ReportOut)
async def upload_report(file: UploadFile = File(...), db: Session = Depends(get_db)):
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF files are supported.")
    target = STORAGE_DIR / file.filename
    counter = 1
    while target.exists():
        target = STORAGE_DIR / f"{target.stem}_{counter}{target.suffix}"
        counter += 1
    with target.open("wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    report = Report(
        filename=file.filename,
        file_path=str(target),
        title=file.filename.rsplit(".", 1)[0],
    )
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


@app.get("/reports", response_model=list[ReportOut])
def list_reports(db: Session = Depends(get_db)):
    return db.query(Report).order_by(Report.upload_date.desc()).all()


@app.get("/reports/{report_id}", response_model=ReportDetail)
def get_report(report_id: int, db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return report


# ---------------------------------------------------------------------------
# Multi-agent processing pipeline
# ---------------------------------------------------------------------------

@app.post("/reports/{report_id}/process", response_model=ReportDetail)
def process_report(report_id: int, db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    # Verify a provider is available before starting (fast-fail)
    try:
        from .providers.factory import get_provider
        provider = get_provider()
    except Exception as exc:
        raise HTTPException(
            status_code=503,
            detail=f"LLM provider unavailable: {exc}. "
                   "Configure LLM_PROVIDER and the corresponding API key in backend/.env",
        )

    # Reset prior results
    report.processing_status = "processing"
    db.query(IOC).filter(IOC.report_id == report_id).delete()
    db.query(MitreMapping).filter(MitreMapping.report_id == report_id).delete()
    db.query(DetectionRule).filter(DetectionRule.report_id == report_id).delete()
    db.query(AgentRun).filter(AgentRun.report_id == report_id).delete()
    db.commit()

    logger.info("Starting multi-agent pipeline report_id=%s filename=%s", report.id, report.filename)

    from .agents.supervisor import AgentSupervisor

    try:
        supervisor = AgentSupervisor(provider)
        context = supervisor.run(report.id, report.file_path, db)
    except Exception as exc:
        logger.exception("Pipeline failed report_id=%s error=%s", report.id, exc)
        report.processing_status = "failed"
        db.commit()
        raise HTTPException(status_code=500, detail=f"Pipeline failed: {exc}")

    # -----------------------------------------------------------------------
    # Persist agent outputs to the database
    # -----------------------------------------------------------------------

    report.raw_text = context.raw_text

    # Overview JSON — derived from ReportGeneratorAgent; stored in summary for frontend
    if context.overview:
        report.title = context.overview.get("title") or report.title
        report.summary = json.dumps(context.overview, ensure_ascii=False)

    # Full SOC Markdown report
    report.report_markdown = context.report_markdown

    # Judge quality metrics
    if context.judge_feedback:
        report.judge_score = context.judge_feedback.score
        report.judge_iterations = context.judge_feedback.iteration

    # IOCs
    for ioc in context.iocs:
        db.add(IOC(
            report_id=report.id,
            ioc_type=ioc.get("ioc_type", "unknown"),
            value=ioc.get("value", ""),
            description=ioc.get("description", ""),
            confidence=ioc.get("confidence", "medium"),
            source_context=ioc.get("source_context", ""),
            enrichment_source=ioc.get("enrichment_source"),
            enrichment_summary=ioc.get("enrichment_summary"),
            enrichment_json=ioc.get("enrichment_json"),
        ))

    # MITRE mappings
    for m in context.mitre_mappings:
        db.add(MitreMapping(
            report_id=report.id,
            technique_id=m.get("technique_id", ""),
            technique_name=m.get("technique_name", ""),
            evidence=m.get("evidence", ""),
            confidence=m.get("confidence", "medium"),
        ))

    # Sigma rules
    for rule in context.sigma_rules:
        db.add(DetectionRule(
            report_id=report.id,
            rule_type=rule.get("rule_type", "sigma"),
            title=rule.get("title", "Untitled Rule"),
            description=rule.get("description", ""),
            severity=rule.get("severity", "medium"),
            mitre_technique=rule.get("mitre_technique", "") or None,
            rule_content=rule.get("rule_content", ""),
            status=rule.get("status", "draft"),
        ))

    report.processing_status = "processed"
    logger.info(
        "Pipeline complete report_id=%s iocs=%d mappings=%d rules=%d judge_score=%s",
        report.id,
        len(context.iocs),
        len(context.mitre_mappings),
        len(context.sigma_rules),
        context.judge_feedback.score if context.judge_feedback else "n/a",
    )
    db.commit()
    db.refresh(report)
    return report


# ---------------------------------------------------------------------------
# IOC endpoints
# ---------------------------------------------------------------------------

@app.get("/reports/{report_id}/iocs", response_model=list[IOCOut])
def get_iocs(report_id: int, db: Session = Depends(get_db)):
    return db.query(IOC).filter(IOC.report_id == report_id).all()


@app.patch("/iocs/{ioc_id}", response_model=IOCOut)
def update_ioc(ioc_id: int, payload: IOCUpdate, db: Session = Depends(get_db)):
    ioc = db.query(IOC).filter(IOC.id == ioc_id).first()
    if not ioc:
        raise HTTPException(status_code=404, detail="IOC not found")
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(ioc, key, value)
    db.commit()
    db.refresh(ioc)
    return ioc


# ---------------------------------------------------------------------------
# Detection rule endpoints
# ---------------------------------------------------------------------------

@app.get("/reports/{report_id}/detections", response_model=list[DetectionOut])
def get_detections(report_id: int, db: Session = Depends(get_db)):
    return db.query(DetectionRule).filter(DetectionRule.report_id == report_id).all()


@app.patch("/detections/{rule_id}", response_model=DetectionOut)
def update_detection(rule_id: int, payload: DetectionUpdate, db: Session = Depends(get_db)):
    rule = db.query(DetectionRule).filter(DetectionRule.id == rule_id).first()
    if not rule:
        raise HTTPException(status_code=404, detail="Detection rule not found")
    for key, value in payload.model_dump(exclude_unset=True).items():
        setattr(rule, key, value)
    db.commit()
    db.refresh(rule)
    return rule


# ---------------------------------------------------------------------------
# Agent run audit log
# ---------------------------------------------------------------------------

@app.get("/reports/{report_id}/agent-runs", response_model=list[AgentRunOut])
def get_agent_runs(report_id: int, db: Session = Depends(get_db)):
    """Return the full agent execution history for a report (all iterations)."""
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return (
        db.query(AgentRun)
        .filter(AgentRun.report_id == report_id)
        .order_by(AgentRun.id)
        .all()
    )


# ---------------------------------------------------------------------------
# SOC report endpoint
# ---------------------------------------------------------------------------

@app.get("/reports/{report_id}/report-md")
def get_report_markdown(report_id: int, db: Session = Depends(get_db)):
    """Return the SOC analyst Markdown report produced by ReportGeneratorAgent."""
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    if not report.report_markdown:
        raise HTTPException(
            status_code=404,
            detail="Markdown report not yet generated. Process the report first.",
        )
    return PlainTextResponse(
        content=report.report_markdown,
        media_type="text/markdown",
    )


# ---------------------------------------------------------------------------
# Export
# ---------------------------------------------------------------------------

@app.post("/reports/{report_id}/export")
def export(report_id: int, db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    path = export_report(report, report.iocs, report.mappings, report.detections)
    return FileResponse(path, media_type="application/zip", filename=Path(path).name)