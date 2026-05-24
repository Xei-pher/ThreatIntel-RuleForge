from fastapi import FastAPI, UploadFile, File, Depends, HTTPException
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pathlib import Path
import json
import logging
import os
import shutil
from sqlalchemy import text as sql_text

from .database import Base, engine, get_db
from .models import Report, IOC, MitreMapping, DetectionRule
from .schemas import ReportOut, ReportDetail, IOCOut, IOCUpdate, DetectionOut, DetectionUpdate
from .services.pdf_service import extract_text_from_pdf
from .services.ioc_service import extract_iocs
from .services.mitre_service import map_mitre
from .services.rule_service import generate_sigma_rules
from .services.export_service import export_report
from .services.llm_service import llm_status, test_llm_connection, generate_overview_with_llm
from .services.virustotal_service import vt_status, enrich_ip

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("ruleforge.api")
logging.getLogger("python_multipart.multipart").setLevel(logging.WARNING)

Base.metadata.create_all(bind=engine)

def ensure_sqlite_columns():
    # Lightweight dev migration for existing local SQLite DBs.
    # Safe to run repeatedly; skips columns that already exist.
    with engine.begin() as conn:
        try:
            columns = {row[1] for row in conn.execute(sql_text("PRAGMA table_info(iocs)"))}
            additions = {
                "enrichment_source": "ALTER TABLE iocs ADD COLUMN enrichment_source VARCHAR",
                "enrichment_summary": "ALTER TABLE iocs ADD COLUMN enrichment_summary TEXT",
                "enrichment_json": "ALTER TABLE iocs ADD COLUMN enrichment_json TEXT",
            }
            for column, ddl in additions.items():
                if column not in columns:
                    conn.execute(sql_text(ddl))
                    logger.info("Applied local DB migration: added iocs.%s", column)
        except Exception as exc:
            logger.warning("Local DB migration skipped/error: %s", exc)

ensure_sqlite_columns()

app = FastAPI(title="ThreatIntel RuleForge API", version="0.1.0")

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

@app.get("/")
def root():
    return {"name": "ThreatIntel RuleForge API", "status": "ok", "docs": "/docs", "health": "/health"}

@app.get("/health")
def health():
    return {"status": "ok", "llm": llm_status(), "virustotal": vt_status()}

@app.get("/llm/health")
def llm_health():
    return test_llm_connection()

@app.get("/virustotal/health")
def virustotal_health():
    return vt_status()

@app.post("/reports/upload", response_model=ReportOut)
async def upload_report(file: UploadFile = File(...), db: Session = Depends(get_db)):
    if not file.filename.lower().endswith(".pdf"):
        raise HTTPException(status_code=400, detail="Only PDF files are supported in this MVP.")
    target = STORAGE_DIR / file.filename
    counter = 1
    while target.exists():
        target = STORAGE_DIR / f"{target.stem}_{counter}{target.suffix}"
        counter += 1
    with target.open("wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    report = Report(filename=file.filename, file_path=str(target), title=file.filename.rsplit(".", 1)[0])
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

@app.post("/reports/{report_id}/process", response_model=ReportDetail)
def process_report(report_id: int, db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")

    report.processing_status = "processing"
    db.query(IOC).filter(IOC.report_id == report_id).delete()
    db.query(MitreMapping).filter(MitreMapping.report_id == report_id).delete()
    db.query(DetectionRule).filter(DetectionRule.report_id == report_id).delete()
    db.commit()

    logger.info("Processing report_id=%s filename=%s", report.id, report.filename)
    text = extract_text_from_pdf(report.file_path)
    logger.info("PDF extraction complete report_id=%s text_chars=%s", report.id, len(text or ""))
    report.raw_text = text

    overview = generate_overview_with_llm(text, report.filename)
    logger.info(
        "Overview generation complete report_id=%s title=%s confidence=%s",
        report.id,
        overview.get("title"),
        overview.get("confidence"),
    )
    report.title = overview.get("title") or report.title
    report.summary = json.dumps(overview, ensure_ascii=False)

    iocs = extract_iocs(text)
    logger.info("IOC extraction complete report_id=%s count=%s", report.id, len(iocs))
    for item in iocs:
        enrichment = None
        if item.get("ioc_type") in {"ipv4", "ip", "ip_address"}:
            enrichment = enrich_ip(item.get("value", ""))
        enrichment_summary = None
        if enrichment:
            enrichment_summary = (
                f"VT malicious={enrichment.get('malicious', 0)}, "
                f"suspicious={enrichment.get('suspicious', 0)}, "
                f"AS={enrichment.get('as_owner') or 'unknown'}, "
                f"country={enrichment.get('country') or 'unknown'}"
            )
        db.add(IOC(
            report_id=report.id,
            enrichment_source=enrichment.get("source") if enrichment else None,
            enrichment_summary=enrichment_summary,
            enrichment_json=json.dumps(enrichment, ensure_ascii=False) if enrichment else None,
            **item,
        ))

    mappings = map_mitre(text)
    logger.info("MITRE mapping complete report_id=%s count=%s", report.id, len(mappings))
    for item in mappings:
        db.add(MitreMapping(report_id=report.id, **item))

    db.flush()
    rules = generate_sigma_rules(iocs, mappings, text)
    logger.info("Sigma generation complete report_id=%s count=%s", report.id, len(rules))
    for item in rules:
        db.add(DetectionRule(report_id=report.id, **item))

    report.processing_status = "processed"
    logger.info("Processing finished report_id=%s", report.id)
    db.commit()
    db.refresh(report)
    return report

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

@app.post("/reports/{report_id}/export")
def export(report_id: int, db: Session = Depends(get_db)):
    report = db.query(Report).filter(Report.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    path = export_report(report, report.iocs, report.mappings, report.detections)
    return FileResponse(path, media_type="application/zip", filename=Path(path).name)
