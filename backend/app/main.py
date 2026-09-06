import json
import logging
import os
from pathlib import Path

from fastapi import Depends, FastAPI, File, HTTPException, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from .database import get_db, init_db
from .models import DetectionRule, IOC, MitreMapping, Report
from .schemas import DetectionOut, DetectionUpdate, IOCOut, IOCUpdate, ReportDetail, ReportOut
from .services.export_service import export_report
from .services.ioc_service import extract_iocs
from .services.judge_service import judge_iocs, judge_mitre_mappings, judge_sigma_rules, judge_status
from .services.llm_service import generate_overview_with_llm, llm_status, test_llm_connection
from .services.mitre_service import map_mitre
from .services.pdf_service import extract_text_from_pdf
from .services.rule_service import generate_sigma_rules
from .services.virustotal_service import enrich_ip, vt_status
from .uploads import max_upload_bytes, sanitize_upload_filename, save_limited_upload, unique_target

logging.basicConfig(
    level=os.getenv("LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("ruleforge.api")
logging.getLogger("python_multipart.multipart").setLevel(logging.WARNING)

init_db()

app = FastAPI(title="ThreatIntel RuleForge API", version="0.1.0")

allowed_origins = os.getenv(
    "CORS_ALLOW_ORIGINS",
    "http://localhost:5173,http://127.0.0.1:5173",
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


def _build_ioc_record(item: dict) -> dict:
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

    return {
        **item,
        "enrichment_source": enrichment.get("source") if enrichment else None,
        "enrichment_summary": enrichment_summary,
        "enrichment_json": json.dumps(enrichment, ensure_ascii=False) if enrichment else None,
    }


@app.get("/")
def root():
    return {"name": "ThreatIntel RuleForge API", "status": "ok", "docs": "/docs", "health": "/health"}


@app.get("/health")
def health():
    return {"status": "ok", "llm": llm_status(), "judge": judge_status(), "virustotal": vt_status()}


@app.get("/llm/health")
def llm_health():
    return test_llm_connection()


@app.get("/virustotal/health")
def virustotal_health():
    return vt_status()


@app.get("/judge/health")
def judge_health():
    return judge_status()


@app.post("/reports/upload", response_model=ReportOut)
async def upload_report(file: UploadFile = File(...), db: Session = Depends(get_db)):
    try:
        filename = sanitize_upload_filename(file.filename)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    target = unique_target(STORAGE_DIR, filename)
    try:
        save_limited_upload(file.file, target)
    except ValueError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc

    report = Report(filename=filename, file_path=str(target), title=Path(filename).stem)
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
    db.commit()

    try:
        logger.info("Processing report_id=%s filename=%s", report.id, report.filename)
        text = extract_text_from_pdf(report.file_path)
        logger.info("PDF extraction complete report_id=%s text_chars=%s", report.id, len(text or ""))

        overview = generate_overview_with_llm(text, report.filename)
        iocs = judge_iocs(text, extract_iocs(text))
        ioc_records = [_build_ioc_record(item) for item in iocs]
        mappings = judge_mitre_mappings(text, map_mitre(text))
        rules = judge_sigma_rules(text, generate_sigma_rules(iocs, mappings, text))

        logger.info(
            "Processing outputs report_id=%s iocs=%s mappings=%s rules=%s",
            report.id,
            len(ioc_records),
            len(mappings),
            len(rules),
        )

        # Replace the previous analysis only after the new run has completed.
        db.query(IOC).filter(IOC.report_id == report_id).delete(synchronize_session=False)
        db.query(MitreMapping).filter(MitreMapping.report_id == report_id).delete(synchronize_session=False)
        db.query(DetectionRule).filter(DetectionRule.report_id == report_id).delete(synchronize_session=False)

        report.raw_text = text
        report.title = overview.get("title") or report.title
        report.summary = json.dumps(overview, ensure_ascii=False)
        report.processing_status = "processed"

        for item in ioc_records:
            db.add(IOC(report_id=report.id, **item))
        for item in mappings:
            db.add(MitreMapping(report_id=report.id, **item))
        for item in rules:
            db.add(DetectionRule(report_id=report.id, **item))

        db.commit()
        db.refresh(report)
        logger.info("Processing finished report_id=%s", report.id)
        return report
    except Exception as exc:
        db.rollback()
        failed_report = db.query(Report).filter(Report.id == report_id).first()
        if failed_report:
            failed_report.processing_status = "failed"
            db.commit()
        logger.exception("Processing failed report_id=%s error_type=%s", report_id, type(exc).__name__)
        raise HTTPException(status_code=500, detail="Report processing failed. Check backend logs for details.") from exc


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
