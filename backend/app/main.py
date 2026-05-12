from fastapi import FastAPI, UploadFile, File, Depends, HTTPException
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from pathlib import Path
import shutil

from .database import Base, engine, get_db
from .models import Report, IOC, MitreMapping, DetectionRule
from .schemas import ReportOut, ReportDetail, IOCOut, IOCUpdate, DetectionOut, DetectionUpdate
from .services.pdf_service import extract_text_from_pdf
from .services.ioc_service import extract_iocs
from .services.mitre_service import map_mitre
from .services.rule_service import generate_sigma_rules
from .services.export_service import export_report

Base.metadata.create_all(bind=engine)

app = FastAPI(title="ThreatIntel RuleForge API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

STORAGE_DIR = Path(__file__).resolve().parents[1] / "storage" / "reports"
STORAGE_DIR.mkdir(parents=True, exist_ok=True)

@app.get("/health")
def health():
    return {"status": "ok"}

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

    text = extract_text_from_pdf(report.file_path)
    report.raw_text = text
    report.summary = text[:900] + ("..." if len(text) > 900 else "")

    iocs = extract_iocs(text)
    for item in iocs:
        db.add(IOC(report_id=report.id, **item))

    mappings = map_mitre(text)
    for item in mappings:
        db.add(MitreMapping(report_id=report.id, **item))

    db.flush()
    rules = generate_sigma_rules(iocs, mappings)
    for item in rules:
        db.add(DetectionRule(report_id=report.id, **item))

    report.processing_status = "processed"
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
