from pydantic import BaseModel
from datetime import datetime
from typing import Optional, List

class IOCOut(BaseModel):
    id: int
    ioc_type: str
    value: str
    description: Optional[str]
    confidence: str
    source_context: Optional[str]
    is_approved: bool
    enrichment_source: Optional[str] = None
    enrichment_summary: Optional[str] = None
    enrichment_json: Optional[str] = None
    class Config:
        from_attributes = True

class IOCUpdate(BaseModel):
    description: Optional[str] = None
    confidence: Optional[str] = None
    is_approved: Optional[bool] = None

class MitreOut(BaseModel):
    id: int
    technique_id: str
    technique_name: str
    evidence: Optional[str]
    confidence: str
    class Config:
        from_attributes = True

class DetectionOut(BaseModel):
    id: int
    rule_type: str
    title: str
    description: Optional[str]
    severity: str
    mitre_technique: Optional[str]
    rule_content: str
    status: str
    class Config:
        from_attributes = True

class DetectionUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    rule_content: Optional[str] = None
    status: Optional[str] = None

class AgentRunOut(BaseModel):
    id: int
    agent_name: str
    iteration: int
    success: bool
    notes: Optional[str]
    score: Optional[float] = None
    critique: Optional[str] = None
    created_at: datetime
    class Config:
        from_attributes = True

class ReportOut(BaseModel):
    id: int
    filename: str
    title: Optional[str]
    upload_date: datetime
    processing_status: str
    summary: Optional[str]
    raw_text: Optional[str] = None
    report_markdown: Optional[str] = None
    judge_score: Optional[float] = None
    judge_iterations: Optional[int] = None
    class Config:
        from_attributes = True

class ReportDetail(ReportOut):
    iocs: List[IOCOut] = []
    mappings: List[MitreOut] = []
    detections: List[DetectionOut] = []
