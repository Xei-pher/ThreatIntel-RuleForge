from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, ConfigDict, Field


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class IOCOut(ORMModel):
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
    judge_decision: Optional[str] = None
    judge_score: Optional[int] = None
    judge_reason: Optional[str] = None


class IOCUpdate(BaseModel):
    description: Optional[str] = None
    confidence: Optional[str] = None
    is_approved: Optional[bool] = None


class MitreOut(ORMModel):
    id: int
    technique_id: str
    technique_name: str
    evidence: Optional[str]
    confidence: str
    judge_decision: Optional[str] = None
    judge_score: Optional[int] = None
    judge_reason: Optional[str] = None


class DetectionOut(ORMModel):
    id: int
    rule_type: str
    title: str
    description: Optional[str]
    severity: str
    mitre_technique: Optional[str]
    rule_content: str
    status: str
    judge_decision: Optional[str] = None
    judge_score: Optional[int] = None
    judge_reason: Optional[str] = None


class DetectionUpdate(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    rule_content: Optional[str] = None
    status: Optional[str] = None


class ReportOut(ORMModel):
    id: int
    filename: str
    title: Optional[str]
    upload_date: datetime
    processing_status: str
    summary: Optional[str]
    raw_text: Optional[str] = None


class ReportDetail(ReportOut):
    iocs: List[IOCOut] = Field(default_factory=list)
    mappings: List[MitreOut] = Field(default_factory=list)
    detections: List[DetectionOut] = Field(default_factory=list)
