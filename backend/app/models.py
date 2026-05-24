from sqlalchemy import Column, Integer, String, Text, Boolean, ForeignKey, DateTime
from sqlalchemy.orm import relationship
from datetime import datetime
from .database import Base

class Report(Base):
    __tablename__ = "reports"
    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    file_path = Column(String, nullable=False)
    title = Column(String, nullable=True)
    upload_date = Column(DateTime, default=datetime.utcnow)
    processing_status = Column(String, default="uploaded")
    raw_text = Column(Text, nullable=True)
    summary = Column(Text, nullable=True)

    iocs = relationship("IOC", back_populates="report", cascade="all, delete-orphan")
    mappings = relationship("MitreMapping", back_populates="report", cascade="all, delete-orphan")
    detections = relationship("DetectionRule", back_populates="report", cascade="all, delete-orphan")

class IOC(Base):
    __tablename__ = "iocs"
    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(Integer, ForeignKey("reports.id"))
    ioc_type = Column(String, nullable=False)
    value = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    confidence = Column(String, default="medium")
    source_context = Column(Text, nullable=True)
    is_approved = Column(Boolean, default=True)
    enrichment_source = Column(String, nullable=True)
    enrichment_summary = Column(Text, nullable=True)
    enrichment_json = Column(Text, nullable=True)
    report = relationship("Report", back_populates="iocs")

class MitreMapping(Base):
    __tablename__ = "mitre_mappings"
    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(Integer, ForeignKey("reports.id"))
    technique_id = Column(String, nullable=False)
    technique_name = Column(String, nullable=False)
    evidence = Column(Text, nullable=True)
    confidence = Column(String, default="medium")
    report = relationship("Report", back_populates="mappings")

class DetectionRule(Base):
    __tablename__ = "detection_rules"
    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(Integer, ForeignKey("reports.id"))
    rule_type = Column(String, default="sigma")
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, default="medium")
    mitre_technique = Column(String, nullable=True)
    rule_content = Column(Text, nullable=False)
    status = Column(String, default="draft")
    report = relationship("Report", back_populates="detections")
