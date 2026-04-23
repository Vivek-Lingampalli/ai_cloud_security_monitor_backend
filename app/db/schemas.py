from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime
from enum import Enum


class SeverityLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(str, Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


# ============= Finding Schemas =============

class FindingBase(BaseModel):
    title: str
    description: str
    severity: SeverityLevel
    resource_type: str
    resource_id: str
    resource_arn: Optional[str] = None
    region: Optional[str] = None
    account_id: Optional[str] = None


class FindingCreate(FindingBase):
    scan_id: Optional[int] = None


class FindingUpdate(BaseModel):
    status: Optional[str] = None
    ai_summary: Optional[str] = None
    remediation_steps: Optional[str] = None
    risk_score: Optional[float] = None


class FindingResponse(FindingBase):
    id: int
    risk_score: float
    ai_summary: Optional[str]
    remediation_steps: Optional[str]
    status: str
    scan_id: Optional[int]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ============= Anomaly Schemas =============

class AnomalyBase(BaseModel):
    anomaly_type: str
    description: str
    severity: SeverityLevel


class AnomalyCreate(AnomalyBase):
    event_name: Optional[str] = None
    event_source: Optional[str] = None
    user_identity: Optional[str] = None
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    location: Optional[str] = None
    is_new_location: int = 0
    event_time: Optional[datetime] = None


class AnomalyUpdate(BaseModel):
    status: Optional[str] = None
    ai_analysis: Optional[str] = None
    confidence_score: Optional[float] = None


class AnomalyResponse(AnomalyBase):
    id: int
    event_name: Optional[str]
    user_identity: Optional[str]
    source_ip: Optional[str]
    location: Optional[str]
    is_new_location: int
    confidence_score: float
    ai_analysis: Optional[str]
    status: str
    event_time: Optional[datetime]
    detected_at: datetime
    created_at: datetime

    class Config:
        from_attributes = True


# ============= Report Schemas =============

class ReportBase(BaseModel):
    title: str
    report_type: str


class ReportCreate(ReportBase):
    scan_id: Optional[int] = None


class ReportUpdate(BaseModel):
    executive_summary: Optional[str] = None
    findings_summary: Optional[str] = None
    anomalies_summary: Optional[str] = None
    recommendations: Optional[str] = None


class ReportResponse(ReportBase):
    id: int
    executive_summary: Optional[str]
    findings_summary: Optional[str]
    anomalies_summary: Optional[str]
    recommendations: Optional[str]
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    total_anomalies: int
    overall_risk_score: float
    scan_id: Optional[int]
    created_at: datetime

    class Config:
        from_attributes = True


# ============= Scan Schemas =============

class ScanBase(BaseModel):
    scan_type: str


class ScanCreate(ScanBase):
    account_id: Optional[str] = None
    regions: Optional[str] = None


class ScanUpdate(BaseModel):
    status: Optional[ScanStatus] = None
    resources_scanned: Optional[int] = None
    findings_count: Optional[int] = None
    completed_at: Optional[datetime] = None


class ScanResponse(ScanBase):
    id: int
    status: ScanStatus
    account_id: Optional[str]
    regions: Optional[str]
    resources_scanned: int
    findings_count: int
    anomalies_count: int
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    duration_seconds: Optional[int]
    error_message: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True
