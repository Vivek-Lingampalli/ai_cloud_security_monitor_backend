from sqlalchemy import Column, Integer, String, Text, DateTime, Float, ForeignKey, Enum
from sqlalchemy.orm import relationship
from datetime import datetime
import enum
from app.db.database import Base


class SeverityLevel(str, enum.Enum):
    """Security severity levels"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class ScanStatus(str, enum.Enum):
    """Scan status types"""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class Finding(Base):
    """Security findings from AWS scans"""
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(Enum(SeverityLevel), nullable=False, default=SeverityLevel.MEDIUM)
    resource_type = Column(String(100), nullable=False)  # S3, EC2, IAM, etc.
    resource_id = Column(String(255), nullable=False)
    resource_arn = Column(String(500))
    region = Column(String(50))
    account_id = Column(String(50))
    
    # AI-generated content
    risk_score = Column(Float, default=0.0)
    ai_summary = Column(Text)
    remediation_steps = Column(Text)
    
    # Metadata
    status = Column(String(50), default="open")  # open, acknowledged, resolved, false_positive
    scan_id = Column(Integer, ForeignKey("scans.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    scan = relationship("Scan", back_populates="findings")
    

class Anomaly(Base):
    """Detected anomalies from CloudTrail logs"""
    __tablename__ = "anomalies"

    id = Column(Integer, primary_key=True, index=True)
    anomaly_type = Column(String(100), nullable=False)  # login, api_call, privilege_escalation
    description = Column(Text, nullable=False)
    severity = Column(Enum(SeverityLevel), nullable=False, default=SeverityLevel.MEDIUM)
    
    # Event details
    event_name = Column(String(255))
    event_source = Column(String(255))
    user_identity = Column(String(255))
    source_ip = Column(String(50))
    user_agent = Column(String(500))
    
    # Location
    location = Column(String(100))  # Country/City
    is_new_location = Column(Integer, default=0)  # Boolean: 0 or 1
    
    # AI analysis
    confidence_score = Column(Float, default=0.0)
    ai_analysis = Column(Text)
    risk_indicators = Column(Text)  # JSON string of risk indicators
    
    # Metadata
    status = Column(String(50), default="new")  # new, investigating, resolved, false_positive
    event_time = Column(DateTime)
    detected_at = Column(DateTime, default=datetime.utcnow)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class Report(Base):
    """Security reports generated from findings and anomalies"""
    __tablename__ = "reports"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    report_type = Column(String(50), nullable=False)  # daily, weekly, monthly, on-demand
    
    # Report content
    executive_summary = Column(Text)
    findings_summary = Column(Text)
    anomalies_summary = Column(Text)
    recommendations = Column(Text)
    
    # Statistics
    total_findings = Column(Integer, default=0)
    critical_findings = Column(Integer, default=0)
    high_findings = Column(Integer, default=0)
    medium_findings = Column(Integer, default=0)
    low_findings = Column(Integer, default=0)
    total_anomalies = Column(Integer, default=0)
    
    # Risk metrics
    overall_risk_score = Column(Float, default=0.0)
    
    # Metadata
    scan_id = Column(Integer, ForeignKey("scans.id"))
    generated_by = Column(String(100), default="AI Security Monitor")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    scan = relationship("Scan", back_populates="reports")


class Scan(Base):
    """Security scan records"""
    __tablename__ = "scans"

    id = Column(Integer, primary_key=True, index=True)
    scan_type = Column(String(50), nullable=False)  # full, s3, ec2, iam, cloudtrail
    status = Column(Enum(ScanStatus), nullable=False, default=ScanStatus.PENDING)
    
    # Scan details
    account_id = Column(String(50))
    regions = Column(Text)  # JSON array of regions
    resources_scanned = Column(Integer, default=0)
    
    # Results
    findings_count = Column(Integer, default=0)
    anomalies_count = Column(Integer, default=0)
    
    # Timing
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    duration_seconds = Column(Integer)
    
    # Metadata
    error_message = Column(Text)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    findings = relationship("Finding", back_populates="scan", cascade="all, delete-orphan")
    reports = relationship("Report", back_populates="scan", cascade="all, delete-orphan")
