from sqlalchemy.orm import Session
from typing import List, Optional
from datetime import datetime
from app.db import models


# ============= FINDING CRUD =============

def create_finding(db: Session, finding_data: dict) -> models.Finding:
    """Create a new finding"""
    finding = models.Finding(**finding_data)
    db.add(finding)
    db.commit()
    db.refresh(finding)
    return finding


def get_finding(db: Session, finding_id: int) -> Optional[models.Finding]:
    """Get a finding by ID"""
    return db.query(models.Finding).filter(models.Finding.id == finding_id).first()


def get_findings(db: Session, skip: int = 0, limit: int = 100, severity: Optional[str] = None) -> List[models.Finding]:
    """Get all findings with optional filtering"""
    query = db.query(models.Finding)
    if severity:
        query = query.filter(models.Finding.severity == severity)
    return query.offset(skip).limit(limit).all()


def update_finding(db: Session, finding_id: int, update_data: dict) -> Optional[models.Finding]:
    """Update a finding"""
    finding = get_finding(db, finding_id)
    if finding:
        for key, value in update_data.items():
            setattr(finding, key, value)
        finding.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(finding)
    return finding


def delete_finding(db: Session, finding_id: int) -> bool:
    """Delete a finding"""
    finding = get_finding(db, finding_id)
    if finding:
        db.delete(finding)
        db.commit()
        return True
    return False


# ============= ANOMALY CRUD =============

def create_anomaly(db: Session, anomaly_data: dict) -> models.Anomaly:
    """Create a new anomaly"""
    anomaly = models.Anomaly(**anomaly_data)
    db.add(anomaly)
    db.commit()
    db.refresh(anomaly)
    return anomaly


def get_anomaly(db: Session, anomaly_id: int) -> Optional[models.Anomaly]:
    """Get an anomaly by ID"""
    return db.query(models.Anomaly).filter(models.Anomaly.id == anomaly_id).first()


def get_anomalies(db: Session, skip: int = 0, limit: int = 100, anomaly_type: Optional[str] = None) -> List[models.Anomaly]:
    """Get all anomalies with optional filtering"""
    query = db.query(models.Anomaly)
    if anomaly_type:
        query = query.filter(models.Anomaly.anomaly_type == anomaly_type)
    return query.offset(skip).limit(limit).all()


def update_anomaly(db: Session, anomaly_id: int, update_data: dict) -> Optional[models.Anomaly]:
    """Update an anomaly"""
    anomaly = get_anomaly(db, anomaly_id)
    if anomaly:
        for key, value in update_data.items():
            setattr(anomaly, key, value)
        anomaly.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(anomaly)
    return anomaly


def delete_anomaly(db: Session, anomaly_id: int) -> bool:
    """Delete an anomaly"""
    anomaly = get_anomaly(db, anomaly_id)
    if anomaly:
        db.delete(anomaly)
        db.commit()
        return True
    return False


# ============= REPORT CRUD =============

def create_report(db: Session, report_data: dict) -> models.Report:
    """Create a new report"""
    report = models.Report(**report_data)
    db.add(report)
    db.commit()
    db.refresh(report)
    return report


def get_report(db: Session, report_id: int) -> Optional[models.Report]:
    """Get a report by ID"""
    return db.query(models.Report).filter(models.Report.id == report_id).first()


def get_reports(db: Session, skip: int = 0, limit: int = 100, report_type: Optional[str] = None) -> List[models.Report]:
    """Get all reports with optional filtering"""
    query = db.query(models.Report)
    if report_type:
        query = query.filter(models.Report.report_type == report_type)
    return query.order_by(models.Report.created_at.desc()).offset(skip).limit(limit).all()


def update_report(db: Session, report_id: int, update_data: dict) -> Optional[models.Report]:
    """Update a report"""
    report = get_report(db, report_id)
    if report:
        for key, value in update_data.items():
            setattr(report, key, value)
        report.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(report)
    return report


def delete_report(db: Session, report_id: int) -> bool:
    """Delete a report"""
    report = get_report(db, report_id)
    if report:
        db.delete(report)
        db.commit()
        return True
    return False


# ============= SCAN CRUD =============

def create_scan(db: Session, scan_data: dict) -> models.Scan:
    """Create a new scan"""
    scan = models.Scan(**scan_data)
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


def get_scan(db: Session, scan_id: int) -> Optional[models.Scan]:
    """Get a scan by ID"""
    return db.query(models.Scan).filter(models.Scan.id == scan_id).first()


def get_scans(db: Session, skip: int = 0, limit: int = 100) -> List[models.Scan]:
    """Get all scans"""
    return db.query(models.Scan).order_by(models.Scan.created_at.desc()).offset(skip).limit(limit).all()


def update_scan(db: Session, scan_id: int, update_data: dict) -> Optional[models.Scan]:
    """Update a scan"""
    scan = get_scan(db, scan_id)
    if scan:
        for key, value in update_data.items():
            setattr(scan, key, value)
        scan.updated_at = datetime.utcnow()
        db.commit()
        db.refresh(scan)
    return scan


def delete_scan(db: Session, scan_id: int) -> bool:
    """Delete a scan"""
    scan = get_scan(db, scan_id)
    if scan:
        db.delete(scan)
        db.commit()
        return True
    return False


# ============= UTILITY FUNCTIONS =============

def get_findings_by_scan(db: Session, scan_id: int) -> List[models.Finding]:
    """Get all findings for a specific scan"""
    return db.query(models.Finding).filter(models.Finding.scan_id == scan_id).all()


def get_findings_by_severity(db: Session, severity: str, limit: int = 100) -> List[models.Finding]:
    """Get findings by severity level"""
    return db.query(models.Finding).filter(models.Finding.severity == severity).limit(limit).all()


def get_recent_anomalies(db: Session, limit: int = 50) -> List[models.Anomaly]:
    """Get most recent anomalies"""
    return db.query(models.Anomaly).order_by(models.Anomaly.detected_at.desc()).limit(limit).all()


def get_statistics(db: Session) -> dict:
    """Get overall statistics"""
    return {
        "total_findings": db.query(models.Finding).count(),
        "total_anomalies": db.query(models.Anomaly).count(),
        "total_reports": db.query(models.Report).count(),
        "total_scans": db.query(models.Scan).count(),
        "critical_findings": db.query(models.Finding).filter(
            models.Finding.severity == models.SeverityLevel.CRITICAL
        ).count(),
        "high_findings": db.query(models.Finding).filter(
            models.Finding.severity == models.SeverityLevel.HIGH
        ).count(),
    }
