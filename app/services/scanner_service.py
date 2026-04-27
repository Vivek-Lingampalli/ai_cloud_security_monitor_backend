from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from datetime import datetime
import logging
import json

from app.scanners.s3_scanner import S3Scanner
# from app.scanners.ec2_scanner import EC2Scanner  # To be implemented
# from app.scanners.iam_scanner import IAMScanner  # To be implemented
from app.db import models, crud
from app.db.schemas import FindingCreate, SeverityLevel

logger = logging.getLogger(__name__)


class ScannerService:
    """
    Security Scanner Service
    Orchestrates security scans across AWS resources
    """
    
    def __init__(self, db: Session, region: Optional[str] = None):
        """
        Initialize Scanner Service
        
        Args:
            db: Database session
            region: AWS region to scan
        """
        self.db = db
        self.region = region or "us-east-1"
        
        # Initialize scanners
        self.s3_scanner = S3Scanner(region=self.region)
        # self.ec2_scanner = EC2Scanner(region=self.region)  # To be implemented
        # self.iam_scanner = IAMScanner(region=self.region)  # To be implemented
    
    def run_full_scan(self) -> models.Scan:
        """
        Run a comprehensive security scan across all AWS services
        
        Returns:
            Scan model with results
        """
        logger.info("Starting full security scan...")
        
        # Create scan record
        scan = self._create_scan_record("full")
        
        try:
            # Update scan status
            self._update_scan_status(scan.id, models.ScanStatus.IN_PROGRESS)
            
            all_findings = []
            resources_scanned = 0
            
            # Run S3 scan
            logger.info("Running S3 scan...")
            s3_findings = self.s3_scanner.scan()
            all_findings.extend(s3_findings)
            buckets = self.s3_scanner.list_buckets()
            resources_scanned += len(buckets)
            logger.info(f"S3 scan completed: {len(s3_findings)} findings from {len(buckets)} buckets")
            
            # TODO: Run EC2 scan
            # ec2_findings = self.ec2_scanner.scan()
            # all_findings.extend(ec2_findings)
            
            # TODO: Run IAM scan
            # iam_findings = self.iam_scanner.scan()
            # all_findings.extend(iam_findings)
            
            # Save findings to database
            logger.info(f"Saving {len(all_findings)} findings to database...")
            self._save_findings(scan.id, all_findings)
            
            # Update scan record with results
            self._complete_scan(scan.id, resources_scanned, len(all_findings))
            
            logger.info(f"Full scan completed successfully. Scan ID: {scan.id}")
            
        except Exception as e:
            logger.error(f"Error during full scan: {e}")
            self._fail_scan(scan.id, str(e))
            raise
        
        # Refresh scan object
        self.db.refresh(scan)
        return scan
    
    def run_s3_scan(self) -> models.Scan:
        """
        Run S3-specific security scan
        
        Returns:
            Scan model with S3 findings
        """
        logger.info("Starting S3 security scan...")
        
        # Create scan record
        scan = self._create_scan_record("s3")
        
        try:
            # Update scan status
            self._update_scan_status(scan.id, models.ScanStatus.IN_PROGRESS)
            
            # Run S3 scan
            findings = self.s3_scanner.scan()
            buckets = self.s3_scanner.list_buckets()
            
            # Save findings to database
            logger.info(f"Saving {len(findings)} S3 findings to database...")
            self._save_findings(scan.id, findings)
            
            # Update scan record
            self._complete_scan(scan.id, len(buckets), len(findings))
            
            logger.info(f"S3 scan completed. Scan ID: {scan.id}")
            
        except Exception as e:
            logger.error(f"Error during S3 scan: {e}")
            self._fail_scan(scan.id, str(e))
            raise
        
        # Refresh scan object
        self.db.refresh(scan)
        return scan
    
    def run_ec2_scan(self) -> models.Scan:
        """
        Run EC2-specific security scan
        
        Returns:
            Scan model with EC2 findings
        """
        logger.info("EC2 scanner not yet implemented")
        scan = self._create_scan_record("ec2")
        self._fail_scan(scan.id, "EC2 scanner not yet implemented")
        self.db.refresh(scan)
        return scan
    
    def run_iam_scan(self) -> models.Scan:
        """
        Run IAM-specific security scan
        
        Returns:
            Scan model with IAM findings
        """
        logger.info("IAM scanner not yet implemented")
        scan = self._create_scan_record("iam")
        self._fail_scan(scan.id, "IAM scanner not yet implemented")
        self.db.refresh(scan)
        return scan
    
    def get_scan(self, scan_id: int) -> Optional[models.Scan]:
        """
        Get scan by ID
        
        Args:
            scan_id: ID of the scan
            
        Returns:
            Scan model or None
        """
        return self.db.query(models.Scan).filter(models.Scan.id == scan_id).first()
    
    def list_scans(self, skip: int = 0, limit: int = 100) -> List[models.Scan]:
        """
        List all scans
        
        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return
            
        Returns:
            List of Scan models
        """
        return self.db.query(models.Scan).order_by(models.Scan.created_at.desc()).offset(skip).limit(limit).all()
    
    def get_scan_findings(self, scan_id: int) -> List[models.Finding]:
        """
        Get all findings for a specific scan
        
        Args:
            scan_id: ID of the scan
            
        Returns:
            List of Finding models
        """
        return self.db.query(models.Finding).filter(models.Finding.scan_id == scan_id).all()
    
    def get_scan_summary(self, scan_id: int) -> Dict[str, Any]:
        """
        Get summary statistics for a scan
        
        Args:
            scan_id: ID of the scan
            
        Returns:
            Dictionary with scan summary
        """
        scan = self.get_scan(scan_id)
        if not scan:
            return {}
        
        findings = self.get_scan_findings(scan_id)
        
        # Count findings by severity
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        resource_types = {}
        
        for finding in findings:
            severity_counts[finding.severity.value] = severity_counts.get(finding.severity.value, 0) + 1
            resource_types[finding.resource_type] = resource_types.get(finding.resource_type, 0) + 1
        
        return {
            'scan_id': scan.id,
            'scan_type': scan.scan_type,
            'status': scan.status.value,
            'started_at': scan.started_at,
            'completed_at': scan.completed_at,
            'duration_seconds': scan.duration_seconds,
            'resources_scanned': scan.resources_scanned,
            'total_findings': len(findings),
            'severity_breakdown': severity_counts,
            'resource_type_breakdown': resource_types,
            'error_message': scan.error_message
        }
    
    # ==================== Private Helper Methods ====================
    
    def _create_scan_record(self, scan_type: str) -> models.Scan:
        """Create a new scan record in the database"""
        scan = models.Scan(
            scan_type=scan_type,
            status=models.ScanStatus.PENDING,
            regions=json.dumps([self.region]),
            started_at=datetime.utcnow()
        )
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        logger.info(f"Created scan record: ID={scan.id}, Type={scan_type}")
        return scan
    
    def _update_scan_status(self, scan_id: int, status: models.ScanStatus):
        """Update scan status"""
        scan = self.get_scan(scan_id)
        if scan:
            scan.status = status
            scan.updated_at = datetime.utcnow()
            self.db.commit()
            logger.debug(f"Updated scan {scan_id} status to {status.value}")
    
    def _save_findings(self, scan_id: int, findings: List[FindingCreate]):
        """Save findings to database"""
        for finding_create in findings:
            finding_dict = finding_create.model_dump()
            finding_dict['scan_id'] = scan_id
            crud.create_finding(self.db, finding_dict)
        logger.info(f"Saved {len(findings)} findings for scan {scan_id}")
    
    def _complete_scan(self, scan_id: int, resources_scanned: int, findings_count: int):
        """Mark scan as completed with results"""
        scan = self.get_scan(scan_id)
        if scan:
            scan.status = models.ScanStatus.COMPLETED
            scan.completed_at = datetime.utcnow()
            scan.resources_scanned = resources_scanned
            scan.findings_count = findings_count
            
            # Calculate duration
            if scan.started_at:
                duration = (scan.completed_at - scan.started_at).total_seconds()
                scan.duration_seconds = int(duration)
            
            scan.updated_at = datetime.utcnow()
            self.db.commit()
            logger.info(f"Scan {scan_id} completed: {findings_count} findings, {resources_scanned} resources scanned")
    
    def _fail_scan(self, scan_id: int, error_message: str):
        """Mark scan as failed with error message"""
        scan = self.get_scan(scan_id)
        if scan:
            scan.status = models.ScanStatus.FAILED
            scan.completed_at = datetime.utcnow()
            scan.error_message = error_message
            
            # Calculate duration
            if scan.started_at:
                duration = (scan.completed_at - scan.started_at).total_seconds()
                scan.duration_seconds = int(duration)
            
            scan.updated_at = datetime.utcnow()
            self.db.commit()
            logger.error(f"Scan {scan_id} failed: {error_message}")
