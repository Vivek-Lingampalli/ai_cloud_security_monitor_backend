from fastapi import APIRouter, Depends, HTTPException, Query, Body
from sqlalchemy.orm import Session
from typing import Optional, List
import logging

from app.db.database import get_db
from app.services.scanner_service import ScannerService
from app.db import schemas

logger = logging.getLogger(__name__)

router = APIRouter()


@router.post("/scan", status_code=200)
async def run_scan(
    scan_type: str = Query("full", description="Type of scan: full, s3, ec2, iam"),
    region: Optional[str] = Query(None, description="AWS region to scan"),
    db: Session = Depends(get_db)
):
    """
    Run a security scan and return results immediately
    
    Simple endpoint that runs a scan and returns all findings in one response.
    
    Args:
        scan_type: Type of scan to run (full, s3, ec2, iam)
        region: AWS region to scan (optional)
        db: Database session
        
    Returns:
        Complete scan results with all findings
    """
    try:
        scanner_service = ScannerService(db, region=region)
        
        # Run the appropriate scan
        logger.info(f"Running {scan_type} scan...")
        if scan_type == "full":
            scan = scanner_service.run_full_scan()
        elif scan_type == "s3":
            scan = scanner_service.run_s3_scan()
        elif scan_type == "ec2":
            scan = scanner_service.run_ec2_scan()
        elif scan_type == "iam":
            scan = scanner_service.run_iam_scan()
        else:
            raise HTTPException(status_code=400, detail=f"Invalid scan type: {scan_type}. Valid types: full, s3, ec2, iam")
        
        # Get detailed results
        summary = scanner_service.get_scan_summary(scan.id)
        findings = scanner_service.get_scan_findings(scan.id)
        
        # Format findings for response
        findings_list = []
        for finding in findings:
            findings_list.append({
                "id": finding.id,
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity.value,
                "resource_type": finding.resource_type,
                "resource_id": finding.resource_id,
                "resource_arn": finding.resource_arn,
                "region": finding.region,
                "account_id": finding.account_id,
                "risk_score": finding.risk_score,
                "status": finding.status,
                "created_at": finding.created_at.isoformat() if finding.created_at else None
            })
        
        return {
            "success": True,
            "message": f"{scan_type.upper()} scan completed successfully",
            "scan": {
                "id": scan.id,
                "type": scan.scan_type,
                "status": scan.status.value,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "duration_seconds": scan.duration_seconds,
                "resources_scanned": scan.resources_scanned,
                "region": region or "us-east-1"
            },
            "summary": {
                "total_findings": len(findings_list),
                "critical": summary['severity_breakdown']['critical'],
                "high": summary['severity_breakdown']['high'],
                "medium": summary['severity_breakdown']['medium'],
                "low": summary['severity_breakdown']['low'],
                "info": summary['severity_breakdown']['info'],
                "by_resource_type": summary['resource_type_breakdown']
            },
            "findings": findings_list
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error running scan: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=f"Scan failed: {str(e)}")


@router.post("/scans", status_code=201)
async def create_scan(
    scan_type: str = Query("full", description="Type of scan: full, s3, ec2, iam"),
    region: Optional[str] = Query(None, description="AWS region to scan"),
    db: Session = Depends(get_db)
):
    """
    Initiate a new security scan
    
    Args:
        scan_type: Type of scan to run (full, s3, ec2, iam)
        region: AWS region to scan (optional)
        db: Database session
        
    Returns:
        Scan summary with initial details
    """
    try:
        scanner_service = ScannerService(db, region=region)
        
        # Run the appropriate scan
        if scan_type == "full":
            scan = scanner_service.run_full_scan()
        elif scan_type == "s3":
            scan = scanner_service.run_s3_scan()
        elif scan_type == "ec2":
            scan = scanner_service.run_ec2_scan()
        elif scan_type == "iam":
            scan = scanner_service.run_iam_scan()
        else:
            raise HTTPException(status_code=400, detail=f"Invalid scan type: {scan_type}")
        
        # Get scan summary
        summary = scanner_service.get_scan_summary(scan.id)
        
        return {
            "message": f"{scan_type.upper()} scan initiated successfully",
            "scan": summary
        }
        
    except Exception as e:
        logger.error(f"Error creating scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scans")
async def list_scans(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=500, description="Maximum number of records to return"),
    db: Session = Depends(get_db)
):
    """
    List all security scans
    
    Args:
        skip: Number of records to skip for pagination
        limit: Maximum number of records to return
        db: Database session
        
    Returns:
        List of scans with summaries
    """
    try:
        scanner_service = ScannerService(db)
        scans = scanner_service.list_scans(skip=skip, limit=limit)
        
        # Get summaries for each scan
        scan_summaries = []
        for scan in scans:
            summary = scanner_service.get_scan_summary(scan.id)
            scan_summaries.append(summary)
        
        return {
            "total": len(scan_summaries),
            "scans": scan_summaries
        }
        
    except Exception as e:
        logger.error(f"Error listing scans: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/scans/{scan_id}")
async def get_scan(
    scan_id: int,
    db: Session = Depends(get_db)
):
    """
    Get scan details by ID
    
    Args:
        scan_id: ID of the scan to retrieve
        db: Database session
        
    Returns:
        Detailed scan information including findings
    """
    try:
        scanner_service = ScannerService(db)
        
        # Get scan
        scan = scanner_service.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        
        # Get summary and findings
        summary = scanner_service.get_scan_summary(scan_id)
        findings = scanner_service.get_scan_findings(scan_id)
        
        # Format findings for response
        findings_list = []
        for finding in findings:
            findings_list.append({
                "id": finding.id,
                "title": finding.title,
                "description": finding.description,
                "severity": finding.severity.value,
                "resource_type": finding.resource_type,
                "resource_id": finding.resource_id,
                "resource_arn": finding.resource_arn,
                "region": finding.region,
                "account_id": finding.account_id,
                "risk_score": finding.risk_score,
                "status": finding.status,
                "ai_summary": finding.ai_summary,
                "remediation_steps": finding.remediation_steps,
                "created_at": finding.created_at.isoformat() if finding.created_at else None,
                "updated_at": finding.updated_at.isoformat() if finding.updated_at else None
            })
        
        return {
            "success": True,
            "scan": {
                "id": scan.id,
                "type": scan.scan_type,
                "status": scan.status.value,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
                "duration_seconds": scan.duration_seconds,
                "resources_scanned": scan.resources_scanned,
                "error_message": scan.error_message
            },
            "summary": {
                "total_findings": len(findings_list),
                "critical": summary['severity_breakdown']['critical'],
                "high": summary['severity_breakdown']['high'],
                "medium": summary['severity_breakdown']['medium'],
                "low": summary['severity_breakdown']['low'],
                "info": summary['severity_breakdown']['info'],
                "by_resource_type": summary['resource_type_breakdown']
            },
            "findings": findings_list
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting scan {scan_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))
