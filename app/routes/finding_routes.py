from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
import logging

from app.db.database import get_db
from app.db import crud
from app.db.schemas import FindingResponse

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/findings", response_model=List[FindingResponse])
async def list_findings(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of records to return"),
    severity: Optional[str] = Query(None, description="Filter by severity level (critical, high, medium, low, info)"),
    resource_type: Optional[str] = Query(None, description="Filter by resource type (S3, EC2, IAM, etc.)"),
    db: Session = Depends(get_db)
):
    """
    List security findings with optional filtering
    
    Args:
        skip: Number of records to skip for pagination
        limit: Maximum number of records to return
        severity: Optional filter by severity (critical, high, medium, low, info)
        resource_type: Optional filter by resource type (S3, EC2, IAM, etc.)
        db: Database session
    
    Returns:
        List of findings matching the filter criteria
    """
    try:
        findings = crud.get_findings(
            db=db,
            skip=skip,
            limit=limit,
            severity=severity,
            resource_type=resource_type
        )
        return findings
    except Exception as e:
        logger.error(f"Error listing findings: {e}")
        raise HTTPException(status_code=500, detail=f"Error listing findings: {str(e)}")


@router.get("/findings/{finding_id}", response_model=FindingResponse)
async def get_finding(
    finding_id: int,
    db: Session = Depends(get_db)
):
    """
    Get finding details by ID
    
    Args:
        finding_id: ID of the finding
        db: Database session
    
    Returns:
        Finding details
    """
    try:
        finding = crud.get_finding(db, finding_id)
        
        if not finding:
            raise HTTPException(status_code=404, detail=f"Finding {finding_id} not found")
        
        return finding
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting finding {finding_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting finding: {str(e)}")


@router.get("/findings/stats")
async def get_findings_stats(
    db: Session = Depends(get_db)
):
    """
    Get statistics about findings
    
    Args:
        db: Database session
    
    Returns:
        Dictionary with finding statistics including severity and resource type breakdowns
    """
    try:
        all_findings = crud.get_findings(db=db, limit=10000)
        
        # Count by severity
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        
        # Count by resource type
        resource_type_counts = {}
        
        # Count by status
        status_counts = {}
        
        for finding in all_findings:
            # Severity counts
            if finding.severity:
                severity_counts[finding.severity.value] = severity_counts.get(finding.severity.value, 0) + 1
            
            # Resource type counts
            if finding.resource_type:
                resource_type_counts[finding.resource_type] = resource_type_counts.get(finding.resource_type, 0) + 1
            
            # Status counts
            status_counts[finding.status] = status_counts.get(finding.status, 0) + 1
        
        return {
            'total_findings': len(all_findings),
            'severity_breakdown': severity_counts,
            'resource_type_breakdown': resource_type_counts,
            'status_breakdown': status_counts
        }
    except Exception as e:
        logger.error(f"Error getting findings stats: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting findings stats: {str(e)}")
