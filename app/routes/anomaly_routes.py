from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session
from typing import List, Optional
import logging

from app.db.database import get_db
from app.db.schemas import AnomalyResponse, AnomalyUpdate
from app.services.anomaly_service import AnomalyService

logger = logging.getLogger(__name__)
router = APIRouter()


@router.get("/anomalies", response_model=List[AnomalyResponse])
async def list_anomalies(
    skip: int = Query(0, ge=0, description="Number of records to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of records to return"),
    anomaly_type: Optional[str] = Query(None, description="Filter by anomaly type"),
    severity: Optional[str] = Query(None, description="Filter by severity level"),
    db: Session = Depends(get_db)
):
    """
    List detected anomalies with optional filtering
    
    Args:
        skip: Number of records to skip for pagination
        limit: Maximum number of records to return
        anomaly_type: Optional filter by anomaly type (login, api_call, privilege_escalation)
        severity: Optional filter by severity (critical, high, medium, low, info)
        db: Database session
    
    Returns:
        List of anomalies
    """
    try:
        anomaly_service = AnomalyService(db)
        anomalies = anomaly_service.list_anomalies(
            skip=skip, 
            limit=limit, 
            anomaly_type=anomaly_type,
            severity=severity
        )
        return anomalies
    except Exception as e:
        logger.error(f"Error listing anomalies: {e}")
        raise HTTPException(status_code=500, detail=f"Error listing anomalies: {str(e)}")


@router.get("/anomalies/{anomaly_id}", response_model=AnomalyResponse)
async def get_anomaly(
    anomaly_id: int,
    db: Session = Depends(get_db)
):
    """
    Get anomaly details by ID
    
    Args:
        anomaly_id: ID of the anomaly
        db: Database session
    
    Returns:
        Anomaly details
    """
    try:
        anomaly_service = AnomalyService(db)
        anomaly = anomaly_service.get_anomaly(anomaly_id)
        
        if not anomaly:
            raise HTTPException(status_code=404, detail=f"Anomaly {anomaly_id} not found")
        
        return anomaly
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting anomaly {anomaly_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting anomaly: {str(e)}")


@router.post("/anomalies/detect")
async def detect_anomalies(
    events: List[dict],
    db: Session = Depends(get_db)
):
    """
    Run anomaly detection on CloudTrail events
    
    Args:
        events: List of CloudTrail events to analyze
        db: Database session
    
    Returns:
        Detection results including number of anomalies found
    """
    try:
        anomaly_service = AnomalyService(db)
        
        # Run all anomaly detectors
        anomalies = anomaly_service.detect_all_anomalies(events)
        
        # Get statistics
        stats = anomaly_service.get_anomaly_stats()
        
        return {
            "status": "success",
            "events_analyzed": len(events),
            "anomalies_detected": len(anomalies),
            "anomaly_ids": [a.id for a in anomalies],
            "statistics": stats
        }
    except Exception as e:
        logger.error(f"Error detecting anomalies: {e}")
        raise HTTPException(status_code=500, detail=f"Error detecting anomalies: {str(e)}")


@router.patch("/anomalies/{anomaly_id}", response_model=AnomalyResponse)
async def update_anomaly(
    anomaly_id: int,
    update_data: AnomalyUpdate,
    db: Session = Depends(get_db)
):
    """
    Update anomaly (e.g., change status)
    
    Args:
        anomaly_id: ID of the anomaly
        update_data: Update data
        db: Database session
    
    Returns:
        Updated anomaly
    """
    try:
        anomaly_service = AnomalyService(db)
        
        # Update status if provided
        if update_data.status:
            anomaly = anomaly_service.update_anomaly_status(anomaly_id, update_data.status)
            if not anomaly:
                raise HTTPException(status_code=404, detail=f"Anomaly {anomaly_id} not found")
        
        # Get updated anomaly
        anomaly = anomaly_service.get_anomaly(anomaly_id)
        return anomaly
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating anomaly {anomaly_id}: {e}")
        raise HTTPException(status_code=500, detail=f"Error updating anomaly: {str(e)}")


@router.get("/anomalies/stats/summary")
async def get_anomaly_stats(
    db: Session = Depends(get_db)
):
    """
    Get anomaly statistics and summary
    
    Args:
        db: Database session
    
    Returns:
        Anomaly statistics
    """
    try:
        anomaly_service = AnomalyService(db)
        stats = anomaly_service.get_anomaly_stats()
        return stats
    except Exception as e:
        logger.error(f"Error getting anomaly stats: {e}")
        raise HTTPException(status_code=500, detail=f"Error getting anomaly stats: {str(e)}")
