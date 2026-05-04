from typing import List, Optional, Dict, Any
from sqlalchemy.orm import Session
from datetime import datetime
import logging

from app.db import models, crud
from app.db.schemas import AnomalyCreate, SeverityLevel
from app.detectors.login_anomaly import LoginAnomalyDetector
from app.detectors.api_anomaly import APIAnomalyDetector
from app.detectors.privilege_escalation import PrivilegeEscalationDetector

logger = logging.getLogger(__name__)


class AnomalyService:
    """
    Anomaly Detection Service
    Orchestrates anomaly detection across CloudTrail events and saves to database
    """
    
    def __init__(self, db: Session):
        """
        Initialize Anomaly Service
        
        Args:
            db: Database session
        """
        self.db = db
        
        # Initialize detectors
        self.login_detector = LoginAnomalyDetector()
        self.api_detector = APIAnomalyDetector()
        self.privilege_detector = PrivilegeEscalationDetector()
    
    def detect_all_anomalies(self, events: List[Dict[str, Any]]) -> List[models.Anomaly]:
        """
        Run all anomaly detectors on CloudTrail events and save to database
        
        Args:
            events: List of CloudTrail events to analyze
            
        Returns:
            List of detected and saved anomalies
        """
        logger.info(f"Starting anomaly detection on {len(events)} events...")
        
        all_anomalies = []
        
        # Detect login anomalies
        logger.info("Running login anomaly detection...")
        login_anomalies = self.login_detector.detect(events)
        all_anomalies.extend(login_anomalies)
        logger.info(f"Detected {len(login_anomalies)} login anomalies")
        
        # Detect API call anomalies
        logger.info("Running API anomaly detection...")
        api_anomalies = self.api_detector.detect(events)
        all_anomalies.extend(api_anomalies)
        logger.info(f"Detected {len(api_anomalies)} API anomalies")
        
        # Detect privilege escalation attempts
        logger.info("Running privilege escalation detection...")
        privilege_anomalies = self.privilege_detector.detect(events)
        all_anomalies.extend(privilege_anomalies)
        logger.info(f"Detected {len(privilege_anomalies)} privilege escalation anomalies")
        
        # Save all anomalies to database
        logger.info(f"Saving {len(all_anomalies)} anomalies to database...")
        saved_anomalies = self._save_anomalies(all_anomalies)
        
        logger.info(f"Anomaly detection completed: {len(saved_anomalies)} anomalies saved")
        return saved_anomalies
    
    def detect_login_anomalies(self, events: List[Dict[str, Any]]) -> List[models.Anomaly]:
        """
        Detect login anomalies and save to database
        
        Args:
            events: List of CloudTrail events
            
        Returns:
            List of detected login anomalies
        """
        logger.info("Running login anomaly detection...")
        anomalies = self.login_detector.detect(events)
        saved_anomalies = self._save_anomalies(anomalies)
        logger.info(f"Detected and saved {len(saved_anomalies)} login anomalies")
        return saved_anomalies
    
    def detect_api_anomalies(self, events: List[Dict[str, Any]]) -> List[models.Anomaly]:
        """
        Detect API call anomalies and save to database
        
        Args:
            events: List of CloudTrail events
            
        Returns:
            List of detected API anomalies
        """
        logger.info("Running API anomaly detection...")
        anomalies = self.api_detector.detect(events)
        saved_anomalies = self._save_anomalies(anomalies)
        logger.info(f"Detected and saved {len(saved_anomalies)} API anomalies")
        return saved_anomalies
    
    def detect_privilege_escalation(self, events: List[Dict[str, Any]]) -> List[models.Anomaly]:
        """
        Detect privilege escalation attempts and save to database
        
        Args:
            events: List of CloudTrail events
            
        Returns:
            List of detected privilege escalation anomalies
        """
        logger.info("Running privilege escalation detection...")
        anomalies = self.privilege_detector.detect(events)
        saved_anomalies = self._save_anomalies(anomalies)
        logger.info(f"Detected and saved {len(saved_anomalies)} privilege escalation anomalies")
        return saved_anomalies
    
    def get_anomaly(self, anomaly_id: int) -> Optional[models.Anomaly]:
        """
        Get anomaly by ID
        
        Args:
            anomaly_id: ID of the anomaly
            
        Returns:
            Anomaly model or None
        """
        return crud.get_anomaly(self.db, anomaly_id)
    
    def list_anomalies(
        self, 
        skip: int = 0, 
        limit: int = 100, 
        anomaly_type: Optional[str] = None,
        severity: Optional[str] = None
    ) -> List[models.Anomaly]:
        """
        List anomalies with filtering
        
        Args:
            skip: Number of records to skip
            limit: Maximum number of records to return
            anomaly_type: Filter by anomaly type
            severity: Filter by severity level
            
        Returns:
            List of Anomaly models
        """
        query = self.db.query(models.Anomaly)
        
        if anomaly_type:
            query = query.filter(models.Anomaly.anomaly_type == anomaly_type)
        
        if severity:
            query = query.filter(models.Anomaly.severity == severity)
        
        return query.order_by(models.Anomaly.detected_at.desc()).offset(skip).limit(limit).all()
    
    def update_anomaly_status(self, anomaly_id: int, status: str) -> Optional[models.Anomaly]:
        """
        Update anomaly status
        
        Args:
            anomaly_id: ID of the anomaly
            status: New status (new, investigating, resolved, false_positive)
            
        Returns:
            Updated Anomaly model or None
        """
        anomaly = crud.get_anomaly(self.db, anomaly_id)
        if anomaly:
            anomaly.status = status
            anomaly.updated_at = datetime.utcnow()
            self.db.commit()
            self.db.refresh(anomaly)
            logger.info(f"Updated anomaly {anomaly_id} status to {status}")
        return anomaly
    
    def get_anomaly_stats(self) -> Dict[str, Any]:
        """
        Get anomaly statistics
        
        Returns:
            Dictionary with anomaly statistics
        """
        all_anomalies = self.db.query(models.Anomaly).all()
        
        # Count by type
        type_counts = {}
        # Count by severity
        severity_counts = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        }
        # Count by status
        status_counts = {}
        
        for anomaly in all_anomalies:
            # Type counts
            type_counts[anomaly.anomaly_type] = type_counts.get(anomaly.anomaly_type, 0) + 1
            
            # Severity counts
            severity_counts[anomaly.severity.value] = severity_counts.get(anomaly.severity.value, 0) + 1
            
            # Status counts
            status_counts[anomaly.status] = status_counts.get(anomaly.status, 0) + 1
        
        return {
            'total_anomalies': len(all_anomalies),
            'type_breakdown': type_counts,
            'severity_breakdown': severity_counts,
            'status_breakdown': status_counts
        }
    
    # ==================== Private Helper Methods ====================
    
    def _save_anomalies(self, anomalies: List[AnomalyCreate]) -> List[models.Anomaly]:
        """
        Save anomalies to database
        
        Args:
            anomalies: List of AnomalyCreate schemas
            
        Returns:
            List of saved Anomaly models
        """
        saved_anomalies = []
        for anomaly_create in anomalies:
            anomaly_dict = anomaly_create.model_dump()
            anomaly = crud.create_anomaly(self.db, anomaly_dict)
            saved_anomalies.append(anomaly)
        
        logger.info(f"Saved {len(saved_anomalies)} anomalies to database")
        return saved_anomalies
