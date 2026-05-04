from typing import List, Dict, Any, Set
from datetime import datetime
from collections import defaultdict
import logging

from app.db.schemas import AnomalyCreate, SeverityLevel

logger = logging.getLogger(__name__)


class APIAnomalyDetector:
    """
    API Anomaly Detector
    Detects suspicious API call patterns from CloudTrail events
    """
    
    # High-risk API calls that should be monitored
    HIGH_RISK_APIS = {
        'DeleteBucket',
        'DeleteObject',
        'DeleteDBInstance',
        'DeleteVolume',
        'TerminateInstances',
        'DeleteUser',
        'DeleteAccessKey',
        'DeleteRole',
        'DeletePolicy',
        'PutBucketPolicy',
        'PutUserPolicy',
        'AttachUserPolicy',
        'AttachRolePolicy',
        'CreateAccessKey',
        'UpdateAccessKey',
        'ModifyImageAttribute',
        'ModifySnapshotAttribute'
    }
    
    # Destructive operations
    DESTRUCTIVE_APIS = {
        'DeleteBucket',
        'DeleteObject',
        'DeleteDBInstance',
        'DeleteVolume',
        'TerminateInstances',
        'DeleteUser',
        'DeleteAccessKey',
        'DeleteRole',
        'DeleteTable'
    }
    
    # Rate limits for anomaly detection (calls per user per minute)
    RATE_LIMIT_THRESHOLD = 50
    
    def __init__(self):
        """Initialize API Anomaly Detector"""
        self.api_call_counts = defaultdict(int)
        self.user_api_counts = defaultdict(lambda: defaultdict(int))
    
    def detect(self, events: List[Dict[str, Any]]) -> List[AnomalyCreate]:
        """
        Detect API call anomalies in CloudTrail events
        
        Args:
            events: List of CloudTrail events
            
        Returns:
            List of detected anomalies
        """
        anomalies = []
        
        logger.info(f"Analyzing {len(events)} API events for anomalies")
        
        # Track API calls per user
        user_calls = defaultdict(list)
        
        for event in events:
            event_name = event.get('eventName', 'Unknown')
            user_identity = event.get('userIdentity', {})
            user_name = user_identity.get('userName') or user_identity.get('arn', 'Unknown')
            
            user_calls[user_name].append(event)
            
            # Check individual event for high-risk APIs
            event_anomalies = self._analyze_api_event(event)
            anomalies.extend(event_anomalies)
        
        # Check for rate-based anomalies
        for user_name, events_list in user_calls.items():
            rate_anomalies = self._check_rate_anomalies(user_name, events_list)
            anomalies.extend(rate_anomalies)
        
        logger.info(f"Detected {len(anomalies)} API anomalies")
        return anomalies
    
    def _analyze_api_event(self, event: Dict[str, Any]) -> List[AnomalyCreate]:
        """
        Analyze a single API event for anomalies
        
        Args:
            event: CloudTrail event
            
        Returns:
            List of anomalies detected in this event
        """
        anomalies = []
        
        event_name = event.get('eventName', 'Unknown')
        event_time_str = event.get('eventTime', '')
        user_identity = event.get('userIdentity', {})
        source_ip = event.get('sourceIPAddress', 'Unknown')
        user_agent = event.get('userAgent', '')
        event_source = event.get('eventSource', '')
        
        # Parse event time
        event_time = None
        if event_time_str:
            try:
                event_time = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
            except:
                event_time = datetime.utcnow()
        
        # Extract user information
        user_name = user_identity.get('userName') or user_identity.get('arn', 'Unknown')
        
        # Check for high-risk API calls
        if event_name in self.HIGH_RISK_APIS:
            severity = SeverityLevel.CRITICAL if event_name in self.DESTRUCTIVE_APIS else SeverityLevel.HIGH
            
            anomalies.append(AnomalyCreate(
                anomaly_type='api_call',
                description=f'High-risk API call detected: {event_name}',
                severity=severity,
                event_name=event_name,
                event_source=event_source,
                user_identity=user_name,
                source_ip=source_ip,
                user_agent=user_agent,
                event_time=event_time
            ))
        
        # Check for failed high-risk operations
        error_code = event.get('errorCode')
        if error_code and event_name in self.HIGH_RISK_APIS:
            anomalies.append(AnomalyCreate(
                anomaly_type='api_call',
                description=f'Failed high-risk API call: {event_name} - {error_code}',
                severity=SeverityLevel.MEDIUM,
                event_name=event_name,
                event_source=event_source,
                user_identity=user_name,
                source_ip=source_ip,
                user_agent=user_agent,
                event_time=event_time
            ))
        
        # Check for API calls from unusual sources
        if self._is_unusual_source(source_ip, user_agent):
            anomalies.append(AnomalyCreate(
                anomaly_type='api_call',
                description=f'API call from unusual source: {source_ip}',
                severity=SeverityLevel.MEDIUM,
                event_name=event_name,
                event_source=event_source,
                user_identity=user_name,
                source_ip=source_ip,
                user_agent=user_agent,
                event_time=event_time
            ))
        
        # Check for disabled logging/monitoring
        if event_name in ['StopLogging', 'DeleteTrail', 'PutEventSelectors']:
            anomalies.append(AnomalyCreate(
                anomaly_type='api_call',
                description=f'Attempt to disable security monitoring: {event_name}',
                severity=SeverityLevel.CRITICAL,
                event_name=event_name,
                event_source=event_source,
                user_identity=user_name,
                source_ip=source_ip,
                user_agent=user_agent,
                event_time=event_time
            ))
        
        return anomalies
    
    def _check_rate_anomalies(self, user_name: str, events: List[Dict[str, Any]]) -> List[AnomalyCreate]:
        """
        Check for rate-based anomalies (too many API calls)
        
        Args:
            user_name: User making the API calls
            events: List of events by this user
            
        Returns:
            List of rate-based anomalies
        """
        anomalies = []
        
        # If user made too many calls in a short period
        if len(events) > self.RATE_LIMIT_THRESHOLD:
            # Get time range
            event_times = []
            for event in events:
                event_time_str = event.get('eventTime', '')
                if event_time_str:
                    try:
                        event_time = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
                        event_times.append(event_time)
                    except:
                        pass
            
            if event_times:
                time_range = max(event_times) - min(event_times)
                minutes = time_range.total_seconds() / 60
                
                if minutes < 60:  # Within one hour
                    rate = len(events) / max(minutes, 1)
                    
                    anomalies.append(AnomalyCreate(
                        anomaly_type='api_call',
                        description=f'Unusually high API call rate: {len(events)} calls in {minutes:.1f} minutes ({rate:.1f} calls/min)',
                        severity=SeverityLevel.HIGH,
                        event_name='Multiple',
                        event_source='cloudtrail.amazonaws.com',
                        user_identity=user_name,
                        source_ip=events[0].get('sourceIPAddress', 'Unknown'),
                        user_agent=events[0].get('userAgent', ''),
                        event_time=max(event_times)
                    ))
        
        # Check for repeated failed calls (potential scanning/enumeration)
        failed_events = [e for e in events if e.get('errorCode')]
        if len(failed_events) > 10:
            anomalies.append(AnomalyCreate(
                anomaly_type='api_call',
                description=f'Multiple failed API calls detected: {len(failed_events)} failures',
                severity=SeverityLevel.MEDIUM,
                event_name='Multiple',
                event_source='cloudtrail.amazonaws.com',
                user_identity=user_name,
                source_ip=failed_events[0].get('sourceIPAddress', 'Unknown'),
                user_agent=failed_events[0].get('userAgent', ''),
                event_time=datetime.utcnow()
            ))
        
        return anomalies
    
    def _is_unusual_source(self, source_ip: str, user_agent: str) -> bool:
        """
        Check if the source IP or user agent is unusual
        
        Args:
            source_ip: Source IP address
            user_agent: User agent string
            
        Returns:
            True if source is unusual
        """
        # Check for TOR exit nodes (simplified check)
        if source_ip and 'tor-exit' in source_ip.lower():
            return True
        
        # Check for known malicious user agents (simplified)
        suspicious_patterns = ['scanner', 'exploit', 'sqlmap', 'nikto', 'masscan']
        if any(pattern in user_agent.lower() for pattern in suspicious_patterns):
            return True
        
        return False
