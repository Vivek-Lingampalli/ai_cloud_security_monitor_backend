from typing import List, Dict, Any, Set
from datetime import datetime
import logging

from app.db.schemas import AnomalyCreate, SeverityLevel

logger = logging.getLogger(__name__)


class LoginAnomalyDetector:
    """
    Login Anomaly Detector
    Detects suspicious login patterns from CloudTrail events
    """
    
    # Login-related event names in CloudTrail
    LOGIN_EVENTS = {
        'ConsoleLogin',
        'GetSigninToken',
        'AssumeRole',
        'AssumeRoleWithSAML',
        'AssumeRoleWithWebIdentity'
    }
    
    # Known suspicious user agents
    SUSPICIOUS_USER_AGENTS = {
        'curl',
        'wget',
        'python-requests',
        'boto3',
        'aws-cli'
    }
    
    def __init__(self):
        """Initialize Login Anomaly Detector"""
        self.known_locations: Set[str] = set()
        self.known_ips: Set[str] = set()
    
    def detect(self, events: List[Dict[str, Any]]) -> List[AnomalyCreate]:
        """
        Detect login anomalies in CloudTrail events
        
        Args:
            events: List of CloudTrail events
            
        Returns:
            List of detected anomalies
        """
        anomalies = []
        
        # Filter login events
        login_events = [e for e in events if e.get('eventName') in self.LOGIN_EVENTS]
        
        logger.info(f"Analyzing {len(login_events)} login events out of {len(events)} total events")
        
        for event in login_events:
            # Check for suspicious patterns
            event_anomalies = self._analyze_login_event(event)
            anomalies.extend(event_anomalies)
        
        logger.info(f"Detected {len(anomalies)} login anomalies")
        return anomalies
    
    def _analyze_login_event(self, event: Dict[str, Any]) -> List[AnomalyCreate]:
        """
        Analyze a single login event for anomalies
        
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
        
        # Parse event time
        event_time = None
        if event_time_str:
            try:
                event_time = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
            except:
                event_time = datetime.utcnow()
        
        # Extract user information
        user_name = user_identity.get('userName') or user_identity.get('arn', 'Unknown')
        
        # Check for new location (simplified - in production, use GeoIP)
        location = self._get_location_from_ip(source_ip)
        is_new_location = location not in self.known_locations
        
        if is_new_location and location != 'Unknown':
            self.known_locations.add(location)
            
            anomalies.append(AnomalyCreate(
                anomaly_type='login',
                description=f'Login from new location: {location}',
                severity=SeverityLevel.MEDIUM,
                event_name=event_name,
                event_source=event.get('eventSource', ''),
                user_identity=user_name,
                source_ip=source_ip,
                user_agent=user_agent,
                location=location,
                is_new_location=1,
                event_time=event_time
            ))
        
        # Check for suspicious user agent
        if any(sus_agent.lower() in user_agent.lower() for sus_agent in self.SUSPICIOUS_USER_AGENTS):
            anomalies.append(AnomalyCreate(
                anomaly_type='login',
                description=f'Console login with suspicious user agent: {user_agent}',
                severity=SeverityLevel.HIGH,
                event_name=event_name,
                event_source=event.get('eventSource', ''),
                user_identity=user_name,
                source_ip=source_ip,
                user_agent=user_agent,
                location=location,
                is_new_location=0,
                event_time=event_time
            ))
        
        # Check for failed login attempts
        error_code = event.get('errorCode')
        if error_code in ['Failed authentication', 'UnauthorizedOperation', 'AccessDenied']:
            anomalies.append(AnomalyCreate(
                anomaly_type='login',
                description=f'Failed login attempt: {error_code}',
                severity=SeverityLevel.MEDIUM,
                event_name=event_name,
                event_source=event.get('eventSource', ''),
                user_identity=user_name,
                source_ip=source_ip,
                user_agent=user_agent,
                location=location,
                is_new_location=0,
                event_time=event_time
            ))
        
        # Check for root account login
        if user_identity.get('type') == 'Root':
            anomalies.append(AnomalyCreate(
                anomaly_type='login',
                description='Root account login detected - high risk',
                severity=SeverityLevel.CRITICAL,
                event_name=event_name,
                event_source=event.get('eventSource', ''),
                user_identity='ROOT',
                source_ip=source_ip,
                user_agent=user_agent,
                location=location,
                is_new_location=0,
                event_time=event_time
            ))
        
        # Check for unusual time (outside business hours)
        if event_time and self._is_unusual_time(event_time):
            anomalies.append(AnomalyCreate(
                anomaly_type='login',
                description=f'Login at unusual time: {event_time.strftime("%Y-%m-%d %H:%M:%S UTC")}',
                severity=SeverityLevel.LOW,
                event_name=event_name,
                event_source=event.get('eventSource', ''),
                user_identity=user_name,
                source_ip=source_ip,
                user_agent=user_agent,
                location=location,
                is_new_location=0,
                event_time=event_time
            ))
        
        return anomalies
    
    def _get_location_from_ip(self, ip_address: str) -> str:
        """
        Get location from IP address
        In production, use GeoIP database or API
        
        Args:
            ip_address: Source IP address
            
        Returns:
            Location string
        """
        # Simplified implementation - in production, use GeoIP
        if not ip_address or ip_address == 'Unknown':
            return 'Unknown'
        
        # AWS service IPs
        if ip_address.startswith('AWS Internal'):
            return 'AWS Internal'
        
        # For demo purposes, extract first two octets as "region"
        try:
            octets = ip_address.split('.')
            if len(octets) >= 2:
                return f"Region-{octets[0]}.{octets[1]}"
        except:
            pass
        
        return 'Unknown'
    
    def _is_unusual_time(self, event_time: datetime) -> bool:
        """
        Check if login time is unusual (outside business hours)
        
        Args:
            event_time: Event timestamp
            
        Returns:
            True if unusual time
        """
        # Business hours: 8 AM - 6 PM UTC, Monday-Friday
        hour = event_time.hour
        weekday = event_time.weekday()  # 0 = Monday, 6 = Sunday
        
        # Weekend
        if weekday >= 5:
            return True
        
        # Outside business hours
        if hour < 8 or hour >= 18:
            return True
        
        return False
