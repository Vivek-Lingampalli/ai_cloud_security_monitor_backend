from typing import List, Dict, Any, Set
from datetime import datetime, timedelta
from collections import defaultdict
import logging

from app.db.schemas import AnomalyCreate, SeverityLevel

logger = logging.getLogger(__name__)


class PrivilegeEscalationDetector:
    """
    Privilege Escalation Detector
    Detects potential privilege escalation attempts from CloudTrail events
    """
    
    # IAM privilege escalation techniques
    PRIVILEGE_ESCALATION_APIS = {
        # Direct policy manipulation
        'PutUserPolicy': 'Inline policy attachment to user',
        'PutGroupPolicy': 'Inline policy attachment to group',
        'PutRolePolicy': 'Inline policy attachment to role',
        'AttachUserPolicy': 'Managed policy attachment to user',
        'AttachGroupPolicy': 'Managed policy attachment to group',
        'AttachRolePolicy': 'Managed policy attachment to role',
        
        # Policy creation/modification
        'CreatePolicy': 'New policy creation',
        'CreatePolicyVersion': 'Policy version creation',
        'SetDefaultPolicyVersion': 'Policy version activation',
        
        # User/Role manipulation
        'CreateUser': 'New user creation',
        'CreateRole': 'New role creation',
        'CreateAccessKey': 'Access key creation',
        'UpdateAccessKey': 'Access key activation',
        'UpdateAssumeRolePolicy': 'Role trust policy modification',
        
        # Group membership
        'AddUserToGroup': 'User added to group',
        
        # Assume role operations
        'AssumeRole': 'Role assumption',
        'UpdateAssumeRolePolicy': 'Assume role policy update',
        
        # Lambda-based escalation
        'CreateFunction': 'Lambda function creation',
        'UpdateFunctionCode': 'Lambda function code update',
        'AddPermission': 'Permission addition',
        
        # EC2 instance profile escalation
        'CreateInstanceProfile': 'Instance profile creation',
        'AddRoleToInstanceProfile': 'Role to instance profile addition',
        'AssociateIamInstanceProfile': 'IAM instance profile association'
    }
    
    # Highly sensitive administrative actions
    ADMIN_ACTIONS = {
        'CreatePolicy',
        'CreatePolicyVersion',
        'SetDefaultPolicyVersion',
        'PutUserPolicy',
        'PutRolePolicy',
        'AttachUserPolicy',
        'AttachRolePolicy',
        'UpdateAssumeRolePolicy'
    }
    
    def __init__(self):
        """Initialize Privilege Escalation Detector"""
        self.user_escalation_attempts = defaultdict(list)
        self.recent_policy_changes = []
    
    def detect(self, events: List[Dict[str, Any]]) -> List[AnomalyCreate]:
        """
        Detect privilege escalation attempts in CloudTrail events
        
        Args:
            events: List of CloudTrail events
            
        Returns:
            List of detected anomalies
        """
        anomalies = []
        
        logger.info(f"Analyzing {len(events)} events for privilege escalation")
        
        # Track events by user
        user_events = defaultdict(list)
        
        for event in events:
            event_name = event.get('eventName', 'Unknown')
            user_identity = event.get('userIdentity', {})
            user_name = user_identity.get('userName') or user_identity.get('arn', 'Unknown')
            
            # Track privilege escalation APIs
            if event_name in self.PRIVILEGE_ESCALATION_APIS:
                user_events[user_name].append(event)
                
                # Analyze individual event
                event_anomalies = self._analyze_privilege_event(event)
                anomalies.extend(event_anomalies)
        
        # Check for patterns across multiple events
        for user_name, events_list in user_events.items():
            pattern_anomalies = self._detect_escalation_patterns(user_name, events_list)
            anomalies.extend(pattern_anomalies)
        
        logger.info(f"Detected {len(anomalies)} privilege escalation anomalies")
        return anomalies
    
    def _analyze_privilege_event(self, event: Dict[str, Any]) -> List[AnomalyCreate]:
        """
        Analyze a single privilege-related event
        
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
        request_params = event.get('requestParameters', {})
        
        # Parse event time
        event_time = None
        if event_time_str:
            try:
                event_time = datetime.fromisoformat(event_time_str.replace('Z', '+00:00'))
            except:
                event_time = datetime.utcnow()
        
        # Extract user information
        user_name = user_identity.get('userName') or user_identity.get('arn', 'Unknown')
        
        # Check if this is a highly sensitive admin action
        if event_name in self.ADMIN_ACTIONS:
            description = self.PRIVILEGE_ESCALATION_APIS.get(event_name, 'Privilege escalation attempt')
            
            anomalies.append(AnomalyCreate(
                anomaly_type='privilege_escalation',
                description=f'Potential privilege escalation: {description}',
                severity=SeverityLevel.HIGH,
                event_name=event_name,
                event_source=event_source,
                user_identity=user_name,
                source_ip=source_ip,
                user_agent=user_agent,
                event_time=event_time
            ))
        
        # Check for wildcard permissions (AdministratorAccess-like)
        if event_name in ['CreatePolicy', 'CreatePolicyVersion', 'PutUserPolicy', 'PutRolePolicy']:
            policy_document = request_params.get('policyDocument', '')
            if isinstance(policy_document, str):
                # Check for overly permissive policies
                if '"Effect":"Allow"' in policy_document and '"Action":"*"' in policy_document:
                    anomalies.append(AnomalyCreate(
                        anomaly_type='privilege_escalation',
                        description='Creation of overly permissive policy with wildcard permissions',
                        severity=SeverityLevel.CRITICAL,
                        event_name=event_name,
                        event_source=event_source,
                        user_identity=user_name,
                        source_ip=source_ip,
                        user_agent=user_agent,
                        event_time=event_time
                    ))
        
        # Check for self-privilege escalation
        target_user = request_params.get('userName', '')
        target_role = request_params.get('roleName', '')
        
        if target_user and target_user == user_name:
            anomalies.append(AnomalyCreate(
                anomaly_type='privilege_escalation',
                description=f'Self-privilege escalation attempt: User modifying own permissions',
                severity=SeverityLevel.CRITICAL,
                event_name=event_name,
                event_source=event_source,
                user_identity=user_name,
                source_ip=source_ip,
                user_agent=user_agent,
                event_time=event_time
            ))
        
        # Check for access key creation (potential persistence)
        if event_name == 'CreateAccessKey':
            target = request_params.get('userName', 'self')
            anomalies.append(AnomalyCreate(
                anomaly_type='privilege_escalation',
                description=f'Access key created for user: {target} - potential persistence mechanism',
                severity=SeverityLevel.HIGH,
                event_name=event_name,
                event_source=event_source,
                user_identity=user_name,
                source_ip=source_ip,
                user_agent=user_agent,
                event_time=event_time
            ))
        
        # Check for Lambda-based escalation
        if event_name in ['CreateFunction', 'UpdateFunctionCode']:
            anomalies.append(AnomalyCreate(
                anomaly_type='privilege_escalation',
                description='Lambda function manipulation - potential code execution for privilege escalation',
                severity=SeverityLevel.HIGH,
                event_name=event_name,
                event_source=event_source,
                user_identity=user_name,
                source_ip=source_ip,
                user_agent=user_agent,
                event_time=event_time
            ))
        
        # Check for EC2 instance profile escalation
        if event_name == 'AssociateIamInstanceProfile':
            anomalies.append(AnomalyCreate(
                anomaly_type='privilege_escalation',
                description='IAM instance profile associated with EC2 - potential privilege escalation vector',
                severity=SeverityLevel.HIGH,
                event_name=event_name,
                event_source=event_source,
                user_identity=user_name,
                source_ip=source_ip,
                user_agent=user_agent,
                event_time=event_time
            ))
        
        return anomalies
    
    def _detect_escalation_patterns(self, user_name: str, events: List[Dict[str, Any]]) -> List[AnomalyCreate]:
        """
        Detect patterns that indicate privilege escalation campaigns
        
        Args:
            user_name: User being analyzed
            events: List of privilege-related events by this user
            
        Returns:
            List of pattern-based anomalies
        """
        anomalies = []
        
        # Pattern 1: Multiple privilege escalation attempts in short time
        if len(events) >= 3:
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
                
                if time_range < timedelta(minutes=30):
                    anomalies.append(AnomalyCreate(
                        anomaly_type='privilege_escalation',
                        description=f'Multiple privilege escalation attempts detected: {len(events)} actions in {time_range.total_seconds()/60:.1f} minutes',
                        severity=SeverityLevel.CRITICAL,
                        event_name='Multiple',
                        event_source='iam.amazonaws.com',
                        user_identity=user_name,
                        source_ip=events[0].get('sourceIPAddress', 'Unknown'),
                        user_agent=events[0].get('userAgent', ''),
                        event_time=max(event_times)
                    ))
        
        # Pattern 2: Policy creation followed by attachment
        event_names = [e.get('eventName') for e in events]
        
        if 'CreatePolicy' in event_names and any(attach in event_names for attach in ['AttachUserPolicy', 'AttachRolePolicy']):
            anomalies.append(AnomalyCreate(
                anomaly_type='privilege_escalation',
                description='Privilege escalation pattern: Policy creation followed by attachment',
                severity=SeverityLevel.HIGH,
                event_name='Pattern',
                event_source='iam.amazonaws.com',
                user_identity=user_name,
                source_ip=events[0].get('sourceIPAddress', 'Unknown'),
                user_agent=events[0].get('userAgent', ''),
                event_time=datetime.utcnow()
            ))
        
        # Pattern 3: User creation followed by access key creation
        if 'CreateUser' in event_names and 'CreateAccessKey' in event_names:
            anomalies.append(AnomalyCreate(
                anomaly_type='privilege_escalation',
                description='Privilege escalation pattern: User creation with immediate access key generation',
                severity=SeverityLevel.HIGH,
                event_name='Pattern',
                event_source='iam.amazonaws.com',
                user_identity=user_name,
                source_ip=events[0].get('sourceIPAddress', 'Unknown'),
                user_agent=events[0].get('userAgent', ''),
                event_time=datetime.utcnow()
            ))
        
        return anomalies
