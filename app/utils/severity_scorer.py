"""
Severity Scoring Module

Provides centralized severity scoring logic for security findings and anomalies.
Calculates severity based on multiple risk factors and maps scores to severity levels.
"""

from typing import Dict, List, Optional, Any
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class SeverityLevel(str, Enum):
    """Severity levels for security findings"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RiskFactor:
    """Individual risk factor with weight and score"""
    def __init__(self, name: str, score: float, weight: float = 1.0, description: str = ""):
        self.name = name
        self.score = score  # 0.0 to 1.0
        self.weight = weight
        self.description = description
    
    def weighted_score(self) -> float:
        """Calculate weighted score"""
        return self.score * self.weight


class SeverityScorer:
    """
    Centralized severity scoring engine
    
    Calculates severity based on multiple risk factors:
    - Exposure level (public vs private)
    - Data sensitivity
    - Exploitability
    - Impact potential
    - Compliance requirements
    """
    
    # Severity thresholds (0-100 scale)
    CRITICAL_THRESHOLD = 85
    HIGH_THRESHOLD = 65
    MEDIUM_THRESHOLD = 40
    LOW_THRESHOLD = 20
    
    def __init__(self):
        """Initialize severity scorer"""
        self.logger = logging.getLogger(__name__)
    
    def calculate_severity(
        self,
        risk_factors: List[RiskFactor],
        override_level: Optional[SeverityLevel] = None
    ) -> SeverityLevel:
        """
        Calculate severity level based on risk factors
        
        Args:
            risk_factors: List of RiskFactor objects
            override_level: Optional manual severity override
            
        Returns:
            SeverityLevel enum value
        """
        if override_level:
            return override_level
        
        if not risk_factors:
            return SeverityLevel.INFO
        
        # Calculate weighted average score
        total_weighted_score = sum(rf.weighted_score() for rf in risk_factors)
        total_weight = sum(rf.weight for rf in risk_factors)
        
        if total_weight == 0:
            return SeverityLevel.INFO
        
        # Normalize to 0-100 scale
        normalized_score = (total_weighted_score / total_weight) * 100
        
        self.logger.debug(
            f"Calculated severity score: {normalized_score:.2f} "
            f"from {len(risk_factors)} risk factors"
        )
        
        # Map score to severity level
        return self._score_to_severity(normalized_score)
    
    def _score_to_severity(self, score: float) -> SeverityLevel:
        """
        Map numeric score to severity level
        
        Args:
            score: Numeric score (0-100)
            
        Returns:
            SeverityLevel enum value
        """
        if score >= self.CRITICAL_THRESHOLD:
            return SeverityLevel.CRITICAL
        elif score >= self.HIGH_THRESHOLD:
            return SeverityLevel.HIGH
        elif score >= self.MEDIUM_THRESHOLD:
            return SeverityLevel.MEDIUM
        elif score >= self.LOW_THRESHOLD:
            return SeverityLevel.LOW
        else:
            return SeverityLevel.INFO
    
    # ==================== Finding Severity Calculators ====================
    
    def calculate_s3_severity(
        self,
        is_public: bool = False,
        has_encryption: bool = True,
        has_versioning: bool = True,
        has_logging: bool = True,
        contains_sensitive_data: bool = False,
        public_acl: bool = False
    ) -> SeverityLevel:
        """
        Calculate severity for S3 bucket findings
        
        Args:
            is_public: Bucket is publicly accessible
            has_encryption: Encryption is enabled
            has_versioning: Versioning is enabled
            has_logging: Access logging is enabled
            contains_sensitive_data: Bucket likely contains sensitive data
            public_acl: Bucket has public ACL grants
            
        Returns:
            SeverityLevel
        """
        risk_factors = []
        
        # Public access is the highest risk
        if public_acl:
            risk_factors.append(RiskFactor(
                "public_acl",
                score=1.0,
                weight=3.0,
                description="Bucket has public ACL grants (AllUsers or AuthenticatedUsers)"
            ))
        elif is_public:
            risk_factors.append(RiskFactor(
                "public_access",
                score=0.9,
                weight=2.5,
                description="Bucket is publicly accessible"
            ))
        
        # Missing encryption
        if not has_encryption:
            weight = 2.0 if contains_sensitive_data else 1.5
            risk_factors.append(RiskFactor(
                "no_encryption",
                score=0.8,
                weight=weight,
                description="Bucket encryption is not enabled"
            ))
        
        # Missing versioning
        if not has_versioning:
            risk_factors.append(RiskFactor(
                "no_versioning",
                score=0.5,
                weight=1.0,
                description="Bucket versioning is not enabled"
            ))
        
        # Missing logging
        if not has_logging:
            risk_factors.append(RiskFactor(
                "no_logging",
                score=0.4,
                weight=1.0,
                description="Bucket access logging is not enabled"
            ))
        
        # Sensitive data increases risk
        if contains_sensitive_data:
            risk_factors.append(RiskFactor(
                "sensitive_data",
                score=0.7,
                weight=1.5,
                description="Bucket may contain sensitive data"
            ))
        
        return self.calculate_severity(risk_factors)
    
    def calculate_ec2_severity(
        self,
        port: int,
        is_open_to_internet: bool = False,
        is_critical_port: bool = False,
        has_public_ip: bool = False,
        allows_all_traffic: bool = False
    ) -> SeverityLevel:
        """
        Calculate severity for EC2/Security Group findings
        
        Args:
            port: Port number
            is_open_to_internet: Port is open to 0.0.0.0/0
            is_critical_port: Port is considered critical (SSH, RDP, DB ports)
            has_public_ip: Instance has a public IP
            allows_all_traffic: Security group allows all traffic
            
        Returns:
            SeverityLevel
        """
        risk_factors = []
        
        # Open to internet
        if is_open_to_internet:
            if is_critical_port:
                risk_factors.append(RiskFactor(
                    "critical_port_open",
                    score=1.0,
                    weight=3.0,
                    description=f"Critical port {port} is open to the internet"
                ))
            elif allows_all_traffic:
                risk_factors.append(RiskFactor(
                    "all_traffic_open",
                    score=1.0,
                    weight=3.0,
                    description="All traffic is allowed from 0.0.0.0/0"
                ))
            else:
                risk_factors.append(RiskFactor(
                    "internet_accessible",
                    score=0.7,
                    weight=2.0,
                    description=f"Port {port} is open to the internet"
                ))
        
        # Instance has public IP (increases exposure)
        if has_public_ip:
            risk_factors.append(RiskFactor(
                "public_ip",
                score=0.6,
                weight=1.5,
                description="Instance has a public IP address"
            ))
        
        return self.calculate_severity(risk_factors)
    
    def calculate_iam_severity(
        self,
        has_mfa: bool = True,
        has_console_access: bool = False,
        has_admin_policy: bool = False,
        is_root_user: bool = False,
        unused_credentials: bool = False,
        excessive_permissions: bool = False
    ) -> SeverityLevel:
        """
        Calculate severity for IAM findings
        
        Args:
            has_mfa: MFA is enabled
            has_console_access: User has console access
            has_admin_policy: User has administrator policy
            is_root_user: Is root account
            unused_credentials: Credentials are unused/stale
            excessive_permissions: User has excessive permissions
            
        Returns:
            SeverityLevel
        """
        risk_factors = []
        
        # Root user issues are critical
        if is_root_user:
            risk_factors.append(RiskFactor(
                "root_user",
                score=1.0,
                weight=3.0,
                description="Root user account issue"
            ))
        
        # No MFA
        if not has_mfa:
            if has_console_access and has_admin_policy:
                risk_factors.append(RiskFactor(
                    "no_mfa_admin",
                    score=0.95,
                    weight=2.5,
                    description="Admin user without MFA and console access"
                ))
            elif has_console_access:
                risk_factors.append(RiskFactor(
                    "no_mfa_console",
                    score=0.8,
                    weight=2.0,
                    description="Console user without MFA"
                ))
            else:
                risk_factors.append(RiskFactor(
                    "no_mfa",
                    score=0.6,
                    weight=1.5,
                    description="User without MFA"
                ))
        
        # Admin policy
        if has_admin_policy:
            weight = 2.5 if not has_mfa else 1.5
            risk_factors.append(RiskFactor(
                "admin_policy",
                score=0.8,
                weight=weight,
                description="User has administrator policy"
            ))
        
        # Excessive permissions
        if excessive_permissions:
            risk_factors.append(RiskFactor(
                "excessive_permissions",
                score=0.6,
                weight=1.5,
                description="User has excessive permissions (violates least privilege)"
            ))
        
        # Unused credentials
        if unused_credentials:
            risk_factors.append(RiskFactor(
                "unused_credentials",
                score=0.5,
                weight=1.0,
                description="Credentials are unused and should be rotated/removed"
            ))
        
        return self.calculate_severity(risk_factors)
    
    # ==================== Anomaly Severity Calculators ====================
    
    def calculate_login_anomaly_severity(
        self,
        is_new_location: bool = False,
        is_new_ip: bool = False,
        failed_attempts: int = 0,
        suspicious_user_agent: bool = False,
        unusual_time: bool = False,
        multiple_locations_short_time: bool = False
    ) -> SeverityLevel:
        """
        Calculate severity for login anomalies
        
        Args:
            is_new_location: Login from new geographic location
            is_new_ip: Login from new IP address
            failed_attempts: Number of failed login attempts
            suspicious_user_agent: User agent appears suspicious
            unusual_time: Login at unusual time
            multiple_locations_short_time: Multiple locations in short time (impossible travel)
            
        Returns:
            SeverityLevel
        """
        risk_factors = []
        
        # Impossible travel is critical
        if multiple_locations_short_time:
            risk_factors.append(RiskFactor(
                "impossible_travel",
                score=1.0,
                weight=3.0,
                description="Login from multiple distant locations in short timeframe"
            ))
        
        # Failed login attempts
        if failed_attempts > 10:
            risk_factors.append(RiskFactor(
                "many_failed_attempts",
                score=0.9,
                weight=2.5,
                description=f"{failed_attempts} failed login attempts detected"
            ))
        elif failed_attempts > 5:
            risk_factors.append(RiskFactor(
                "failed_attempts",
                score=0.7,
                weight=2.0,
                description=f"{failed_attempts} failed login attempts"
            ))
        
        # New location
        if is_new_location:
            risk_factors.append(RiskFactor(
                "new_location",
                score=0.6,
                weight=1.5,
                description="Login from new geographic location"
            ))
        
        # New IP address
        if is_new_ip:
            risk_factors.append(RiskFactor(
                "new_ip",
                score=0.5,
                weight=1.2,
                description="Login from new IP address"
            ))
        
        # Suspicious user agent
        if suspicious_user_agent:
            risk_factors.append(RiskFactor(
                "suspicious_agent",
                score=0.7,
                weight=1.5,
                description="Suspicious user agent detected (automated tool)"
            ))
        
        # Unusual time
        if unusual_time:
            risk_factors.append(RiskFactor(
                "unusual_time",
                score=0.4,
                weight=1.0,
                description="Login at unusual time"
            ))
        
        return self.calculate_severity(risk_factors)
    
    def calculate_api_anomaly_severity(
        self,
        is_destructive: bool = False,
        is_high_risk: bool = False,
        rate_exceeded: bool = False,
        burst_detected: bool = False,
        unusual_api_sequence: bool = False,
        privilege_escalation: bool = False
    ) -> SeverityLevel:
        """
        Calculate severity for API call anomalies
        
        Args:
            is_destructive: API call is destructive (delete, terminate)
            is_high_risk: API call is high-risk (policy modification)
            rate_exceeded: API rate limit exceeded
            burst_detected: Burst of API calls detected
            unusual_api_sequence: Unusual sequence of API calls
            privilege_escalation: Potential privilege escalation attempt
            
        Returns:
            SeverityLevel
        """
        risk_factors = []
        
        # Privilege escalation is critical
        if privilege_escalation:
            risk_factors.append(RiskFactor(
                "privilege_escalation",
                score=1.0,
                weight=3.0,
                description="Potential privilege escalation attempt detected"
            ))
        
        # Destructive operations
        if is_destructive:
            risk_factors.append(RiskFactor(
                "destructive_api",
                score=0.9,
                weight=2.5,
                description="Destructive API operation detected"
            ))
        
        # High-risk APIs
        if is_high_risk:
            risk_factors.append(RiskFactor(
                "high_risk_api",
                score=0.8,
                weight=2.0,
                description="High-risk API call detected"
            ))
        
        # Rate exceeded (possible attack or compromise)
        if rate_exceeded:
            risk_factors.append(RiskFactor(
                "rate_exceeded",
                score=0.7,
                weight=2.0,
                description="API rate limit exceeded (possible compromise)"
            ))
        
        # Burst detected
        if burst_detected:
            risk_factors.append(RiskFactor(
                "burst_detected",
                score=0.6,
                weight=1.5,
                description="Burst of API calls detected"
            ))
        
        # Unusual sequence
        if unusual_api_sequence:
            risk_factors.append(RiskFactor(
                "unusual_sequence",
                score=0.5,
                weight=1.2,
                description="Unusual sequence of API calls"
            ))
        
        return self.calculate_severity(risk_factors)
    
    # ==================== Utility Methods ====================
    
    def get_severity_score(self, severity: SeverityLevel) -> float:
        """
        Get numeric score for a severity level
        
        Args:
            severity: SeverityLevel enum
            
        Returns:
            Numeric score (0-100)
        """
        severity_scores = {
            SeverityLevel.CRITICAL: 90,
            SeverityLevel.HIGH: 75,
            SeverityLevel.MEDIUM: 50,
            SeverityLevel.LOW: 30,
            SeverityLevel.INFO: 10
        }
        return severity_scores.get(severity, 0)
    
    def get_severity_color(self, severity: SeverityLevel) -> str:
        """
        Get color code for severity level (for UI display)
        
        Args:
            severity: SeverityLevel enum
            
        Returns:
            Color name or hex code
        """
        severity_colors = {
            SeverityLevel.CRITICAL: "#d32f2f",  # Red
            SeverityLevel.HIGH: "#f57c00",      # Orange
            SeverityLevel.MEDIUM: "#fbc02d",    # Yellow
            SeverityLevel.LOW: "#388e3c",       # Green
            SeverityLevel.INFO: "#1976d2"       # Blue
        }
        return severity_colors.get(severity, "#757575")
    
    def get_severity_priority(self, severity: SeverityLevel) -> int:
        """
        Get priority order for severity (1 = highest priority)
        
        Args:
            severity: SeverityLevel enum
            
        Returns:
            Priority number (1-5)
        """
        priority_map = {
            SeverityLevel.CRITICAL: 1,
            SeverityLevel.HIGH: 2,
            SeverityLevel.MEDIUM: 3,
            SeverityLevel.LOW: 4,
            SeverityLevel.INFO: 5
        }
        return priority_map.get(severity, 5)


# Singleton instance
_scorer_instance = None


def get_severity_scorer() -> SeverityScorer:
    """
    Get singleton instance of SeverityScorer
    
    Returns:
        SeverityScorer instance
    """
    global _scorer_instance
    if _scorer_instance is None:
        _scorer_instance = SeverityScorer()
    return _scorer_instance
