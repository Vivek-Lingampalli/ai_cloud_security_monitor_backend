"""
Severity Scoring Examples

This file demonstrates how to use the SeverityScorer in various scenarios.
Use these patterns in scanners, detectors, and services.
"""

from app.utils.severity_scorer import get_severity_scorer, SeverityLevel, RiskFactor

# Get the scorer instance
scorer = get_severity_scorer()


# ==================== S3 Scanner Example ====================

def example_s3_public_bucket():
    """Example: S3 bucket that is publicly accessible"""
    severity = scorer.calculate_s3_severity(
        is_public=True,
        has_encryption=False,
        has_versioning=True,
        has_logging=False,
        contains_sensitive_data=True,
        public_acl=True
    )
    print(f"Public S3 bucket with no encryption: {severity.value}")
    # Result: CRITICAL


def example_s3_missing_encryption():
    """Example: S3 bucket missing encryption only"""
    severity = scorer.calculate_s3_severity(
        is_public=False,
        has_encryption=False,
        has_versioning=True,
        has_logging=True,
        contains_sensitive_data=False,
        public_acl=False
    )
    print(f"S3 bucket missing encryption: {severity.value}")
    # Result: MEDIUM


# ==================== EC2 Scanner Example ====================

def example_ec2_ssh_open():
    """Example: EC2 instance with SSH open to internet"""
    severity = scorer.calculate_ec2_severity(
        port=22,
        is_open_to_internet=True,
        is_critical_port=True,
        has_public_ip=True,
        allows_all_traffic=False
    )
    print(f"SSH open to internet: {severity.value}")
    # Result: CRITICAL


def example_ec2_http_open():
    """Example: EC2 instance with HTTP open to internet"""
    severity = scorer.calculate_ec2_severity(
        port=80,
        is_open_to_internet=True,
        is_critical_port=False,
        has_public_ip=True,
        allows_all_traffic=False
    )
    print(f"HTTP open to internet: {severity.value}")
    # Result: MEDIUM or HIGH


# ==================== IAM Scanner Example ====================

def example_iam_no_mfa_admin():
    """Example: Admin user without MFA"""
    severity = scorer.calculate_iam_severity(
        has_mfa=False,
        has_console_access=True,
        has_admin_policy=True,
        is_root_user=False,
        unused_credentials=False,
        excessive_permissions=False
    )
    print(f"Admin user without MFA: {severity.value}")
    # Result: CRITICAL


def example_iam_unused_credentials():
    """Example: User with unused credentials"""
    severity = scorer.calculate_iam_severity(
        has_mfa=True,
        has_console_access=False,
        has_admin_policy=False,
        is_root_user=False,
        unused_credentials=True,
        excessive_permissions=False
    )
    print(f"Unused credentials: {severity.value}")
    # Result: LOW


# ==================== Login Anomaly Example ====================

def example_login_impossible_travel():
    """Example: Impossible travel login anomaly"""
    severity = scorer.calculate_login_anomaly_severity(
        is_new_location=True,
        is_new_ip=True,
        failed_attempts=0,
        suspicious_user_agent=False,
        unusual_time=False,
        multiple_locations_short_time=True
    )
    print(f"Impossible travel detected: {severity.value}")
    # Result: CRITICAL


def example_login_new_location():
    """Example: Login from new location"""
    severity = scorer.calculate_login_anomaly_severity(
        is_new_location=True,
        is_new_ip=True,
        failed_attempts=0,
        suspicious_user_agent=False,
        unusual_time=False,
        multiple_locations_short_time=False
    )
    print(f"New location login: {severity.value}")
    # Result: MEDIUM


# ==================== API Anomaly Example ====================

def example_api_privilege_escalation():
    """Example: Potential privilege escalation"""
    severity = scorer.calculate_api_anomaly_severity(
        is_destructive=False,
        is_high_risk=True,
        rate_exceeded=False,
        burst_detected=False,
        unusual_api_sequence=True,
        privilege_escalation=True
    )
    print(f"Privilege escalation attempt: {severity.value}")
    # Result: CRITICAL


def example_api_destructive():
    """Example: Destructive API call"""
    severity = scorer.calculate_api_anomaly_severity(
        is_destructive=True,
        is_high_risk=True,
        rate_exceeded=False,
        burst_detected=False,
        unusual_api_sequence=False,
        privilege_escalation=False
    )
    print(f"Destructive API call: {severity.value}")
    # Result: HIGH or CRITICAL


# ==================== Custom Risk Factors Example ====================

def example_custom_risk_factors():
    """Example: Using custom risk factors for complex scenarios"""
    risk_factors = [
        RiskFactor(
            name="data_exfiltration",
            score=0.9,
            weight=3.0,
            description="Potential data exfiltration detected"
        ),
        RiskFactor(
            name="anomalous_volume",
            score=0.8,
            weight=2.0,
            description="Unusual data transfer volume"
        ),
        RiskFactor(
            name="new_destination",
            score=0.6,
            weight=1.5,
            description="Data sent to new external destination"
        )
    ]
    
    severity = scorer.calculate_severity(risk_factors)
    print(f"Custom risk factors severity: {severity.value}")
    # Result: Based on weighted calculation


# ==================== Integration Example ====================

def example_s3_scanner_integration():
    """
    Example: How to integrate severity scorer in S3 scanner
    
    This shows the pattern you should use in your scanners:
    1. Check security conditions
    2. Use scorer to calculate severity
    3. Create finding with calculated severity
    """
    # Simulated S3 bucket check
    bucket_name = "example-bucket"
    public_access_block = {
        'BlockPublicAcls': False,
        'IgnorePublicAcls': True,
        'BlockPublicPolicy': False,
        'RestrictPublicBuckets': False
    }
    
    # Calculate severity based on actual conditions
    is_fully_blocked = all([
        public_access_block.get('BlockPublicAcls', False),
        public_access_block.get('IgnorePublicAcls', False),
        public_access_block.get('BlockPublicPolicy', False),
        public_access_block.get('RestrictPublicBuckets', False)
    ])
    
    if not is_fully_blocked:
        # Use severity scorer instead of hardcoded severity
        severity = scorer.calculate_s3_severity(
            is_public=True,
            has_encryption=True,  # Would check actual encryption status
            has_versioning=True,  # Would check actual versioning status
            has_logging=False,
            contains_sensitive_data=False,  # Could use heuristics or tagging
            public_acl=False
        )
        
        # Create finding with calculated severity
        from app.db.schemas import FindingCreate
        
        finding = FindingCreate(
            title=f"S3 Bucket Public Access Block Not Fully Enabled: {bucket_name}",
            description=f"The S3 bucket '{bucket_name}' does not have all Public Access Block settings enabled.",
            severity=severity,  # Use calculated severity
            resource_type="S3",
            resource_id=bucket_name,
            resource_arn=f"arn:aws:s3:::{bucket_name}",
            region="us-east-1"
        )
        
        print(f"Created finding with severity: {severity.value}")
        return finding


# ==================== Utility Functions Example ====================

def example_utility_functions():
    """Example: Using utility functions"""
    
    # Get numeric score
    score = scorer.get_severity_score(SeverityLevel.HIGH)
    print(f"HIGH severity score: {score}")
    
    # Get color for UI
    color = scorer.get_severity_color(SeverityLevel.CRITICAL)
    print(f"CRITICAL severity color: {color}")
    
    # Get priority for sorting
    priority = scorer.get_severity_priority(SeverityLevel.MEDIUM)
    print(f"MEDIUM severity priority: {priority}")


if __name__ == "__main__":
    print("=== S3 Examples ===")
    example_s3_public_bucket()
    example_s3_missing_encryption()
    
    print("\n=== EC2 Examples ===")
    example_ec2_ssh_open()
    example_ec2_http_open()
    
    print("\n=== IAM Examples ===")
    example_iam_no_mfa_admin()
    example_iam_unused_credentials()
    
    print("\n=== Login Anomaly Examples ===")
    example_login_impossible_travel()
    example_login_new_location()
    
    print("\n=== API Anomaly Examples ===")
    example_api_privilege_escalation()
    example_api_destructive()
    
    print("\n=== Custom Risk Factors ===")
    example_custom_risk_factors()
    
    print("\n=== Utility Functions ===")
    example_utility_functions()
