"""
Test Severity Scoring Logic

Tests for the centralized severity scoring module
"""

import pytest
from app.utils.severity_scorer import (
    SeverityScorer,
    SeverityLevel,
    RiskFactor,
    get_severity_scorer
)


class TestSeverityScorer:
    """Test SeverityScorer functionality"""
    
    def setup_method(self):
        """Setup test instance"""
        self.scorer = SeverityScorer()
    
    # ==================== Basic Functionality Tests ====================
    
    def test_singleton_instance(self):
        """Test that get_severity_scorer returns singleton"""
        scorer1 = get_severity_scorer()
        scorer2 = get_severity_scorer()
        assert scorer1 is scorer2
    
    def test_empty_risk_factors(self):
        """Test with no risk factors returns INFO"""
        severity = self.scorer.calculate_severity([])
        assert severity == SeverityLevel.INFO
    
    def test_score_to_severity_mapping(self):
        """Test score to severity level mapping"""
        assert self.scorer._score_to_severity(95) == SeverityLevel.CRITICAL
        assert self.scorer._score_to_severity(85) == SeverityLevel.CRITICAL
        assert self.scorer._score_to_severity(75) == SeverityLevel.HIGH
        assert self.scorer._score_to_severity(65) == SeverityLevel.HIGH
        assert self.scorer._score_to_severity(50) == SeverityLevel.MEDIUM
        assert self.scorer._score_to_severity(40) == SeverityLevel.MEDIUM
        assert self.scorer._score_to_severity(30) == SeverityLevel.LOW
        assert self.scorer._score_to_severity(20) == SeverityLevel.LOW
        assert self.scorer._score_to_severity(10) == SeverityLevel.INFO
    
    def test_manual_override(self):
        """Test that manual override works"""
        risk_factors = [RiskFactor("test", score=1.0, weight=3.0)]
        severity = self.scorer.calculate_severity(
            risk_factors,
            override_level=SeverityLevel.LOW
        )
        assert severity == SeverityLevel.LOW
    
    # ==================== S3 Severity Tests ====================
    
    def test_s3_public_bucket_critical(self):
        """Test that public S3 bucket with ACL is CRITICAL"""
        severity = self.scorer.calculate_s3_severity(
            is_public=True,
            has_encryption=False,
            public_acl=True
        )
        assert severity == SeverityLevel.CRITICAL
    
    def test_s3_no_encryption_medium(self):
        """Test that S3 bucket without encryption is MEDIUM (if not public)"""
        severity = self.scorer.calculate_s3_severity(
            is_public=False,
            has_encryption=False,
            has_versioning=True,
            has_logging=True,
            public_acl=False
        )
        assert severity in [SeverityLevel.MEDIUM, SeverityLevel.HIGH]
    
    def test_s3_public_no_acl_high(self):
        """Test that public S3 bucket without ACL is HIGH"""
        severity = self.scorer.calculate_s3_severity(
            is_public=True,
            has_encryption=True,
            public_acl=False
        )
        assert severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]
    
    def test_s3_missing_logging_low(self):
        """Test that only missing logging is LOW"""
        severity = self.scorer.calculate_s3_severity(
            is_public=False,
            has_encryption=True,
            has_versioning=True,
            has_logging=False,
            public_acl=False
        )
        assert severity in [SeverityLevel.LOW, SeverityLevel.MEDIUM]
    
    # ==================== EC2 Severity Tests ====================
    
    def test_ec2_ssh_open_critical(self):
        """Test that SSH open to internet is CRITICAL"""
        severity = self.scorer.calculate_ec2_severity(
            port=22,
            is_open_to_internet=True,
            is_critical_port=True,
            has_public_ip=True
        )
        assert severity == SeverityLevel.CRITICAL
    
    def test_ec2_rdp_open_critical(self):
        """Test that RDP open to internet is CRITICAL"""
        severity = self.scorer.calculate_ec2_severity(
            port=3389,
            is_open_to_internet=True,
            is_critical_port=True,
            has_public_ip=True
        )
        assert severity == SeverityLevel.CRITICAL
    
    def test_ec2_http_open_medium(self):
        """Test that HTTP open to internet is MEDIUM"""
        severity = self.scorer.calculate_ec2_severity(
            port=80,
            is_open_to_internet=True,
            is_critical_port=False,
            has_public_ip=True
        )
        assert severity in [SeverityLevel.MEDIUM, SeverityLevel.HIGH]
    
    def test_ec2_all_traffic_critical(self):
        """Test that all traffic open is CRITICAL"""
        severity = self.scorer.calculate_ec2_severity(
            port=0,
            is_open_to_internet=True,
            is_critical_port=False,
            has_public_ip=True,
            allows_all_traffic=True
        )
        assert severity == SeverityLevel.CRITICAL
    
    # ==================== IAM Severity Tests ====================
    
    def test_iam_no_mfa_admin_critical(self):
        """Test that admin without MFA is CRITICAL"""
        severity = self.scorer.calculate_iam_severity(
            has_mfa=False,
            has_console_access=True,
            has_admin_policy=True
        )
        assert severity == SeverityLevel.CRITICAL
    
    def test_iam_root_user_critical(self):
        """Test that root user issues are CRITICAL"""
        severity = self.scorer.calculate_iam_severity(
            has_mfa=True,
            is_root_user=True
        )
        assert severity == SeverityLevel.CRITICAL
    
    def test_iam_no_mfa_console_high(self):
        """Test that console user without MFA is HIGH"""
        severity = self.scorer.calculate_iam_severity(
            has_mfa=False,
            has_console_access=True,
            has_admin_policy=False
        )
        assert severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]
    
    def test_iam_unused_credentials_low(self):
        """Test that unused credentials is LOW"""
        severity = self.scorer.calculate_iam_severity(
            has_mfa=True,
            has_console_access=False,
            has_admin_policy=False,
            unused_credentials=True
        )
        assert severity in [SeverityLevel.LOW, SeverityLevel.MEDIUM]
    
    # ==================== Login Anomaly Tests ====================
    
    def test_login_impossible_travel_critical(self):
        """Test that impossible travel is CRITICAL"""
        severity = self.scorer.calculate_login_anomaly_severity(
            is_new_location=True,
            multiple_locations_short_time=True
        )
        assert severity == SeverityLevel.CRITICAL
    
    def test_login_many_failed_attempts_high(self):
        """Test that many failed attempts is HIGH/CRITICAL"""
        severity = self.scorer.calculate_login_anomaly_severity(
            failed_attempts=15
        )
        assert severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]
    
    def test_login_new_location_medium(self):
        """Test that new location is MEDIUM"""
        severity = self.scorer.calculate_login_anomaly_severity(
            is_new_location=True,
            is_new_ip=True
        )
        assert severity in [SeverityLevel.MEDIUM, SeverityLevel.HIGH]
    
    def test_login_suspicious_agent_medium(self):
        """Test that suspicious user agent is MEDIUM"""
        severity = self.scorer.calculate_login_anomaly_severity(
            suspicious_user_agent=True
        )
        assert severity in [SeverityLevel.MEDIUM, SeverityLevel.HIGH]
    
    # ==================== API Anomaly Tests ====================
    
    def test_api_privilege_escalation_critical(self):
        """Test that privilege escalation is CRITICAL"""
        severity = self.scorer.calculate_api_anomaly_severity(
            privilege_escalation=True
        )
        assert severity == SeverityLevel.CRITICAL
    
    def test_api_destructive_high(self):
        """Test that destructive API is HIGH/CRITICAL"""
        severity = self.scorer.calculate_api_anomaly_severity(
            is_destructive=True,
            is_high_risk=True
        )
        assert severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]
    
    def test_api_rate_exceeded_high(self):
        """Test that rate exceeded is HIGH"""
        severity = self.scorer.calculate_api_anomaly_severity(
            rate_exceeded=True
        )
        assert severity in [SeverityLevel.MEDIUM, SeverityLevel.HIGH]
    
    def test_api_burst_medium(self):
        """Test that burst detection is MEDIUM"""
        severity = self.scorer.calculate_api_anomaly_severity(
            burst_detected=True
        )
        assert severity in [SeverityLevel.MEDIUM, SeverityLevel.HIGH]
    
    # ==================== Custom Risk Factors Tests ====================
    
    def test_custom_risk_factors_high(self):
        """Test custom risk factors calculation"""
        risk_factors = [
            RiskFactor("factor1", score=0.8, weight=2.0),
            RiskFactor("factor2", score=0.7, weight=1.5),
            RiskFactor("factor3", score=0.9, weight=2.5)
        ]
        severity = self.scorer.calculate_severity(risk_factors)
        assert severity in [SeverityLevel.HIGH, SeverityLevel.CRITICAL]
    
    def test_risk_factor_weighted_score(self):
        """Test RiskFactor weighted score calculation"""
        rf = RiskFactor("test", score=0.8, weight=2.0)
        assert rf.weighted_score() == 1.6
    
    def test_low_risk_factors_info(self):
        """Test that low risk factors result in INFO or LOW"""
        risk_factors = [
            RiskFactor("factor1", score=0.1, weight=1.0),
            RiskFactor("factor2", score=0.15, weight=1.0)
        ]
        severity = self.scorer.calculate_severity(risk_factors)
        assert severity in [SeverityLevel.INFO, SeverityLevel.LOW]
    
    # ==================== Utility Methods Tests ====================
    
    def test_get_severity_score(self):
        """Test get_severity_score returns correct values"""
        assert self.scorer.get_severity_score(SeverityLevel.CRITICAL) == 90
        assert self.scorer.get_severity_score(SeverityLevel.HIGH) == 75
        assert self.scorer.get_severity_score(SeverityLevel.MEDIUM) == 50
        assert self.scorer.get_severity_score(SeverityLevel.LOW) == 30
        assert self.scorer.get_severity_score(SeverityLevel.INFO) == 10
    
    def test_get_severity_color(self):
        """Test get_severity_color returns valid colors"""
        colors = [
            self.scorer.get_severity_color(SeverityLevel.CRITICAL),
            self.scorer.get_severity_color(SeverityLevel.HIGH),
            self.scorer.get_severity_color(SeverityLevel.MEDIUM),
            self.scorer.get_severity_color(SeverityLevel.LOW),
            self.scorer.get_severity_color(SeverityLevel.INFO)
        ]
        # All should be hex colors
        for color in colors:
            assert color.startswith("#")
            assert len(color) == 7
    
    def test_get_severity_priority(self):
        """Test get_severity_priority returns correct order"""
        assert self.scorer.get_severity_priority(SeverityLevel.CRITICAL) == 1
        assert self.scorer.get_severity_priority(SeverityLevel.HIGH) == 2
        assert self.scorer.get_severity_priority(SeverityLevel.MEDIUM) == 3
        assert self.scorer.get_severity_priority(SeverityLevel.LOW) == 4
        assert self.scorer.get_severity_priority(SeverityLevel.INFO) == 5
    
    # ==================== Edge Cases Tests ====================
    
    def test_zero_weight_risk_factors(self):
        """Test handling of zero weight risk factors"""
        risk_factors = [
            RiskFactor("factor1", score=1.0, weight=0.0),
            RiskFactor("factor2", score=1.0, weight=0.0)
        ]
        severity = self.scorer.calculate_severity(risk_factors)
        assert severity == SeverityLevel.INFO
    
    def test_very_high_scores(self):
        """Test that very high scores result in CRITICAL"""
        risk_factors = [
            RiskFactor("critical_issue", score=1.0, weight=5.0)
        ]
        severity = self.scorer.calculate_severity(risk_factors)
        assert severity == SeverityLevel.CRITICAL
    
    def test_mixed_risk_factors(self):
        """Test mixed high and low risk factors"""
        risk_factors = [
            RiskFactor("high_risk", score=0.9, weight=2.0),
            RiskFactor("low_risk", score=0.2, weight=1.0)
        ]
        severity = self.scorer.calculate_severity(risk_factors)
        # Should be weighted toward the higher risk
        assert severity in [SeverityLevel.MEDIUM, SeverityLevel.HIGH, SeverityLevel.CRITICAL]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
