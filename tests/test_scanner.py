"""
Test IAM Scanner functionality
"""
import pytest
from app.scanners.iam_scanner import IAMScanner
from app.db.schemas import SeverityLevel
from app.utils.aws_client import get_aws_client, AWSClient


@pytest.fixture
def mock_aws_client():
    """Fixture to create a mock AWS client"""
    return AWSClient(mock_mode=True)


@pytest.fixture
def iam_scanner(mock_aws_client):
    """Fixture to create IAM scanner with mock client"""
    scanner = IAMScanner()
    scanner.aws_client = mock_aws_client
    return scanner


def test_iam_scanner_initialization():
    """Test IAM scanner can be initialized"""
    scanner = IAMScanner()
    assert scanner is not None
    assert scanner.region == "us-east-1"


def test_iam_scanner_list_users(iam_scanner):
    """Test IAM scanner can list users"""
    users = iam_scanner.list_users()
    
    assert isinstance(users, list)
    # In mock mode, we should get our mock users
    assert len(users) > 0
    
    # Check user structure
    for user in users:
        assert 'UserName' in user
        assert 'Arn' in user


def test_iam_scanner_detects_users_without_mfa(iam_scanner):
    """Test IAM scanner detects users without MFA enabled"""
    findings = iam_scanner.scan()
    
    # Check for MFA-related findings
    mfa_findings = [f for f in findings if 'MFA' in f.title]
    assert len(mfa_findings) > 0
    
    # Verify finding structure
    for finding in mfa_findings:
        assert finding.resource_type == "IAM"
        assert finding.severity in [SeverityLevel.HIGH, SeverityLevel.MEDIUM]
        assert 'Multi-Factor Authentication' in finding.description or 'MFA' in finding.description
        assert finding.region == "global"


def test_iam_scanner_detects_admin_policies(iam_scanner):
    """Test IAM scanner detects users with administrator access"""
    findings = iam_scanner.scan()
    
    # Check for admin policy findings
    admin_findings = [f for f in findings if 'Administrator' in f.title or 'admin' in f.title.lower()]
    assert len(admin_findings) > 0
    
    # Verify finding structure
    for finding in admin_findings:
        assert finding.resource_type == "IAM"
        assert finding.severity in [SeverityLevel.CRITICAL, SeverityLevel.HIGH]
        assert finding.region == "global"


def test_iam_scanner_admin_without_mfa_is_critical(iam_scanner):
    """Test that admin users without MFA are flagged as CRITICAL"""
    findings = iam_scanner.scan()
    
    # Find admin findings without MFA
    critical_admin_findings = [
        f for f in findings 
        if 'Administrator' in f.title and 'NO MFA' in f.title
    ]
    
    # These should be CRITICAL severity
    for finding in critical_admin_findings:
        assert finding.severity == SeverityLevel.CRITICAL


def test_iam_scanner_password_policy_check(iam_scanner):
    """Test IAM scanner checks password policy"""
    findings = iam_scanner.scan()
    
    # Check for password policy findings
    password_findings = [f for f in findings if 'Password Policy' in f.title]
    assert len(password_findings) > 0
    
    # Verify finding structure
    for finding in password_findings:
        assert finding.resource_type == "IAM"
        assert finding.resource_id == "account-password-policy"
        assert finding.region == "global"


def test_iam_scanner_full_scan(iam_scanner):
    """Test complete IAM scan returns expected findings"""
    findings = iam_scanner.scan()
    
    # Should have findings (in mock mode)
    assert len(findings) > 0
    
    # All findings should be properly structured
    for finding in findings:
        assert finding.title
        assert finding.description
        assert finding.severity
        assert finding.resource_type == "IAM"
        assert finding.resource_id
        assert finding.region == "global"


def test_mfa_devices_check(mock_aws_client):
    """Test MFA device checking for specific users"""
    # Test admin user (should have MFA in mock mode)
    admin_mfa = mock_aws_client.list_mfa_devices('admin-user')
    assert len(admin_mfa) > 0
    
    # Test developer user (should not have MFA in mock mode)
    dev_mfa = mock_aws_client.list_mfa_devices('developer')
    assert len(dev_mfa) == 0


def test_admin_policy_detection(iam_scanner):
    """Test detection of administrator policies"""
    # Test with various policy ARNs
    assert iam_scanner._is_admin_policy(
        'arn:aws:iam::aws:policy/AdministratorAccess',
        'AdministratorAccess'
    ) is True
    
    assert iam_scanner._is_admin_policy(
        'arn:aws:iam::aws:policy/PowerUserAccess',
        'PowerUserAccess'
    ) is True
    
    assert iam_scanner._is_admin_policy(
        'arn:aws:iam::aws:policy/ReadOnlyAccess',
        'ReadOnlyAccess'
    ) is False


def test_account_id_extraction(iam_scanner):
    """Test extraction of account ID from ARN"""
    arn = 'arn:aws:iam::123456789012:user/test-user'
    account_id = iam_scanner._extract_account_id(arn)
    assert account_id == '123456789012'
    
    # Test with invalid ARN
    assert iam_scanner._extract_account_id('') == ''
    assert iam_scanner._extract_account_id('invalid-arn') == ''


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
