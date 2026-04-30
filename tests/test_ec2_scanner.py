"""
Test EC2 Scanner functionality
"""
import pytest
from app.scanners.ec2_scanner import EC2Scanner
from app.db.schemas import SeverityLevel
from app.utils.aws_client import AWSClient


@pytest.fixture
def mock_aws_client():
    """Fixture to create a mock AWS client"""
    return AWSClient(mock_mode=True)


@pytest.fixture
def ec2_scanner(mock_aws_client):
    """Fixture to create EC2 scanner with mock client"""
    scanner = EC2Scanner()
    scanner.aws_client = mock_aws_client
    return scanner


def test_ec2_scanner_initialization():
    """Test EC2 scanner can be initialized"""
    scanner = EC2Scanner()
    assert scanner is not None
    assert scanner.region == "us-east-1"


def test_ec2_scanner_list_instances(ec2_scanner):
    """Test EC2 scanner can list instances"""
    instances = ec2_scanner.list_instances()
    
    assert isinstance(instances, list)
    assert len(instances) > 0
    
    # Check instance structure
    for instance in instances:
        assert 'InstanceId' in instance
        assert 'State' in instance


def test_ec2_scanner_list_security_groups(ec2_scanner):
    """Test EC2 scanner can list security groups"""
    security_groups = ec2_scanner.list_security_groups()
    
    assert isinstance(security_groups, list)
    assert len(security_groups) > 0
    
    # Check security group structure
    for sg in security_groups:
        assert 'GroupId' in sg
        assert 'GroupName' in sg


def test_ec2_scanner_detects_ssh_open_to_internet(ec2_scanner):
    """Test EC2 scanner detects SSH port open to 0.0.0.0/0"""
    findings = ec2_scanner.scan()
    
    # Check for SSH-related findings
    ssh_findings = [f for f in findings if 'SSH' in f.title and '0.0.0.0/0' in f.description]
    assert len(ssh_findings) > 0
    
    # SSH open to internet should be CRITICAL
    for finding in ssh_findings:
        assert finding.severity == SeverityLevel.CRITICAL
        assert finding.resource_type == "EC2"
        assert '22' in finding.description


def test_ec2_scanner_detects_rdp_open_to_internet(ec2_scanner):
    """Test EC2 scanner detects RDP port open to 0.0.0.0/0"""
    findings = ec2_scanner.scan()
    
    # Check for RDP-related findings
    rdp_findings = [f for f in findings if 'RDP' in f.title]
    assert len(rdp_findings) > 0
    
    # RDP open to internet should be CRITICAL
    for finding in rdp_findings:
        assert finding.severity == SeverityLevel.CRITICAL
        assert finding.resource_type == "EC2"


def test_ec2_scanner_detects_database_ports_open(ec2_scanner):
    """Test EC2 scanner detects database ports open to internet"""
    findings = ec2_scanner.scan()
    
    # Check for MySQL-related findings
    db_findings = [f for f in findings if 'MySQL' in f.title or '3306' in f.description]
    assert len(db_findings) > 0
    
    # Database ports open to internet should be CRITICAL
    for finding in db_findings:
        assert finding.severity == SeverityLevel.CRITICAL


def test_ec2_scanner_http_https_info_level(ec2_scanner):
    """Test EC2 scanner marks HTTP/HTTPS as INFO level"""
    findings = ec2_scanner.scan()
    
    # Check for HTTP/HTTPS findings
    web_findings = [f for f in findings if 'HTTP' in f.title and 'HTTPS' not in f.title]
    
    # HTTP/HTTPS should be INFO level (common for web servers)
    for finding in web_findings:
        if 'port 80' in finding.description or 'port 443' in finding.description:
            assert finding.severity == SeverityLevel.INFO


def test_ec2_scanner_full_scan(ec2_scanner):
    """Test complete EC2 scan returns expected findings"""
    findings = ec2_scanner.scan()
    
    # Should have findings (in mock mode with insecure security groups)
    assert len(findings) > 0
    
    # All findings should be properly structured
    for finding in findings:
        assert finding.title
        assert finding.description
        assert finding.severity
        assert finding.resource_type == "EC2"
        assert finding.resource_id
        assert finding.region


def test_ec2_scanner_port_risk_classification(ec2_scanner):
    """Test port risk classification logic"""
    # Critical ports
    severity, name = ec2_scanner._classify_port_risk(22, 'tcp')
    assert severity == SeverityLevel.CRITICAL
    assert name == 'SSH'
    
    severity, name = ec2_scanner._classify_port_risk(3389, 'tcp')
    assert severity == SeverityLevel.CRITICAL
    assert name == 'RDP'
    
    severity, name = ec2_scanner._classify_port_risk(3306, 'tcp')
    assert severity == SeverityLevel.CRITICAL
    assert name == 'MySQL'
    
    # Web ports (INFO level)
    severity, name = ec2_scanner._classify_port_risk(80, 'tcp')
    assert severity == SeverityLevel.INFO
    assert name == 'HTTP'
    
    severity, name = ec2_scanner._classify_port_risk(443, 'tcp')
    assert severity == SeverityLevel.INFO
    assert name == 'HTTPS'
    
    # Privileged ports (HIGH level)
    severity, name = ec2_scanner._classify_port_risk(25, 'tcp')
    assert severity == SeverityLevel.HIGH
    
    # Port 8080 is in CRITICAL_PORTS (HTTP Alt)
    severity, name = ec2_scanner._classify_port_risk(8080, 'tcp')
    assert severity == SeverityLevel.CRITICAL
    assert name == 'HTTP Alt'
    
    # Non-critical high port (MEDIUM level)
    severity, name = ec2_scanner._classify_port_risk(9999, 'tcp')
    assert severity == SeverityLevel.MEDIUM


def test_ec2_scanner_security_group_risk_map(ec2_scanner):
    """Test security group risk mapping"""
    security_groups = ec2_scanner.list_security_groups()
    risk_map = ec2_scanner._build_security_group_risk_map(security_groups)
    
    assert isinstance(risk_map, dict)
    assert len(risk_map) > 0
    
    # Security groups with critical ports should be marked as CRITICAL
    for sg_id, risk_level in risk_map.items():
        assert risk_level in [SeverityLevel.INFO, SeverityLevel.MEDIUM, 
                              SeverityLevel.HIGH, SeverityLevel.CRITICAL]


def test_ec2_scanner_instance_name_extraction(ec2_scanner):
    """Test instance name extraction from tags"""
    instance_with_name = {
        'InstanceId': 'i-1234567890',
        'Tags': [
            {'Key': 'Name', 'Value': 'WebServer'},
            {'Key': 'Environment', 'Value': 'Production'}
        ]
    }
    
    name = ec2_scanner._get_instance_name(instance_with_name)
    assert name == 'WebServer'
    
    # Instance without Name tag
    instance_without_name = {
        'InstanceId': 'i-0987654321',
        'Tags': []
    }
    
    name = ec2_scanner._get_instance_name(instance_without_name)
    assert name == 'i-0987654321'


def test_ec2_scanner_detects_multiple_security_issues(ec2_scanner):
    """Test scanner detects various types of security issues"""
    findings = ec2_scanner.scan()
    
    # Should detect different severity levels
    severities = {f.severity for f in findings}
    assert SeverityLevel.CRITICAL in severities
    
    # Should detect different types of issues
    titles = {f.title for f in findings}
    
    # Check we have variety in findings
    assert len(titles) > 1


def test_unrestricted_outbound_detection(ec2_scanner):
    """Test detection of unrestricted outbound rules"""
    rule_unrestricted = {
        'IpProtocol': '-1',
        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
    }
    
    assert ec2_scanner._is_unrestricted_outbound(rule_unrestricted) is True
    
    rule_restricted = {
        'IpProtocol': 'tcp',
        'FromPort': 443,
        'ToPort': 443,
        'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
    }
    
    assert ec2_scanner._is_unrestricted_outbound(rule_restricted) is False


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
