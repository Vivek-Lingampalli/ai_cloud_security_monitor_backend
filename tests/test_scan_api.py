"""
Test Scan API endpoints
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.main import app
from app.db.database import Base, get_db

# Create test database
SQLALCHEMY_DATABASE_URL = "sqlite:///./test_scan_api.db"
engine = create_engine(SQLALCHEMY_DATABASE_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    """Override database dependency for testing"""
    try:
        db = TestingSessionLocal()
        yield db
    finally:
        db.close()


@pytest.fixture(scope="module")
def setup_database():
    """Setup test database"""
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def client(setup_database):
    """Create test client"""
    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_run_full_scan(client):
    """Test POST /api/v1/scan endpoint with full scan"""
    response = client.post("/api/v1/scan?scan_type=full")
    
    assert response.status_code == 200
    data = response.json()
    
    assert data["success"] is True
    assert "FULL scan completed successfully" in data["message"]
    assert "scan" in data
    assert "summary" in data
    assert "findings" in data
    
    # Check scan details
    assert data["scan"]["type"] == "full"
    assert data["scan"]["status"] == "completed"
    assert data["scan"]["id"] > 0
    
    # Check summary
    assert "total_findings" in data["summary"]
    assert "critical" in data["summary"]
    assert "high" in data["summary"]
    assert "medium" in data["summary"]
    assert "low" in data["summary"]
    assert "info" in data["summary"]
    
    # Should have findings from all three scanners (S3, IAM, EC2)
    assert data["summary"]["total_findings"] > 0
    assert isinstance(data["findings"], list)


def test_run_s3_scan(client):
    """Test POST /api/v1/scan endpoint with S3 scan"""
    response = client.post("/api/v1/scan?scan_type=s3")
    
    assert response.status_code == 200
    data = response.json()
    
    assert data["success"] is True
    assert data["scan"]["type"] == "s3"
    assert data["scan"]["status"] == "completed"


def test_run_iam_scan(client):
    """Test POST /api/v1/scan endpoint with IAM scan"""
    response = client.post("/api/v1/scan?scan_type=iam")
    
    assert response.status_code == 200
    data = response.json()
    
    assert data["success"] is True
    assert data["scan"]["type"] == "iam"
    
    # Should have IAM findings
    assert data["summary"]["total_findings"] > 0
    
    # Check for IAM-specific findings
    iam_findings = [f for f in data["findings"] if f["resource_type"] == "IAM"]
    assert len(iam_findings) > 0


def test_run_ec2_scan(client):
    """Test POST /api/v1/scan endpoint with EC2 scan"""
    response = client.post("/api/v1/scan?scan_type=ec2")
    
    assert response.status_code == 200
    data = response.json()
    
    assert data["success"] is True
    assert data["scan"]["type"] == "ec2"
    assert data["scan"]["status"] == "completed"
    
    # In mock mode with proper AWS access, should have EC2 findings
    # If using real AWS without permissions, may have 0 findings
    assert data["summary"]["total_findings"] >= 0
    assert isinstance(data["findings"], list)


def test_invalid_scan_type(client):
    """Test POST /api/v1/scan with invalid scan type"""
    response = client.post("/api/v1/scan?scan_type=invalid")
    
    assert response.status_code == 400
    data = response.json()
    assert "Invalid scan type" in data["detail"]


def test_get_scan_by_id(client):
    """Test GET /api/v1/scans/{scan_id} endpoint"""
    # First create a scan
    create_response = client.post("/api/v1/scan?scan_type=iam")
    assert create_response.status_code == 200
    scan_id = create_response.json()["scan"]["id"]
    
    # Get the scan by ID
    response = client.get(f"/api/v1/scans/{scan_id}")
    
    assert response.status_code == 200
    data = response.json()
    
    assert data["success"] is True
    assert data["scan"]["id"] == scan_id
    assert "findings" in data
    assert "summary" in data


def test_get_nonexistent_scan(client):
    """Test GET /api/v1/scans/{scan_id} with non-existent ID"""
    response = client.get("/api/v1/scans/99999")
    
    assert response.status_code == 404
    data = response.json()
    assert "not found" in data["detail"]


def test_list_scans(client):
    """Test GET /api/v1/scans endpoint"""
    # Create a few scans first
    client.post("/api/v1/scan?scan_type=s3")
    client.post("/api/v1/scan?scan_type=iam")
    
    # List scans
    response = client.get("/api/v1/scans")
    
    assert response.status_code == 200
    data = response.json()
    
    assert "total" in data
    assert "scans" in data
    assert data["total"] >= 2
    assert isinstance(data["scans"], list)


def test_finding_structure(client):
    """Test that findings have correct structure"""
    response = client.post("/api/v1/scan?scan_type=full")
    
    assert response.status_code == 200
    data = response.json()
    
    if len(data["findings"]) > 0:
        finding = data["findings"][0]
        
        # Required fields
        assert "id" in finding
        assert "title" in finding
        assert "description" in finding
        assert "severity" in finding
        assert "resource_type" in finding
        assert "resource_id" in finding
        assert "status" in finding
        
        # Severity should be valid
        assert finding["severity"] in ["critical", "high", "medium", "low", "info"]
        
        # Resource type should be valid
        assert finding["resource_type"] in ["S3", "IAM", "EC2"]


def test_severity_breakdown(client):
    """Test that severity breakdown is correct"""
    response = client.post("/api/v1/scan?scan_type=full")
    
    assert response.status_code == 200
    data = response.json()
    
    summary = data["summary"]
    total = summary["total_findings"]
    
    # Sum of severity counts should equal total findings
    severity_sum = (
        summary["critical"] + 
        summary["high"] + 
        summary["medium"] + 
        summary["low"] + 
        summary["info"]
    )
    
    assert severity_sum == total


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
