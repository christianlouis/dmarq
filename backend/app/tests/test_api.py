from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.domain import Domain


def test_read_health(client: TestClient):
    """Test health check endpoint"""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data


def test_read_domains_empty(client: TestClient):
    """Test reading domains when none exist"""
    response = client.get("/api/v1/domains")
    assert response.status_code == 200
    data = response.json()
    assert data == []


def test_read_domains(client: TestClient, db_session: Session):
    """Test reading domains"""
    # Create some test domains
    domain1 = Domain(name="example.com", description="Example Domain", active=True)
    domain2 = Domain(name="test.com", description="Test Domain", active=True)
    db_session.add_all([domain1, domain2])
    db_session.commit()

    response = client.get("/api/v1/domains")
    assert response.status_code == 200
    data = response.json()

    assert len(data) == 2
    assert {"name": "example.com", "description": "Example Domain"}.items() <= data[0].items()
    assert {"name": "test.com", "description": "Test Domain"}.items() <= data[1].items()


def test_create_domain(client: TestClient):
    """Test creating a new domain"""
    import pytest

    pytest.skip("Domain creation via POST is not implemented in Milestone 1")
