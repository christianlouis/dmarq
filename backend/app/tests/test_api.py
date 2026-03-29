from fastapi.testclient import TestClient


def test_health_check(client: TestClient):
    """Test the health check endpoint returns status ok."""
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data


def test_domains_empty(client: TestClient):
    """Test that GET /api/v1/domains/domains returns empty list when no reports uploaded."""
    response = client.get("/api/v1/domains/domains")
    assert response.status_code == 200
    data = response.json()
    assert data == []


def test_reports_upload_invalid_extension(client: TestClient):
    """Test that uploading a file with an unsupported extension returns 400."""
    response = client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.txt", b"not a report", "text/plain")},
    )
    assert response.status_code == 400
    assert "Invalid file type" in response.json()["detail"]


def test_reports_upload_empty_file(client: TestClient):
    """Test that uploading an empty file returns 400."""
    response = client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.xml", b"", "application/xml")},
    )
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()
