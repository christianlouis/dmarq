from fastapi.testclient import TestClient

from app.main import app


def test_health_check(authed_client: TestClient):
    """Test the health check endpoint returns status ok."""
    response = authed_client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data


def test_domains_empty(authed_client: TestClient):
    """Test that GET /api/v1/domains/domains returns empty list when no reports uploaded."""
    response = authed_client.get("/api/v1/domains/domains")
    assert response.status_code == 200
    data = response.json()
    assert data == []


def test_create_domain_without_reports(authed_client: TestClient):
    """A monitored domain can be created before its first report arrives."""
    response = authed_client.post(
        "/api/v1/domains/domains",
        json={"name": "Example.COM.", "description": "Primary mail domain"},
    )
    assert response.status_code == 201
    assert response.json()["name"] == "example.com"

    list_response = authed_client.get("/api/v1/domains/domains")
    assert list_response.status_code == 200
    assert list_response.json()[0]["name"] == "example.com"
    assert list_response.json()[0]["reports_count"] == 0


def test_create_domain_rejects_duplicates(authed_client: TestClient):
    """Creating the same monitored domain twice returns a conflict."""
    first = authed_client.post("/api/v1/domains/domains", json={"name": "example.com"})
    second = authed_client.post("/api/v1/domains/domains", json={"name": "EXAMPLE.com"})

    assert first.status_code == 201
    assert second.status_code == 409


def test_operations_health_endpoint(authed_client: TestClient):
    """Detailed health includes database, scheduler, import, and report sections."""
    response = authed_client.get("/api/v1/health/operations")
    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "dmarq"
    assert data["database"]["ok"] is True
    assert "scheduler" in data
    assert "imports" in data
    assert "reports" in data
    assert data["mailbox_recovery"][0]["category"] == "not_configured"


def test_setup_status_includes_mailbox_recovery_hint(authed_client: TestClient):
    """Setup status points first-run operators at mailbox configuration."""
    response = authed_client.get("/api/v1/setup/status")
    assert response.status_code == 200
    data = response.json()
    assert data["mailbox_recovery_hint"]["category"] == "not_configured"
    assert data["mailbox_recovery_hint"]["recovery_steps"]


def test_members_page_route_is_registered():
    """The membership management page is available from the server-rendered UI."""
    assert any(getattr(route, "path", None) == "/members" for route in app.routes)


def test_reports_upload_invalid_extension(authed_client: TestClient):
    """Test that uploading a file with an unsupported extension returns 400."""
    response = authed_client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.txt", b"not a report", "text/plain")},
    )
    assert response.status_code == 400
    assert "Invalid file type" in response.json()["detail"]


def test_reports_upload_empty_file(authed_client: TestClient):
    """Test that uploading an empty file returns 400."""
    response = authed_client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.xml", b"", "application/xml")},
    )
    assert response.status_code == 400
    assert "empty" in response.json()["detail"].lower()
