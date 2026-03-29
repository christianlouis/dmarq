import io
import zipfile

from fastapi.testclient import TestClient

from app.tests.test_data import SAMPLE_XML


def _make_zip(xml_content: str) -> bytes:
    """Create a ZIP file containing the given XML content."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("report.xml", xml_content)
    return buf.getvalue()


def test_upload_report_success(client: TestClient):
    """Uploading a valid zipped DMARC report succeeds."""
    zip_bytes = _make_zip(SAMPLE_XML)
    response = client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_bytes, "application/zip")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["domain"] == "example.com"


def test_upload_populates_domains_list(client: TestClient):
    """After uploading a report, the domain appears in the reports/domains endpoint."""
    zip_bytes = _make_zip(SAMPLE_XML)
    client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_bytes, "application/zip")},
    )

    response = client.get("/api/v1/reports/domains")
    assert response.status_code == 200
    domains = response.json()
    assert any(d == "example.com" for d in domains)


def test_reports_domains_empty(client: TestClient):
    """GET /api/v1/reports/domains returns empty list when no reports uploaded."""
    response = client.get("/api/v1/reports/domains")
    assert response.status_code == 200
    assert response.json() == []


def test_reports_summary_empty(client: TestClient):
    """GET /api/v1/reports/summary returns empty list when no reports uploaded."""
    response = client.get("/api/v1/reports/summary")
    assert response.status_code == 200
    assert response.json() == []


def test_upload_and_get_domain_summary(client: TestClient):
    """After uploading a report, the domain summary endpoint returns correct data."""
    zip_bytes = _make_zip(SAMPLE_XML)
    client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_bytes, "application/zip")},
    )

    response = client.get("/api/v1/reports/domain/example.com/summary")
    assert response.status_code == 200
    data = response.json()
    assert data["domain"] == "example.com"
    assert data["total_count"] == 2
    assert data["reports_processed"] == 1


def test_duplicate_upload_returns_409(client: TestClient):
    """Uploading the same report twice returns 409 Conflict."""
    zip_bytes = _make_zip(SAMPLE_XML)

    first = client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_bytes, "application/zip")},
    )
    assert first.status_code == 200

    second = client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_bytes, "application/zip")},
    )
    assert second.status_code == 409
    assert "already been uploaded" in second.json()["detail"].lower()


def test_delete_report_success(client: TestClient):
    """Deleting an existing report returns 200 and removes it from the store."""
    zip_bytes = _make_zip(SAMPLE_XML)
    client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_bytes, "application/zip")},
    )

    # Confirm the domain exists first
    assert client.get("/api/v1/reports/domain/example.com/summary").status_code == 200

    # Delete the report (report_id comes from SAMPLE_XML: "123456789")
    response = client.delete("/api/v1/reports/domain/example.com/reports/123456789")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True

    # Domain should be gone now
    assert client.get("/api/v1/reports/domain/example.com/summary").status_code == 404


def test_delete_nonexistent_report_returns_404(client: TestClient):
    """Deleting a report that does not exist returns 404."""
    response = client.delete("/api/v1/reports/domain/example.com/reports/no-such-id")
    assert response.status_code == 404


def test_upload_after_delete_succeeds(client: TestClient):
    """After deleting a report, the same report can be uploaded again."""
    zip_bytes = _make_zip(SAMPLE_XML)

    client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_bytes, "application/zip")},
    )
    client.delete("/api/v1/reports/domain/example.com/reports/123456789")

    response = client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_bytes, "application/zip")},
    )
    assert response.status_code == 200
    assert response.json()["success"] is True


def test_get_report_by_id_returns_detail(client: TestClient):
    """GET /api/v1/reports/{report_id} returns full report detail after upload."""
    zip_bytes = _make_zip(SAMPLE_XML)
    client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_bytes, "application/zip")},
    )

    response = client.get("/api/v1/reports/123456789")
    assert response.status_code == 200
    data = response.json()
    assert data["report_id"] == "123456789"
    assert data["domain"] == "example.com"
    assert data["org_name"] == "google.com"
    assert "policy" in data
    assert "records" in data
    assert "summary" in data
    assert data["summary"]["total_count"] == 2


def test_get_report_by_id_not_found(client: TestClient):
    """GET /api/v1/reports/{report_id} returns 404 when report does not exist."""
    response = client.get("/api/v1/reports/no-such-report-id")
    assert response.status_code == 404


def test_report_detail_html_page():
    """GET /reports/{report_id} returns 200 HTML page.

    The /reports/{report_id} route is registered on the module-level ``app``
    instance in main.py, not on the ``create_app()`` instance used by the
    ``client`` fixture, so we must import the module-level app here.
    """
    from app.main import app as main_app  # noqa: PLC0415

    with TestClient(main_app) as c:
        response = c.get("/reports/123456789")
    assert response.status_code == 200
    assert "text/html" in response.headers["content-type"]
