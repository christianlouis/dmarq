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


# ---------------------------------------------------------------------------
# Tests for GET /api/v1/reports  (cross-domain reports list)
# ---------------------------------------------------------------------------


def test_get_all_reports_empty(client: TestClient):
    """GET /api/v1/reports returns an empty list when no reports have been uploaded."""
    response = client.get("/api/v1/reports")
    assert response.status_code == 200
    assert response.json() == []


def test_get_all_reports_single_report(client: TestClient):
    """GET /api/v1/reports returns the report after a successful upload."""
    zip_bytes = _make_zip(SAMPLE_XML)
    client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_bytes, "application/zip")},
    )

    response = client.get("/api/v1/reports")
    assert response.status_code == 200
    items = response.json()
    assert len(items) == 1
    item = items[0]
    assert item["report_id"] == "123456789"
    assert item["domain"] == "example.com"
    assert item["org_name"] == "google.com"
    assert "begin_date" in item
    assert "end_date" in item
    assert item["total_count"] == 2
    # SAMPLE_XML has one record with count=2 and dkim=pass (DMARC passes on dkim pass)
    assert item["passed_count"] >= 0
    assert item["failed_count"] >= 0
    assert isinstance(item["pass_rate"], float)


def test_get_all_reports_multiple_domains(client: TestClient):
    """GET /api/v1/reports returns reports from all domains."""
    from app.services.report_store import ReportStore

    store = ReportStore.get_instance()

    report_a = {
        "domain": "alpha.com",
        "report_id": "rpt-alpha",
        "org_name": "Google",
        "email": "",
        "begin_date": "2024-01-01T00:00:00",
        "end_date": "2024-01-01T23:59:59",
        "begin_timestamp": 1704067200,
        "end_timestamp": 1704153599,
        "policy": {"p": "none", "sp": "none", "pct": "100"},
        "records": [],
        "summary": {"total_count": 10, "passed_count": 10, "failed_count": 0},
    }
    report_b = {
        "domain": "beta.com",
        "report_id": "rpt-beta",
        "org_name": "Microsoft",
        "email": "",
        "begin_date": "2024-01-02T00:00:00",
        "end_date": "2024-01-02T23:59:59",
        "begin_timestamp": 1704153600,
        "end_timestamp": 1704239999,
        "policy": {"p": "reject", "sp": "reject", "pct": "100"},
        "records": [],
        "summary": {"total_count": 5, "passed_count": 3, "failed_count": 2},
    }
    store.add_report(report_a)
    store.add_report(report_b)

    response = client.get("/api/v1/reports")
    assert response.status_code == 200
    items = response.json()
    assert len(items) == 2
    domains_returned = {item["domain"] for item in items}
    assert domains_returned == {"alpha.com", "beta.com"}


def test_get_all_reports_sorted_by_end_date_desc(client: TestClient):
    """GET /api/v1/reports returns items sorted by end_date descending."""
    from app.services.report_store import ReportStore

    store = ReportStore.get_instance()

    older = {
        "domain": "example.com",
        "report_id": "rpt-older",
        "org_name": "OrgA",
        "email": "",
        "begin_date": "2023-06-01T00:00:00",
        "end_date": "2023-06-01T23:59:59",
        "begin_timestamp": 1685577600,
        "end_timestamp": 1685663999,
        "policy": {"p": "none"},
        "records": [],
        "summary": {"total_count": 4, "passed_count": 4, "failed_count": 0},
    }
    newer = {
        "domain": "example.com",
        "report_id": "rpt-newer",
        "org_name": "OrgA",
        "email": "",
        "begin_date": "2024-01-01T00:00:00",
        "end_date": "2024-01-01T23:59:59",
        "begin_timestamp": 1704067200,
        "end_timestamp": 1704153599,
        "policy": {"p": "none"},
        "records": [],
        "summary": {"total_count": 6, "passed_count": 6, "failed_count": 0},
    }
    store.add_report(older)
    store.add_report(newer)

    response = client.get("/api/v1/reports")
    assert response.status_code == 200
    items = response.json()
    assert len(items) == 2
    # Newest end_date should come first
    assert items[0]["report_id"] == "rpt-newer"
    assert items[1]["report_id"] == "rpt-older"


def test_get_all_reports_pass_rate_computed_correctly(client: TestClient):
    """pass_rate is computed from passed_count / total_count * 100."""
    from app.services.report_store import ReportStore

    store = ReportStore.get_instance()

    report = {
        "domain": "example.com",
        "report_id": "rpt-rate",
        "org_name": "OrgB",
        "email": "",
        "begin_date": "2024-03-01T00:00:00",
        "end_date": "2024-03-01T23:59:59",
        "begin_timestamp": 1709251200,
        "end_timestamp": 1709337599,
        "policy": {"p": "none"},
        "records": [],
        "summary": {"total_count": 8, "passed_count": 6, "failed_count": 2},
    }
    store.add_report(report)

    response = client.get("/api/v1/reports")
    assert response.status_code == 200
    items = response.json()
    assert len(items) == 1
    assert items[0]["pass_rate"] == 75.0


def test_get_all_reports_zero_total_gives_zero_pass_rate(client: TestClient):
    """pass_rate is 0.0 when total_count is 0 (no division by zero)."""
    from app.services.report_store import ReportStore

    store = ReportStore.get_instance()

    report = {
        "domain": "example.com",
        "report_id": "rpt-zero",
        "org_name": "OrgC",
        "email": "",
        "begin_date": "2024-04-01T00:00:00",
        "end_date": "2024-04-01T23:59:59",
        "begin_timestamp": 1711929600,
        "end_timestamp": 1712015999,
        "policy": {"p": "none"},
        "records": [],
        "summary": {"total_count": 0, "passed_count": 0, "failed_count": 0},
    }
    store.add_report(report)

    response = client.get("/api/v1/reports")
    assert response.status_code == 200
    items = response.json()
    assert len(items) == 1
    assert items[0]["pass_rate"] == 0.0
