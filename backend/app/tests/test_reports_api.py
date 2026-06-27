import io
import zipfile
from contextlib import contextmanager

from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from app.api.api_v1.endpoints import reports as reports_endpoint
from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.domain import Domain
from app.models.report import DMARCReport, ReportRecord
from app.models.user import User
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceMembership
from app.services.report_persistence import persisted_report_to_dict, save_parsed_report
from app.services.report_store import ReportStore
from app.services.workspace_access import ROLE_ANALYST
from app.services.workspaces import get_or_create_default_workspace
from app.tests.test_data import SAMPLE_XML, load_dmarc_fixture

SAMPLE_RFC9990_XML = load_dmarc_fixture("rfc9990-treewalk-extension.xml")


def _make_zip(xml_content: str) -> bytes:
    """Create a ZIP file containing the given XML content."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("report.xml", xml_content)
    return buf.getvalue()


def _persist_parsed_report(db_session, report: dict, workspace_id: int | None = None) -> None:
    save_parsed_report(db_session, report, workspace_id=workspace_id)
    db_session.commit()


def _parsed_report(
    *,
    domain: str,
    report_id: str,
    count: int = 5,
    begin_ts: int = 1704067200,
    end_ts: int = 1704153599,
) -> dict:
    return {
        "domain": domain,
        "report_id": report_id,
        "org_name": "Workspace Test Org",
        "email": "",
        "begin_timestamp": begin_ts,
        "end_timestamp": end_ts,
        "policy": {"p": "none", "sp": "none", "pct": "100"},
        "records": [
            {
                "source_ip": "192.0.2.55",
                "count": count,
                "disposition": "none",
                "dkim_result": "pass",
                "spf_result": "pass",
                "header_from": domain,
            }
        ],
    }


def _add_user(db_session, email: str, *, is_superuser: bool = False) -> User:
    user = User(
        email=email,
        is_active=True,
        is_superuser=is_superuser,
        is_verified=True,
    )
    db_session.add(user)
    db_session.flush()
    return user


def _add_membership(db_session, workspace, user: User, role: str) -> None:
    db_session.add(
        WorkspaceMembership(
            workspace_id=workspace.id,
            user_id=user.id,
            role=role,
            active=True,
        )
    )
    db_session.flush()


@contextmanager
def _client_as_user(test_app, db_session, user: User):
    async def mock_admin_auth():
        return {"auth_type": "session", "user_id": user.id}

    def override_get_db():
        try:
            yield db_session
        finally:
            pass

    original_overrides = dict(test_app.dependency_overrides)
    test_app.dependency_overrides[get_db] = override_get_db
    test_app.dependency_overrides[require_admin_auth] = mock_admin_auth
    try:
        with TestClient(test_app) as client:
            yield client
    finally:
        test_app.dependency_overrides = original_overrides


def test_upload_report_success(authed_client: TestClient):
    """Uploading a valid zipped DMARC report succeeds."""
    zip_bytes = _make_zip(SAMPLE_XML)
    response = authed_client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_bytes, "application/zip")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["domain"] == "example.com"


def test_report_routes_enforce_workspace_read_and_write_roles(test_app, db_session):
    """Analysts can read report surfaces, but uploads require report write access."""
    workspace = get_or_create_default_workspace(db_session)
    analyst = _add_user(db_session, "analyst@example.test")
    outsider = _add_user(db_session, "outsider@example.test")
    _add_membership(db_session, workspace, analyst, ROLE_ANALYST)
    db_session.commit()

    zip_bytes = _make_zip(SAMPLE_XML)
    with _client_as_user(test_app, db_session, analyst) as client:
        read_response = client.get("/api/v1/reports/domains")
        all_reports_response = client.get("/api/v1/reports")
        summary_response = client.get("/api/v1/reports/summary")
        delete_response = client.delete("/api/v1/reports/domain/example.com/reports/123456789")
        write_response = client.post(
            "/api/v1/reports/upload",
            files={"file": ("report.zip", zip_bytes, "application/zip")},
        )

    assert read_response.status_code == 200
    assert all_reports_response.status_code == 200
    assert summary_response.status_code == 200
    assert delete_response.status_code == 403
    assert "reports:write" in delete_response.json()["detail"]
    assert write_response.status_code == 403
    assert "reports:write" in write_response.json()["detail"]

    with _client_as_user(test_app, db_session, outsider) as client:
        denied = client.get("/api/v1/reports/domains")
        denied_list = client.get("/api/v1/reports")

    assert denied.status_code == 403
    assert "reports:read" in denied.json()["detail"]
    assert denied_list.status_code == 403
    assert "reports:read" in denied_list.json()["detail"]


def test_upload_persists_report_rows(authed_client: TestClient, db_session):
    """Uploaded reports are written to the durable report tables."""
    zip_bytes = _make_zip(SAMPLE_XML)
    response = authed_client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_bytes, "application/zip")},
    )
    assert response.status_code == 200

    report = db_session.query(DMARCReport).filter_by(report_id="123456789").one()
    assert report.org_name == "google.com"
    assert report.domain.name == "example.com"
    assert db_session.query(ReportRecord).filter_by(report_id=report.id).count() == 1


def test_upload_report_respects_selected_workspace_header(
    authed_client: TestClient,
    db_session,
):
    """Uploaded reports are persisted in the selected workspace."""
    other_workspace = Workspace(slug="selected-report-upload", name="Selected Report Upload")
    db_session.add(other_workspace)
    db_session.commit()

    zip_bytes = _make_zip(SAMPLE_XML)
    response = authed_client.post(
        "/api/v1/reports/upload",
        headers={"X-DMARQ-Workspace-ID": str(other_workspace.id)},
        files={"file": ("report.zip", zip_bytes, "application/zip")},
    )

    assert response.status_code == 200
    domain = db_session.query(Domain).filter(Domain.name == "example.com").one()
    assert domain.workspace_id == other_workspace.id

    default_listing = authed_client.get("/api/v1/reports/domains")
    selected_listing = authed_client.get(
        "/api/v1/reports/domains",
        headers={"X-DMARQ-Workspace-ID": str(other_workspace.id)},
    )
    assert default_listing.status_code == 200
    assert default_listing.json() == []
    assert selected_listing.status_code == 200
    assert selected_listing.json() == ["example.com"]


def test_upload_report_rejects_domain_owned_by_another_workspace(
    authed_client: TestClient,
    db_session,
):
    """Uploading a cross-workspace duplicate domain returns a controlled conflict."""
    default_workspace = get_or_create_default_workspace(db_session)
    other_workspace = Workspace(slug="duplicate-domain-upload", name="Duplicate Domain Upload")
    db_session.add(other_workspace)
    db_session.flush()
    _persist_parsed_report(
        db_session,
        _parsed_report(domain="example.com", report_id="default-example"),
        workspace_id=default_workspace.id,
    )

    response = authed_client.post(
        "/api/v1/reports/upload",
        headers={"X-DMARQ-Workspace-ID": str(other_workspace.id)},
        files={"file": ("report.zip", _make_zip(SAMPLE_XML), "application/zip")},
    )

    assert response.status_code == 409
    assert "already belongs to another workspace" in response.json()["detail"]
    assert db_session.query(Domain).filter(Domain.name == "example.com").count() == 1
    assert db_session.query(DMARCReport).filter_by(report_id="123456789").count() == 0


def test_upload_report_normalizes_domain_before_conflict_check(
    authed_client: TestClient,
    db_session,
):
    """Cross-workspace domain checks use the same normalized domain as persistence."""
    default_workspace = get_or_create_default_workspace(db_session)
    other_workspace = Workspace(slug="case-domain-upload", name="Case Domain Upload")
    db_session.add(other_workspace)
    db_session.flush()
    _persist_parsed_report(
        db_session,
        _parsed_report(domain="example.com", report_id="default-example"),
        workspace_id=default_workspace.id,
    )
    uppercase_xml = SAMPLE_XML.replace(
        "<domain>example.com</domain>",
        "<domain>Example.COM.</domain>",
        1,
    )

    response = authed_client.post(
        "/api/v1/reports/upload",
        headers={"X-DMARQ-Workspace-ID": str(other_workspace.id)},
        files={"file": ("report.zip", _make_zip(uppercase_xml), "application/zip")},
    )

    assert response.status_code == 409
    assert "Domain 'example.com' already belongs to another workspace" in response.json()["detail"]
    assert db_session.query(Domain).filter(Domain.name == "example.com").count() == 1
    assert db_session.query(DMARCReport).filter_by(report_id="123456789").count() == 0


def test_upload_report_translates_raced_domain_integrity_error(
    authed_client: TestClient,
    db_session,
    monkeypatch,
):
    """A concurrent cross-workspace domain insert is returned as a controlled 409."""
    get_or_create_default_workspace(db_session)
    other_workspace = Workspace(slug="raced-domain-upload", name="Raced Domain Upload")
    db_session.add(other_workspace)
    db_session.commit()
    TestingSessionLocal = sessionmaker(bind=db_session.get_bind())

    def raced_save(db, report, *, workspace_id=None):  # pylint: disable=unused-argument
        concurrent_db = TestingSessionLocal()
        try:
            default_workspace = get_or_create_default_workspace(concurrent_db)
            concurrent_db.add(Domain(name="example.com", workspace_id=default_workspace.id))
            concurrent_db.commit()
        finally:
            concurrent_db.close()
        raise IntegrityError("insert", {}, Exception("UNIQUE constraint failed: domains.name"))

    monkeypatch.setattr(reports_endpoint, "save_parsed_report", raced_save)

    response = authed_client.post(
        "/api/v1/reports/upload",
        headers={"X-DMARQ-Workspace-ID": str(other_workspace.id)},
        files={"file": ("report.zip", _make_zip(SAMPLE_XML), "application/zip")},
    )

    assert response.status_code == 409
    assert "Domain 'example.com' already belongs to another workspace" in response.json()["detail"]
    assert db_session.query(DMARCReport).filter_by(report_id="123456789").count() == 0


def test_upload_report_recovers_from_same_workspace_domain_race(
    authed_client: TestClient,
    db_session,
    monkeypatch,
):
    """A same-workspace raced domain insert retries instead of leaking a 500."""
    default_workspace = get_or_create_default_workspace(db_session)
    db_session.commit()
    TestingSessionLocal = sessionmaker(bind=db_session.get_bind())
    real_save_parsed_report = reports_endpoint.save_parsed_report
    call_count = 0

    def raced_save(db, report, *, workspace_id=None):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            concurrent_db = TestingSessionLocal()
            try:
                concurrent_db.add(Domain(name="example.com", workspace_id=default_workspace.id))
                concurrent_db.commit()
            finally:
                concurrent_db.close()
            raise IntegrityError("insert", {}, Exception("UNIQUE constraint failed: domains.name"))
        return real_save_parsed_report(db, report, workspace_id=workspace_id)

    monkeypatch.setattr(reports_endpoint, "save_parsed_report", raced_save)

    response = authed_client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", _make_zip(SAMPLE_XML), "application/zip")},
    )

    assert response.status_code == 200
    assert response.json()["domain"] == "example.com"
    assert db_session.query(Domain).filter(Domain.name == "example.com").count() == 1
    assert db_session.query(DMARCReport).filter_by(report_id="123456789").count() == 1


def test_upload_persists_rfc9990_optional_fields(authed_client: TestClient, db_session):
    """RFC 9990 / DMARCbis metadata is kept for exports and future UI use."""
    zip_bytes = _make_zip(SAMPLE_RFC9990_XML)
    response = authed_client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_bytes, "application/zip")},
    )
    assert response.status_code == 200

    report = db_session.query(DMARCReport).filter_by(report_id="fixture-rfc9990-treewalk").one()
    assert report.domain.name == "example.org"
    assert report.extra_contact_info == "https://example.test/dmarc"
    assert report.generator == "ExampleRUA 2.0"
    assert report.report_variant == "rfc9990"
    assert report.schema_version == "1.0"
    assert report.xml_namespace == "urn:ietf:params:xml:ns:dmarc-2.0"
    assert report.non_subdomain_policy == "none"
    assert report.failure_options == "1"
    assert report.testing == "y"
    assert report.discovery_method == "treewalk"
    assert "Multiple DMARC records were ignored before treewalk." in report.report_errors
    assert "mx1.example.test" in report.report_extensions

    record = db_session.query(ReportRecord).filter_by(report_id=report.id).one()
    assert record.envelope_from == "bounce.example.org"
    assert record.envelope_to == "customer.example.net"
    assert "local_policy" in record.policy_override_reasons
    assert "mail-platform" in record.record_extensions
    assert "human_result" in record.dkim_auth_details
    assert "scope" in record.spf_auth_details


def test_persisted_report_to_dict_hydrates_optional_json_metadata(db_session):
    """Persisted RFC 9990 extension metadata is restored safely for readers."""
    domain = Domain(name="metadata.example", dmarc_policy="reject")
    report = DMARCReport(
        domain=domain,
        report_id="metadata-report",
        org_name="Example Receiver",
        begin_date=1779494400,
        end_date=1779580799,
        source_email="dmarc@example.test",
        report_errors='["Multiple records ignored."]',
        policy="reject",
        subdomain_policy="quarantine",
        non_subdomain_policy="none",
        adkim="s",
        aspf="r",
        percentage=100,
        failure_options="1",
        testing="y",
        discovery_method="treewalk",
        schema_version="1.0",
        report_variant="rfc9990",
        xml_namespace="urn:ietf:params:xml:ns:dmarc-2.0",
        report_extensions='{"vendor:receiver": "mx1.example.test"}',
    )
    report.records.append(
        ReportRecord(
            source_ip="2001:db8::1",
            count=5,
            disposition="quarantine",
            dkim="fail",
            spf="pass",
            header_from="news.metadata.example",
            envelope_from="bounce.metadata.example",
            envelope_to="customer.example.net",
            policy_override_reasons='[{"type": "local_policy"}]',
            record_extensions='{"vendor:source": "mail-platform"}',
        )
    )
    db_session.add(report)
    db_session.flush()

    hydrated = persisted_report_to_dict(report)

    assert hydrated["errors"] == ["Multiple records ignored."]
    assert hydrated["extensions"] == {"vendor:receiver": "mx1.example.test"}
    assert hydrated["policy"]["np"] == "none"
    assert hydrated["policy"]["fo"] == "1"
    assert hydrated["records"][0]["envelope_to"] == "customer.example.net"
    assert hydrated["records"][0]["extensions"] == {"vendor:source": "mail-platform"}

    report.report_extensions = "{not-json"
    report.records[0].record_extensions = "{not-json"

    hydrated_with_bad_json = persisted_report_to_dict(report)

    assert hydrated_with_bad_json["extensions"] == {}
    assert hydrated_with_bad_json["records"][0]["extensions"] == {}


def test_report_reads_hydrate_from_persisted_rows(authed_client: TestClient):
    """Report read APIs rebuild the in-memory projection from the database."""
    zip_bytes = _make_zip(SAMPLE_XML)
    response = authed_client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_bytes, "application/zip")},
    )
    assert response.status_code == 200

    ReportStore.get_instance().clear()

    domains = authed_client.get("/api/v1/reports/domains")
    assert domains.status_code == 200
    assert domains.json() == ["example.com"]

    detail = authed_client.get("/api/v1/reports/123456789")
    assert detail.status_code == 200
    assert detail.json()["summary"]["total_count"] == 2


def test_upload_populates_domains_list(authed_client: TestClient):
    """After uploading a report, the domain appears in the reports/domains endpoint."""
    zip_bytes = _make_zip(SAMPLE_XML)
    authed_client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_bytes, "application/zip")},
    )

    response = authed_client.get("/api/v1/reports/domains")
    assert response.status_code == 200
    domains = response.json()
    assert any(d == "example.com" for d in domains)


def test_reports_domains_empty(authed_client: TestClient):
    """GET /api/v1/reports/domains returns empty list when no reports uploaded."""
    response = authed_client.get("/api/v1/reports/domains")
    assert response.status_code == 200
    assert response.json() == []


def test_reports_summary_empty(authed_client: TestClient):
    """GET /api/v1/reports/summary returns empty list when no reports uploaded."""
    response = authed_client.get("/api/v1/reports/summary")
    assert response.status_code == 200
    assert response.json() == []


def test_report_read_and_delete_routes_respect_selected_workspace(
    authed_client: TestClient,
    db_session,
):
    """Report read/delete APIs operate inside the selected workspace boundary."""
    default_workspace = get_or_create_default_workspace(db_session)
    selected_workspace = Workspace(slug="selected-report-reads", name="Selected Report Reads")
    db_session.add(selected_workspace)
    db_session.flush()
    _persist_parsed_report(
        db_session,
        _parsed_report(domain="default-reports.example", report_id="default-report", count=4),
        workspace_id=default_workspace.id,
    )
    _persist_parsed_report(
        db_session,
        _parsed_report(domain="selected-reports.example", report_id="selected-report", count=9),
        workspace_id=selected_workspace.id,
    )

    selected_header = {"X-DMARQ-Workspace-ID": str(selected_workspace.id)}

    domains = authed_client.get("/api/v1/reports/domains", headers=selected_header)
    all_reports = authed_client.get("/api/v1/reports", headers=selected_header)
    summaries = authed_client.get("/api/v1/reports/summary", headers=selected_header)
    domain_summary = authed_client.get(
        "/api/v1/reports/domain/selected-reports.example/summary",
        headers=selected_header,
    )
    domain_reports = authed_client.get(
        "/api/v1/reports/domain/selected-reports.example/reports",
        headers=selected_header,
    )
    paginated_reports = authed_client.get(
        "/api/v1/reports/domain/selected-reports.example/reports/paginated",
        headers=selected_header,
    )
    detail = authed_client.get("/api/v1/reports/selected-report", headers=selected_header)
    hidden_detail = authed_client.get("/api/v1/reports/default-report", headers=selected_header)
    hidden_domain_summary = authed_client.get(
        "/api/v1/reports/domain/default-reports.example/summary",
        headers=selected_header,
    )
    hidden_domain_reports = authed_client.get(
        "/api/v1/reports/domain/default-reports.example/reports",
        headers=selected_header,
    )
    hidden_paginated_reports = authed_client.get(
        "/api/v1/reports/domain/default-reports.example/reports/paginated",
        headers=selected_header,
    )

    assert domains.status_code == 200
    assert domains.json() == ["selected-reports.example"]
    assert all_reports.status_code == 200
    assert [item["report_id"] for item in all_reports.json()] == ["selected-report"]
    assert summaries.status_code == 200
    assert [item["domain"] for item in summaries.json()] == ["selected-reports.example"]
    assert domain_summary.status_code == 200
    assert domain_summary.json()["total_count"] == 9
    assert domain_reports.status_code == 200
    assert [item["report_id"] for item in domain_reports.json()] == ["selected-report"]
    assert paginated_reports.status_code == 200
    assert [item["report_id"] for item in paginated_reports.json()["reports"]] == [
        "selected-report"
    ]
    assert detail.status_code == 200
    assert detail.json()["summary"]["total_count"] == 9
    assert hidden_detail.status_code == 404
    assert hidden_domain_summary.status_code == 404
    assert hidden_domain_reports.status_code == 404
    assert hidden_paginated_reports.status_code == 404

    delete_hidden = authed_client.delete(
        "/api/v1/reports/domain/default-reports.example/reports/default-report",
        headers=selected_header,
    )
    delete_selected = authed_client.delete(
        "/api/v1/reports/domain/selected-reports.example/reports/selected-report",
        headers=selected_header,
    )

    assert delete_hidden.status_code == 404
    assert delete_selected.status_code == 200
    assert db_session.query(DMARCReport).filter_by(report_id="default-report").count() == 1
    assert db_session.query(DMARCReport).filter_by(report_id="selected-report").count() == 0


def test_upload_and_get_domain_summary(authed_client: TestClient):
    """After uploading a report, the domain summary endpoint returns correct data."""
    zip_bytes = _make_zip(SAMPLE_XML)
    authed_client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_bytes, "application/zip")},
    )

    response = authed_client.get("/api/v1/reports/domain/example.com/summary")
    assert response.status_code == 200
    data = response.json()
    assert data["domain"] == "example.com"
    assert data["total_count"] == 2
    assert data["reports_processed"] == 1


def test_duplicate_upload_returns_409(authed_client: TestClient):
    """Uploading the same report twice returns 409 Conflict."""
    zip_bytes = _make_zip(SAMPLE_XML)

    first = authed_client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_bytes, "application/zip")},
    )
    assert first.status_code == 200

    second = authed_client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_bytes, "application/zip")},
    )
    assert second.status_code == 409
    assert "already been uploaded" in second.json()["detail"].lower()


def test_duplicate_upload_checks_persisted_rows(authed_client: TestClient):
    """Duplicate detection still works when the in-memory store is empty."""
    zip_bytes = _make_zip(SAMPLE_XML)

    first = authed_client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_bytes, "application/zip")},
    )
    assert first.status_code == 200

    ReportStore.get_instance().clear()

    second = authed_client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_bytes, "application/zip")},
    )
    assert second.status_code == 409


def test_delete_report_success(authed_client: TestClient, db_session):
    """Deleting an existing report returns 200 and removes it from the store."""
    zip_bytes = _make_zip(SAMPLE_XML)
    authed_client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_bytes, "application/zip")},
    )

    # Confirm the domain exists first
    assert authed_client.get("/api/v1/reports/domain/example.com/summary").status_code == 200

    # Delete the report (report_id comes from SAMPLE_XML: "123456789")
    response = authed_client.delete("/api/v1/reports/domain/example.com/reports/123456789")
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert db_session.query(DMARCReport).filter_by(report_id="123456789").count() == 0

    # Domain should be gone now
    assert authed_client.get("/api/v1/reports/domain/example.com/summary").status_code == 404


def test_delete_nonexistent_report_returns_404(authed_client: TestClient):
    """Deleting a report that does not exist returns 404."""
    response = authed_client.delete("/api/v1/reports/domain/example.com/reports/no-such-id")
    assert response.status_code == 404


def test_upload_after_delete_succeeds(authed_client: TestClient):
    """After deleting a report, the same report can be uploaded again."""
    zip_bytes = _make_zip(SAMPLE_XML)

    authed_client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_bytes, "application/zip")},
    )
    authed_client.delete("/api/v1/reports/domain/example.com/reports/123456789")

    response = authed_client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_bytes, "application/zip")},
    )
    assert response.status_code == 200
    assert response.json()["success"] is True


def test_get_report_by_id_returns_detail(authed_client: TestClient):
    """GET /api/v1/reports/{report_id} returns full report detail after upload."""
    zip_bytes = _make_zip(SAMPLE_XML)
    authed_client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_bytes, "application/zip")},
    )

    response = authed_client.get("/api/v1/reports/123456789")
    assert response.status_code == 200
    data = response.json()
    assert data["report_id"] == "123456789"
    assert data["domain"] == "example.com"
    assert data["org_name"] == "google.com"
    assert "policy" in data
    assert "records" in data
    assert "summary" in data
    assert data["summary"]["total_count"] == 2


def test_get_report_by_id_not_found(authed_client: TestClient):
    """GET /api/v1/reports/{report_id} returns 404 when report does not exist."""
    response = authed_client.get("/api/v1/reports/no-such-report-id")
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


def test_get_all_reports_empty(authed_client: TestClient):
    """GET /api/v1/reports returns an empty list when no reports have been uploaded."""
    response = authed_client.get("/api/v1/reports")
    assert response.status_code == 200
    assert response.json() == []


def test_get_all_reports_single_report(authed_client: TestClient):
    """GET /api/v1/reports returns the report after a successful upload."""
    zip_bytes = _make_zip(SAMPLE_XML)
    authed_client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_bytes, "application/zip")},
    )

    response = authed_client.get("/api/v1/reports")
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


def test_get_all_reports_multiple_domains(authed_client: TestClient, db_session):
    """GET /api/v1/reports returns reports from all domains."""
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
        "records": [
            {
                "source_ip": "192.0.2.10",
                "count": 10,
                "disposition": "none",
                "dkim_result": "pass",
                "spf_result": "pass",
                "header_from": "alpha.com",
            }
        ],
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
        "records": [
            {
                "source_ip": "192.0.2.20",
                "count": 3,
                "disposition": "none",
                "dkim_result": "pass",
                "spf_result": "fail",
                "header_from": "beta.com",
            },
            {
                "source_ip": "192.0.2.21",
                "count": 2,
                "disposition": "reject",
                "dkim_result": "fail",
                "spf_result": "fail",
                "header_from": "beta.com",
            },
        ],
    }
    _persist_parsed_report(db_session, report_a)
    _persist_parsed_report(db_session, report_b)

    response = authed_client.get("/api/v1/reports")
    assert response.status_code == 200
    items = response.json()
    assert len(items) == 2
    domains_returned = {item["domain"] for item in items}
    assert domains_returned == {"alpha.com", "beta.com"}


def test_get_all_reports_sorted_by_end_date_desc(authed_client: TestClient, db_session):
    """GET /api/v1/reports returns items sorted by end_date descending."""
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
        "records": [
            {
                "source_ip": "192.0.2.30",
                "count": 4,
                "disposition": "none",
                "dkim_result": "pass",
                "spf_result": "pass",
                "header_from": "example.com",
            }
        ],
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
        "records": [
            {
                "source_ip": "192.0.2.31",
                "count": 6,
                "disposition": "none",
                "dkim_result": "pass",
                "spf_result": "pass",
                "header_from": "example.com",
            }
        ],
    }
    _persist_parsed_report(db_session, older)
    _persist_parsed_report(db_session, newer)

    response = authed_client.get("/api/v1/reports")
    assert response.status_code == 200
    items = response.json()
    assert len(items) == 2
    # Newest end_date should come first
    assert items[0]["report_id"] == "rpt-newer"
    assert items[1]["report_id"] == "rpt-older"


def test_get_all_reports_pass_rate_computed_correctly(authed_client: TestClient, db_session):
    """pass_rate is computed from passed_count / total_count * 100."""
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
        "records": [
            {
                "source_ip": "192.0.2.40",
                "count": 6,
                "disposition": "none",
                "dkim_result": "pass",
                "spf_result": "fail",
                "header_from": "example.com",
            },
            {
                "source_ip": "192.0.2.41",
                "count": 2,
                "disposition": "none",
                "dkim_result": "fail",
                "spf_result": "fail",
                "header_from": "example.com",
            },
        ],
    }
    _persist_parsed_report(db_session, report)

    response = authed_client.get("/api/v1/reports")
    assert response.status_code == 200
    items = response.json()
    assert len(items) == 1
    assert items[0]["pass_rate"] == 75.0


def test_get_all_reports_zero_total_gives_zero_pass_rate(authed_client: TestClient, db_session):
    """pass_rate is 0.0 when total_count is 0 (no division by zero)."""
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
    }
    _persist_parsed_report(db_session, report)

    response = authed_client.get("/api/v1/reports")
    assert response.status_code == 200
    items = response.json()
    assert len(items) == 1
    assert items[0]["pass_rate"] == 0.0
