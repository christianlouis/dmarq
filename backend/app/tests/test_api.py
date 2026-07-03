import asyncio
from types import SimpleNamespace

from fastapi.testclient import TestClient
from sqlalchemy.exc import IntegrityError
from starlette.requests import Request

from app.api.api_v1.endpoints import domains as domains_endpoint
from app.main import app, health as root_health, members_page, settings
from app.models.domain import Domain
from app.models.report import DMARCReport, ReportRecord
from app.services.workspaces import get_or_create_default_workspace


def test_health_check(authed_client: TestClient):
    """Test the health check endpoint returns status ok."""
    response = authed_client.get("/api/v1/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"
    assert "version" in data


def test_release_info_endpoint_exposes_safe_build_metadata(authed_client: TestClient, monkeypatch):
    """Release metadata is available for support without exposing secrets."""
    from app.api.api_v1.endpoints import (
        health as health_endpoint,
    )  # pylint: disable=import-outside-toplevel
    from app.core.config import Settings  # pylint: disable=import-outside-toplevel

    monkeypatch.setattr(
        health_endpoint,
        "get_settings",
        lambda: Settings(
            SECRET_KEY="s" * 32,
            ENVIRONMENT="production",
            DEMO_MODE=False,
            PUBLIC_BASE_URL="https://app.dmarq.org",
            DMARQ_BUILD_SHA="abcdef1234567890",
            DMARQ_BUILD_REF="main",
            DMARQ_BUILD_IMAGE="ghcr.io/christianlouis/dmarq:abcdef1",
            DMARQ_BUILD_DATE="2026-07-03T12:00:00Z",
        ),
    )

    response = authed_client.get("/api/v1/health/release")

    assert response.status_code == 200
    data = response.json()
    assert data["service"] == "dmarq"
    assert data["version"]
    assert data["label"].startswith(f"v{data['version']}")
    assert data["environment"] == "production"
    assert data["demo_mode"] is False
    assert data["public_base_url"] == "https://app.dmarq.org"
    assert data["build"]["short_sha"] == "abcdef123456"
    assert data["build"]["ref"] == "main"
    assert data["build"]["image"] == "ghcr.io/christianlouis/dmarq:abcdef1"
    assert data["build"]["image_tag"] == "abcdef1"
    assert data["rollout"]["endpoint"] == "/api/v1/health/release"
    assert data["rollout"]["environment"] == "production"
    assert data["rollout"]["image_tag_matches_short_sha"] is True
    assert data["changelog_url"].endswith("/CHANGELOG.md")
    assert len(data["changes"]) >= 8
    assert "Cloudflare rights profiles" in {item["title"] for item in data["changes"]}
    assert "CSP hardening progress" in {item["title"] for item in data["changes"]}


def test_release_info_ignores_digest_only_image_references(authed_client: TestClient, monkeypatch):
    """Digest-pinned images do not expose a misleading digest as a tag."""
    from app.api.api_v1.endpoints import (
        health as health_endpoint,
    )  # pylint: disable=import-outside-toplevel
    from app.core.config import Settings  # pylint: disable=import-outside-toplevel

    monkeypatch.setattr(
        health_endpoint,
        "get_settings",
        lambda: Settings(
            SECRET_KEY="s" * 32,
            DMARQ_BUILD_SHA="abcdef1234567890",
            DMARQ_BUILD_IMAGE=(
                "ghcr.io/christianlouis/dmarq@"
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            ),
        ),
    )

    response = authed_client.get("/api/v1/health/release")

    assert response.status_code == 200
    data = response.json()
    assert data["build"]["image_tag"] is None
    assert data["rollout"]["image_tag_matches_short_sha"] is False


def test_release_info_extracts_tag_from_digest_pinned_tag(authed_client: TestClient, monkeypatch):
    """Tag-plus-digest image references still expose the tag for rollout checks."""
    from app.api.api_v1.endpoints import (
        health as health_endpoint,
    )  # pylint: disable=import-outside-toplevel
    from app.core.config import Settings  # pylint: disable=import-outside-toplevel

    monkeypatch.setattr(
        health_endpoint,
        "get_settings",
        lambda: Settings(
            SECRET_KEY="s" * 32,
            DMARQ_BUILD_SHA="abcdef1234567890",
            DMARQ_BUILD_IMAGE=(
                "ghcr.io/christianlouis/dmarq:abcdef1@"
                "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            ),
        ),
    )

    response = authed_client.get("/api/v1/health/release")

    assert response.status_code == 200
    data = response.json()
    assert data["build"]["image_tag"] == "abcdef1"
    assert data["rollout"]["image_tag_matches_short_sha"] is True


def test_api_health_includes_release_summary(authed_client: TestClient, monkeypatch):
    """The simple API health endpoint exposes the same release metadata family."""
    from app.api.api_v1.endpoints import (
        health as health_endpoint,
    )  # pylint: disable=import-outside-toplevel
    from app.core.config import Settings  # pylint: disable=import-outside-toplevel

    monkeypatch.setattr(
        health_endpoint,
        "get_settings",
        lambda: Settings(
            SECRET_KEY="s" * 32,
            ENVIRONMENT="demo",
            DMARQ_BUILD_SHA="1234567890abcdef",
            DMARQ_BUILD_IMAGE="ghcr.io/christianlouis/dmarq:1234567",
        ),
    )

    response = authed_client.get("/api/v1/health")

    assert response.status_code == 200
    data = response.json()
    assert data["release"]["label"].startswith(f"v{data['version']}")
    assert data["release"]["environment"] == "demo"
    assert data["release"]["build"]["short_sha"] == "1234567890ab"
    assert data["release"]["build"]["image"] == "ghcr.io/christianlouis/dmarq:1234567"


def test_root_healthz_includes_release_summary(authed_client: TestClient, monkeypatch):
    """Root health probes expose the same non-secret build summary."""
    del authed_client
    monkeypatch.setattr(settings, "ENVIRONMENT", "demo")
    monkeypatch.setattr(settings, "DMARQ_BUILD_SHA", "1234567890abcdef")
    monkeypatch.setattr(settings, "DMARQ_BUILD_IMAGE", "ghcr.io/christianlouis/dmarq:1234567")

    data = asyncio.run(root_health())

    assert data["status"] == "ok"
    assert data["release"]["environment"] == "demo"
    assert data["release"]["build"]["short_sha"] == "1234567890ab"


def test_domains_empty(authed_client: TestClient):
    """Test that GET /api/v1/domains/domains returns empty list when no reports uploaded."""
    response = authed_client.get("/api/v1/domains/domains")
    assert response.status_code == 200
    data = response.json()
    assert data == []


def test_domains_returns_demo_report_domains_in_demo_mode(
    authed_client: TestClient,
    db_session,
    monkeypatch,
):
    """Demo mode keeps domain list reads on the demo ReportStore path."""
    domain = Domain(name="demo-list.example", active=True)
    db_session.add(domain)
    db_session.commit()

    def fake_hydrate(_db, store, workspace_id=None):
        del workspace_id
        store.add_report(
            {
                "domain": "demo-list.example",
                "report_id": "demo-list-001",
                "org_name": "Demo Reporter",
                "policy": {"p": "none", "sp": "", "pct": "100"},
                "records": [
                    {
                        "source_ip": "192.0.2.20",
                        "count": 3,
                        "disposition": "none",
                        "dkim_result": "pass",
                        "spf_result": "pass",
                        "header_from": "demo-list.example",
                    }
                ],
                "summary": {
                    "total_count": 3,
                    "passed_count": 3,
                    "failed_count": 0,
                    "pass_rate": 100.0,
                },
            }
        )
        return 1

    monkeypatch.setattr(
        "app.api.api_v1.endpoints.domains.get_settings",
        lambda: SimpleNamespace(DEMO_MODE=True),
    )
    monkeypatch.setattr(domains_endpoint, "hydrate_report_store_from_db", fake_hydrate)

    response = authed_client.get("/api/v1/domains/domains")

    assert response.status_code == 200
    row = next(item for item in response.json() if item["name"] == "demo-list.example")
    assert row["reports_count"] == 1
    assert row["emails_count"] == 3
    assert row["compliance_rate"] == 100.0


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


def test_read_domains_uses_database_aggregates_without_full_report_hydration(
    authed_client: TestClient, db_session, monkeypatch
):
    """Domain list reads persisted aggregates without loading every report record into memory."""
    workspace = get_or_create_default_workspace(db_session)
    domain = Domain(
        name="fast-list.example",
        workspace_id=workspace.id,
        active=True,
        dmarc_policy="reject",
    )
    db_session.add(domain)
    db_session.flush()
    report = DMARCReport(
        domain_id=domain.id,
        report_id="fast-list-001",
        org_name="Example Reporter",
        begin_date=1_700_000_000,
        end_date=1_700_086_399,
        policy="reject",
    )
    db_session.add(report)
    db_session.flush()
    db_session.add_all(
        [
            ReportRecord(
                report_id=report.id,
                source_ip="203.0.113.10",
                count=8,
                disposition="none",
                dkim="pass",
                spf="fail",
                header_from=domain.name,
            ),
            ReportRecord(
                report_id=report.id,
                source_ip="203.0.113.11",
                count=2,
                disposition="reject",
                dkim="fail",
                spf="fail",
                header_from=domain.name,
            ),
        ]
    )
    db_session.commit()

    def fail_hydrate(*_args, **_kwargs):
        raise AssertionError("read_domains should not hydrate the full ReportStore")

    monkeypatch.setattr(domains_endpoint, "hydrate_report_store_from_db", fail_hydrate)

    response = authed_client.get("/api/v1/domains/domains")

    assert response.status_code == 200
    row = next(item for item in response.json() if item["name"] == "fast-list.example")
    assert row["policy"] == "reject"
    assert row["reports_count"] == 1
    assert row["emails_count"] == 10
    assert row["compliance_rate"] == 80.0


def test_update_domain_metadata_without_reports(authed_client: TestClient):
    """Editable monitored-domain metadata can be changed from the domain list."""
    created = authed_client.post(
        "/api/v1/domains/domains",
        json={
            "name": "Example.COM.",
            "description": "Primary mail domain",
            "dkim_selectors": ["default"],
        },
    )
    assert created.status_code == 201

    response = authed_client.patch(
        "/api/v1/domains/domains/example.com",
        json={
            "description": "Updated production mail domain",
            "dkim_selectors": ["google", "default", "google"],
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["name"] == "example.com"
    assert data["description"] == "Updated production mail domain"
    assert data["dkim_selectors"] == ["google", "default"]

    list_response = authed_client.get("/api/v1/domains/domains")
    assert list_response.status_code == 200
    listed = list_response.json()[0]
    assert listed["description"] == "Updated production mail domain"
    assert listed["dkim_selectors"] == ["google", "default"]

    selectors_response = authed_client.get("/api/v1/domains/example.com/selectors")
    assert selectors_response.status_code == 200
    assert selectors_response.json()["selectors"] == ["google", "default"]


def test_update_report_only_domain_creates_monitored_domain(
    authed_client: TestClient, db_session, monkeypatch
):
    """PATCH can persist metadata for a domain that only exists in report summaries."""
    report_domain = "report-only.example"
    report = {
        "domain": report_domain,
        "report_id": "report-only-update",
        "org_name": "Example RUA",
        "begin_timestamp": 1597449600,
        "end_timestamp": 1597535999,
        "policy": "none",
        "records": [
            {
                "source_ip": "192.0.2.10",
                "count": 3,
                "disposition": "none",
                "dkim_result": "pass",
                "spf_result": "pass",
                "header_from": report_domain,
            }
        ],
    }

    def fake_hydrate(_db, store, workspace_id=None):
        del workspace_id
        store.clear()
        store.add_report(report)
        return 1

    monkeypatch.setattr(domains_endpoint, "hydrate_report_store_from_db", fake_hydrate)

    response = authed_client.patch(
        f"/api/v1/domains/domains/{report_domain}",
        json={
            "description": "Persisted from report-only summary",
            "dkim_selectors": ["google", "default", "google"],
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["name"] == report_domain
    assert data["description"] == "Persisted from report-only summary"
    assert data["reports_count"] == 1
    assert data["dkim_selectors"] == ["google", "default"]

    domain = db_session.query(Domain).filter(Domain.name == report_domain).one()
    assert domain.description == "Persisted from report-only summary"
    assert domain.dkim_selectors == "google,default"


def test_update_report_only_domain_insert_race_returns_conflict(
    authed_client: TestClient, db_session, monkeypatch
):
    """Concurrent monitor-domain creation returns a controlled conflict."""
    report_domain = "raced-report-only.example"
    report = {
        "domain": report_domain,
        "report_id": "report-only-race",
        "org_name": "Example RUA",
        "begin_timestamp": 1597449600,
        "end_timestamp": 1597535999,
        "policy": "none",
        "records": [
            {
                "source_ip": "192.0.2.10",
                "count": 1,
                "disposition": "none",
                "dkim_result": "pass",
                "spf_result": "pass",
                "header_from": report_domain,
            }
        ],
    }

    def fake_hydrate(_db, store, workspace_id=None):
        del workspace_id
        store.clear()
        store.add_report(report)
        return 1

    def fail_commit():
        raise IntegrityError("insert domain", {}, Exception("duplicate domain"))

    workspace = domains_endpoint._authorized_domain_workspace(  # pylint: disable=protected-access
        {"auth_type": "api_key"},
        db_session,
    )
    monkeypatch.setattr(
        domains_endpoint,
        "_authorized_domain_workspace",
        lambda *_args, **_kwargs: workspace,
    )
    monkeypatch.setattr(domains_endpoint, "hydrate_report_store_from_db", fake_hydrate)
    monkeypatch.setattr(db_session, "commit", fail_commit)

    response = authed_client.patch(
        f"/api/v1/domains/domains/{report_domain}",
        json={"description": "Race loser"},
    )

    assert response.status_code == 409
    assert response.json()["detail"] == "Domain is already monitored"


def test_domain_selectors_map_normalizes_legacy_duplicates(db_session):
    """Summary selector lookups return the same normalized selector shape as read APIs."""
    db_session.add(Domain(name="legacy.example", dkim_selectors=" google,default,google, "))
    db_session.commit()

    assert domains_endpoint._get_domain_selectors_map_from_db(  # pylint: disable=protected-access
        db_session,
        ["legacy.example"],
    ) == {"legacy.example": ["google", "default"]}


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


def test_members_page_redirects_when_multi_workspace_ui_disabled(monkeypatch):
    """Single-workspace installs should not expose the membership management UI."""
    monkeypatch.setattr(settings, "MULTI_WORKSPACE_UI_ENABLED", False)

    request = Request({"type": "http", "method": "GET", "path": "/members", "headers": []})
    response = asyncio.run(members_page(request))

    assert response.status_code == 303
    assert response.headers["location"] == "/settings"


def test_members_page_renders_when_multi_workspace_ui_enabled(monkeypatch):
    """Multi-workspace installs keep the membership management UI available."""
    monkeypatch.setattr(settings, "MULTI_WORKSPACE_UI_ENABLED", True)

    request = Request({"type": "http", "method": "GET", "path": "/members", "headers": []})
    response = asyncio.run(members_page(request))

    assert response.status_code == 200
    assert response.template.name == "members.html"


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
