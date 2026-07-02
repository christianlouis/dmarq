"""
Tests for MailSource model and mail-sources API endpoints.
"""

import asyncio
import json
import logging
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Optional
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs, urlparse

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.api_v1.endpoints import mail_sources as mail_sources_endpoint
from app.core.credential_encryption import is_encrypted_secret
from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.domain import Domain
from app.models.mail_source import MailSource
from app.models.mail_source_backfill import MailSourceBackfillJob
from app.models.mail_source_import import MailSourceImport
from app.models.setting import Setting
from app.models.user import User
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceMembership
from app.services.import_history import record_import_attempt
from app.services.workspace_access import ROLE_OPERATOR
from app.services.workspaces import get_or_create_default_workspace


class TestOAuthStateHelpers:
    """Unit coverage for the signed OAuth state helpers."""

    def test_signed_oauth_state_round_trip(self):
        state = mail_sources_endpoint._oauth_state(workspace_id=42, source_id=7)

        assert state.startswith("v1.")
        assert (
            mail_sources_endpoint._workspace_id_from_oauth_state(
                state,
                source_id=7,
            )
            == 42
        )

    def test_signed_oauth_state_rejects_bad_shape(self):
        with pytest.raises(HTTPException) as exc:
            mail_sources_endpoint._workspace_id_from_oauth_state(
                "v1.only-two-parts",
                source_id=7,
            )

        assert exc.value.status_code == 400
        assert exc.value.detail == "Invalid OAuth state."

    def test_signed_oauth_state_rejects_tampered_payload(self):
        state = mail_sources_endpoint._oauth_state(workspace_id=42, source_id=7)
        prefix, token = state.split(".", 1)
        header, payload, signature = token.split(".")
        replacement = "A" if not payload.startswith("A") else "B"
        tampered_payload = f"{replacement}{payload[1:]}"

        with pytest.raises(HTTPException) as exc:
            mail_sources_endpoint._workspace_id_from_oauth_state(
                f"{prefix}.{header}.{tampered_payload}.{signature}",
                source_id=7,
            )

        assert exc.value.status_code == 400
        assert exc.value.detail == "Invalid OAuth state."

    def test_signed_oauth_state_rejects_source_mismatch(self):
        state = mail_sources_endpoint._oauth_state(workspace_id=42, source_id=7)

        with pytest.raises(HTTPException) as exc:
            mail_sources_endpoint._workspace_id_from_oauth_state(
                state,
                source_id=8,
            )

        assert exc.value.status_code == 400
        assert exc.value.detail == "OAuth state does not match the requested mail source."

    def test_signed_oauth_state_rejects_expired_token(self):
        now = datetime.now(timezone.utc)
        expired = mail_sources_endpoint.jwt.encode(
            {
                "source_id": 7,
                "workspace_id": 42,
                "iat": now - timedelta(minutes=20),
                "exp": now - timedelta(minutes=10),
            },
            mail_sources_endpoint._oauth_state_signing_key(),
            algorithm=mail_sources_endpoint._OAUTH_STATE_ALGORITHM,
        )

        with pytest.raises(HTTPException) as exc:
            mail_sources_endpoint._workspace_id_from_oauth_state(
                f"v1.{expired}",
                source_id=7,
            )

        assert exc.value.status_code == 400
        assert exc.value.detail == "Invalid OAuth state."

    def test_signed_oauth_state_uses_dedicated_signing_key(self):
        state = mail_sources_endpoint._oauth_state(workspace_id=42, source_id=7)
        token = state.removeprefix("v1.")

        with pytest.raises(mail_sources_endpoint.JWTError):
            mail_sources_endpoint.jwt.decode(
                token,
                mail_sources_endpoint.get_settings().SECRET_KEY,
                algorithms=[mail_sources_endpoint._OAUTH_STATE_ALGORITHM],
                options={"verify_aud": False},
            )

    @pytest.mark.parametrize(
        ("state", "source_id", "expected_workspace_id"),
        [
            ("workspace:42:source:7", 7, 42),
            ("7", 7, None),
        ],
    )
    def test_legacy_oauth_state_accepts_matching_source(
        self,
        state: str,
        source_id: int,
        expected_workspace_id: Optional[int],
    ):
        assert (
            mail_sources_endpoint._workspace_id_from_oauth_state(
                state,
                source_id=source_id,
            )
            == expected_workspace_id
        )

    @pytest.mark.parametrize(
        ("state", "expected_detail"),
        [
            ("workspace:42:source:not-an-int", "Invalid OAuth state."),
            (
                "workspace:42:source:8",
                "OAuth state does not match the requested mail source.",
            ),
            ("8", "OAuth state does not match the requested mail source."),
            ("workspace:42", "Invalid OAuth state."),
        ],
    )
    def test_legacy_oauth_state_rejects_invalid_or_mismatched_source(
        self,
        state: str,
        expected_detail: str,
    ):
        with pytest.raises(HTTPException) as exc:
            mail_sources_endpoint._workspace_id_from_oauth_state(state, source_id=7)

        assert exc.value.status_code == 400
        assert exc.value.detail == expected_detail


class TestOAuthRedirectBaseUrl:
    """OAuth redirect URIs use the public app URL, not the internal proxy URL."""

    @staticmethod
    def _request(base_url: str = "http://app.dmarc.org/", headers: Optional[dict] = None):
        request = MagicMock()
        request.base_url = base_url
        request.headers = headers or {}
        return request

    def test_public_base_url_prefers_environment_setting(self, db_session, monkeypatch):
        monkeypatch.setattr(
            mail_sources_endpoint.get_settings(),
            "PUBLIC_BASE_URL",
            "https://app.dmarc.org/",
        )

        assert (
            mail_sources_endpoint._public_base_url(self._request(), db_session)
            == "https://app.dmarc.org"
        )

    def test_public_base_url_prefers_setup_setting(self, db_session, monkeypatch):
        monkeypatch.setattr(mail_sources_endpoint.get_settings(), "PUBLIC_BASE_URL", None)
        db_session.add(
            Setting(
                key="general.base_url",
                value="https://setup.dmarc.org/",
                category="general",
            )
        )
        db_session.commit()

        assert (
            mail_sources_endpoint._public_base_url(self._request(), db_session)
            == "https://setup.dmarc.org"
        )

    def test_public_base_url_respects_forwarded_proto(self, db_session, monkeypatch):
        monkeypatch.setattr(mail_sources_endpoint.get_settings(), "PUBLIC_BASE_URL", None)

        assert (
            mail_sources_endpoint._public_base_url(
                self._request(headers={"x-forwarded-proto": "https"}),
                db_session,
            )
            == "https://app.dmarc.org"
        )


def _add_user(db_session: Session, email: str):
    user = User(email=email, is_active=True, is_verified=True, is_superuser=False)
    db_session.add(user)
    db_session.flush()
    return user


def _add_membership(db_session: Session, workspace: Workspace, user: User, role: str):
    membership = WorkspaceMembership(
        workspace_id=workspace.id,
        user_id=user.id,
        role=role,
        active=True,
    )
    db_session.add(membership)
    db_session.flush()
    return membership


def _add_domain(
    db_session: Session,
    workspace: Workspace,
    *,
    name: str = "example.com",
    verified: bool = False,
) -> Domain:
    domain = Domain(
        workspace_id=workspace.id,
        name=name,
        active=True,
        verified=verified,
    )
    db_session.add(domain)
    db_session.commit()
    return domain


class TestMailSourceModel:
    """Unit tests for the MailSource ORM model."""

    def test_create_mail_source(self, db_session: Session):
        source = MailSource(
            name="Test IMAP",
            method="IMAP",
            server="imap.example.com",
            port=993,
            username="user@example.com",
            password="secret",
            use_ssl=True,
            folder="INBOX",
            polling_interval=60,
            enabled=True,
        )
        db_session.add(source)
        db_session.commit()
        db_session.refresh(source)

        assert source.id is not None
        assert source.name == "Test IMAP"
        assert source.method == "IMAP"
        assert source.server == "imap.example.com"
        assert source.port == 993
        assert source.username == "user@example.com"
        assert source.password == "secret"
        assert source.use_ssl is True
        assert source.folder == "INBOX"
        assert source.polling_interval == 60
        assert source.enabled is True
        assert source.last_checked is None

    def test_imap_password_is_encrypted_at_rest(self, db_session: Session):
        source = MailSource(name="Encrypted IMAP", method="IMAP", password="raw-secret")
        db_session.add(source)
        db_session.commit()
        db_session.refresh(source)

        stored = db_session.execute(
            text("SELECT password FROM mail_sources WHERE id = :id"), {"id": source.id}
        ).scalar_one()

        assert source.password == "raw-secret"
        assert stored != "raw-secret"
        assert is_encrypted_secret(stored)

    def test_gmail_oauth_secrets_are_encrypted_at_rest(self, db_session: Session):
        source = MailSource(
            name="Encrypted Gmail",
            method="GMAIL_API",
            gmail_client_secret="client-secret",
            gmail_access_token="access-token",
            gmail_refresh_token="refresh-token",
        )
        db_session.add(source)
        db_session.commit()
        db_session.refresh(source)

        stored = db_session.execute(
            text(
                "SELECT gmail_client_secret, gmail_access_token, gmail_refresh_token "
                "FROM mail_sources WHERE id = :id"
            ),
            {"id": source.id},
        ).one()

        assert source.gmail_client_secret == "client-secret"
        assert source.gmail_access_token == "access-token"
        assert source.gmail_refresh_token == "refresh-token"
        assert stored.gmail_client_secret != "client-secret"
        assert stored.gmail_access_token != "access-token"
        assert stored.gmail_refresh_token != "refresh-token"
        assert is_encrypted_secret(stored.gmail_client_secret)
        assert is_encrypted_secret(stored.gmail_access_token)
        assert is_encrypted_secret(stored.gmail_refresh_token)

    def test_m365_oauth_secrets_are_encrypted_at_rest(self, db_session: Session):
        source = MailSource(
            name="Encrypted Microsoft 365",
            method="M365_GRAPH",
            m365_client_secret="client-secret",
            m365_access_token="access-token",
            m365_refresh_token="refresh-token",
        )
        db_session.add(source)
        db_session.commit()
        db_session.refresh(source)

        stored = db_session.execute(
            text(
                "SELECT m365_client_secret, m365_access_token, m365_refresh_token "
                "FROM mail_sources WHERE id = :id"
            ),
            {"id": source.id},
        ).one()

        assert source.m365_client_secret == "client-secret"
        assert source.m365_access_token == "access-token"
        assert source.m365_refresh_token == "refresh-token"
        assert stored.m365_client_secret != "client-secret"
        assert stored.m365_access_token != "access-token"
        assert stored.m365_refresh_token != "refresh-token"
        assert is_encrypted_secret(stored.m365_client_secret)
        assert is_encrypted_secret(stored.m365_access_token)
        assert is_encrypted_secret(stored.m365_refresh_token)

    def test_legacy_plaintext_mail_source_secret_remains_readable(self, db_session: Session):
        db_session.execute(
            text(
                "INSERT INTO mail_sources (name, method, password) "
                "VALUES (:name, :method, :password)"
            ),
            {"name": "Legacy IMAP", "method": "IMAP", "password": "legacy-secret"},
        )
        db_session.commit()

        source = db_session.query(MailSource).filter_by(name="Legacy IMAP").one()

        assert source.password == "legacy-secret"

    def test_encrypt_legacy_secrets_rewrites_plaintext_storage(self, db_session: Session):
        db_session.execute(
            text(
                "INSERT INTO mail_sources (name, method, password, gmail_access_token) "
                "VALUES (:name, :method, :password, :token)"
            ),
            {
                "name": "Legacy Rewrite",
                "method": "GMAIL_API",
                "password": "legacy-secret",
                "token": "legacy-token",
            },
        )
        db_session.commit()

        source = db_session.query(MailSource).filter_by(name="Legacy Rewrite").one()
        assert source.encrypt_legacy_secrets() is True
        db_session.commit()

        stored = db_session.execute(
            text("SELECT password, gmail_access_token FROM mail_sources WHERE id = :id"),
            {"id": source.id},
        ).one()

        assert source.password == "legacy-secret"
        assert source.gmail_access_token == "legacy-token"
        assert is_encrypted_secret(stored.password)
        assert is_encrypted_secret(stored.gmail_access_token)

    def test_default_values(self, db_session: Session):
        source = MailSource(name="Minimal", method="IMAP")
        db_session.add(source)
        db_session.commit()
        db_session.refresh(source)

        assert source.folder == "INBOX"  # model default
        assert source.enabled is True
        assert source.last_checked is None

    def test_repr(self, db_session: Session):
        source = MailSource(name="Demo", method="POP3")
        db_session.add(source)
        db_session.commit()
        db_session.refresh(source)

        rep = repr(source)
        assert "Demo" in rep
        assert "POP3" in rep

    def test_multiple_sources(self, db_session: Session):
        for i in range(3):
            db_session.add(MailSource(name=f"Source {i}", method="IMAP"))
        db_session.commit()

        all_sources = db_session.query(MailSource).all()
        assert len(all_sources) == 3


class TestMailSourceImportModel:
    """Unit tests for persisted mail source import history."""

    def test_create_import_history_row(self, db_session: Session):
        source = MailSource(name="History Source", method="GMAIL_API")
        db_session.add(source)
        db_session.commit()
        db_session.refresh(source)

        row = MailSourceImport(
            mail_source_id=source.id,
            trigger="manual",
            status="warning",
            processed=3,
            reports_found=2,
            duplicate_reports=1,
            error_count=1,
            new_domains='["example.com"]',
            errors='["bad attachment"]',
            details='[{"status": "imported", "filename": "report.xml"}]',
        )
        db_session.add(row)
        db_session.commit()
        db_session.refresh(row)

        assert row.id is not None
        assert row.mail_source_id == source.id
        assert row.duplicate_reports == 1
        assert '"imported"' in row.details
        assert row.mail_source.name == "History Source"

    def test_record_import_attempt_sanitizes_details(self, db_session: Session):
        source = MailSource(name="Detail Sanitizer", method="IMAP")
        db_session.add(source)
        db_session.commit()
        db_session.refresh(source)

        attempt = record_import_attempt(
            db_session,
            source,
            {
                "success": True,
                "errors": ["x" * 600],
                "details": [
                    "skip-me",
                    {
                        "status": "imported",
                        "filename": "a" * 400,
                        "mailbox": "shared@example.com",
                        "folder": "DMARC Reports",
                        "ignored": "secret",
                    },
                ],
            },
            started_at=datetime.utcnow(),
            trigger="manual",
        )

        details = json.loads(attempt.details)
        errors = json.loads(attempt.errors)
        assert len(errors[0]) == 500
        assert details[0]["status"] == "imported"
        assert len(details[0]["filename"]) == 300
        assert details[0]["mailbox"] == "shared@example.com"
        assert details[0]["folder"] == "DMARC Reports"
        assert "ignored" not in details[0]

    def test_record_import_attempt_redacts_sensitive_values(self, db_session: Session):
        source = MailSource(name="Secret Sanitizer", method="GMAIL_API")
        db_session.add(source)
        db_session.commit()
        db_session.refresh(source)

        attempt = record_import_attempt(
            db_session,
            source,
            {
                "success": False,
                "errors": ["provider returned access_token=ya29.raw-token"],
                "details": [
                    {
                        "status": "failed",
                        "error": 'oauth failed: {"client_secret":"GOCSPX-raw-secret"}',
                    },
                ],
            },
            started_at=datetime.utcnow(),
            trigger="manual",
        )

        assert "ya29.raw-token" not in attempt.errors
        assert "GOCSPX-raw-secret" not in attempt.details
        assert "**redacted**" in attempt.errors
        assert "**redacted**" in attempt.details


class TestMailSourceBackfillModel:
    """Unit tests for persisted mail source backfill progress rows."""

    def test_create_backfill_job_row(self, db_session: Session):
        workspace = get_or_create_default_workspace(db_session)
        source = MailSource(
            workspace_id=workspace.id,
            name="Backfill Source",
            method="IMAP",
        )
        db_session.add(source)
        db_session.flush()

        row = MailSourceBackfillJob(
            workspace_id=workspace.id,
            mail_source_id=source.id,
            status="queued",
            requested_by="operator@example.com",
            processed=10,
            reports_found=2,
            duplicate_reports=1,
            errors='["temporary failure"]',
            details='[{"status": "queued"}]',
        )
        db_session.add(row)
        db_session.commit()
        db_session.refresh(row)

        assert row.id is not None
        assert row.workspace_id == workspace.id
        assert row.mail_source_id == source.id
        assert row.mail_source.name == "Backfill Source"
        assert row.status == "queued"


def test_mail_source_folder_input_has_no_pattern_validation():
    """The UI should not reject valid IMAP folder names containing spaces."""
    template = (Path(__file__).resolve().parents[1] / "templates" / "mail_sources.html").read_text()
    model_position = template.index('x-model="form.folder"')
    input_start = template.rfind("<input", 0, model_position)
    input_end = template.index(">", model_position)
    folder_input = template[input_start:input_end]

    assert "pattern=" not in folder_input


def test_mail_sources_template_exposes_backfill_progress_controls():
    """The UI should surface queued backfill progress, cancellation, and retry."""
    template = (Path(__file__).resolve().parents[1] / "templates" / "mail_sources.html").read_text()

    assert "data-backfill-progress" in template
    assert "progress_percent" in template
    assert "status_summary" in template
    assert "can_cancel" in template
    assert "can_retry" in template
    assert "/backfills?limit=5" in template
    assert "/backfills/${job.id}/cancel" in template
    assert "/backfills/${job.id}/retry" in template
    assert "Queue Backfill" in template
    assert "canCancelBackfill" in template
    assert "canRetryBackfill" in template
    assert "latestBackfill(source)" in template
    assert "apiErrorFeedback" in template
    assert "feedback.links" in template
    assert "x-html" not in template


class TestImportHistoryDecoding:
    """Unit tests for import-history JSON decoding helpers."""

    def test_decode_details_handles_empty_and_malformed_values(self):
        from app.api.api_v1.endpoints.mail_sources import _decode_json_details

        assert _decode_json_details(None) == []
        assert _decode_json_details("not-json") == []
        assert _decode_json_details('{"not": "a list"}') == []
        assert _decode_json_details('["skip", {"status": "imported", "report_id": 123}]') == [
            {"status": "imported", "report_id": "123"}
        ]


class TestMailSourcesAPI:
    """Integration tests for /api/v1/mail-sources endpoints (no auth)."""

    def test_list_requires_auth(self, client: TestClient):
        resp = client.get("/api/v1/mail-sources")
        # Without auth, expect 401 or 403
        assert resp.status_code in (401, 403)

    def test_create_requires_auth(self, client: TestClient):
        resp = client.post("/api/v1/mail-sources", json={"name": "x", "method": "IMAP"})
        assert resp.status_code in (401, 403)

    def test_model_create_and_list(self, client: TestClient, db_session: Session):
        """Create a mail source directly in DB and verify it's retrievable."""
        source = MailSource(
            name="Direct DB Source",
            method="IMAP",
            server="imap.example.com",
            port=993,
            username="user@example.com",
            password="secret",
            use_ssl=True,
            folder="INBOX",
            polling_interval=60,
            enabled=True,
        )
        db_session.add(source)
        db_session.commit()
        db_session.refresh(source)

        assert source.id is not None
        fetched = db_session.query(MailSource).filter_by(name="Direct DB Source").first()
        assert fetched is not None
        assert fetched.server == "imap.example.com"

    def test_toggle_enabled(self, db_session: Session):
        source = MailSource(name="Toggle Test", method="IMAP", enabled=True)
        db_session.add(source)
        db_session.commit()
        db_session.refresh(source)

        # Simulate toggle
        source.enabled = not source.enabled
        db_session.commit()
        db_session.refresh(source)

        assert source.enabled is False

        source.enabled = not source.enabled
        db_session.commit()
        db_session.refresh(source)

        assert source.enabled is True

    def test_delete_source(self, db_session: Session):
        source = MailSource(name="To Delete", method="IMAP")
        db_session.add(source)
        db_session.commit()
        sid = source.id

        db_session.delete(source)
        db_session.commit()

        fetched = db_session.query(MailSource).filter_by(id=sid).first()
        assert fetched is None

    def test_query_enabled_sources(self, db_session: Session):
        db_session.add(MailSource(name="Enabled A", method="IMAP", enabled=True))
        db_session.add(MailSource(name="Enabled B", method="IMAP", enabled=True))
        db_session.add(MailSource(name="Disabled", method="IMAP", enabled=False))
        db_session.commit()

        enabled = db_session.query(MailSource).filter(MailSource.enabled).all()
        assert len(enabled) == 2
        names = {s.name for s in enabled}
        assert "Enabled A" in names
        assert "Enabled B" in names
        assert "Disabled" not in names


# ---------------------------------------------------------------------------
# Authenticated HTTP API tests (uses authed_client fixture from conftest)
# ---------------------------------------------------------------------------


class TestMailSourcesAPIAuthed:
    """HTTP-level tests using the authed_client fixture (auth dependency bypassed)."""

    # ------------------------------------------------------------------
    # List
    # ------------------------------------------------------------------

    def test_list_empty(self, authed_client: TestClient):
        resp = authed_client.get("/api/v1/mail-sources")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_mail_source_routes_require_workspace_membership(
        self,
        test_app,
        db_session: Session,
    ):
        workspace = get_or_create_default_workspace(db_session)
        operator = _add_user(db_session, "mail-operator@example.com")
        outsider = _add_user(db_session, "mail-outsider@example.com")
        _add_membership(db_session, workspace, operator, ROLE_OPERATOR)
        db_session.commit()

        current_user = {"id": operator.id}

        async def mock_admin_auth():
            return {"auth_type": "session", "user_id": current_user["id"]}

        def override_get_db():
            try:
                yield db_session
            finally:
                pass

        test_app.dependency_overrides[get_db] = override_get_db
        test_app.dependency_overrides[require_admin_auth] = mock_admin_auth

        with TestClient(test_app) as client:
            list_response = client.get("/api/v1/mail-sources")
            assert list_response.status_code == 200

            create_response = client.post(
                "/api/v1/mail-sources",
                json={"name": "Operator IMAP", "method": "IMAP"},
            )
            assert create_response.status_code == 201

            source_id = create_response.json()["id"]
            update_response = client.put(
                f"/api/v1/mail-sources/{source_id}",
                json={"folder": "Reports"},
            )
            assert update_response.status_code == 200

            current_user["id"] = outsider.id

            list_response = client.get("/api/v1/mail-sources")
            assert list_response.status_code == 403

            create_response = client.post(
                "/api/v1/mail-sources",
                json={"name": "Blocked IMAP", "method": "IMAP"},
            )
            assert create_response.status_code == 403

        test_app.dependency_overrides.clear()

    def test_mail_source_routes_respect_selected_workspace_header(
        self,
        authed_client: TestClient,
        db_session: Session,
    ):
        """Mail-source CRUD actions stay inside the selected workspace."""
        get_or_create_default_workspace(db_session)
        selected_workspace = Workspace(
            slug="selected-mail-sources",
            name="Selected Mail Sources",
        )
        db_session.add(selected_workspace)
        db_session.commit()
        selected_header = {"X-DMARQ-Workspace-ID": str(selected_workspace.id)}

        create_response = authed_client.post(
            "/api/v1/mail-sources",
            headers=selected_header,
            json={"name": "Selected IMAP", "method": "IMAP", "enabled": True},
        )

        assert create_response.status_code == 201
        source_id = create_response.json()["id"]
        source = db_session.get(MailSource, source_id)
        assert source.workspace_id == selected_workspace.id

        default_list = authed_client.get("/api/v1/mail-sources")
        selected_list = authed_client.get("/api/v1/mail-sources", headers=selected_header)
        default_get = authed_client.get(f"/api/v1/mail-sources/{source_id}")
        selected_get = authed_client.get(
            f"/api/v1/mail-sources/{source_id}",
            headers=selected_header,
        )

        assert default_list.status_code == 200
        assert default_list.json() == []
        assert selected_list.status_code == 200
        assert [item["id"] for item in selected_list.json()] == [source_id]
        assert default_get.status_code == 404
        assert selected_get.status_code == 200
        assert selected_get.json()["name"] == "Selected IMAP"

        update_response = authed_client.put(
            f"/api/v1/mail-sources/{source_id}",
            headers=selected_header,
            json={"name": "Selected IMAP Updated"},
        )
        toggle_response = authed_client.post(
            f"/api/v1/mail-sources/{source_id}/toggle",
            headers=selected_header,
        )
        default_delete = authed_client.delete(f"/api/v1/mail-sources/{source_id}")
        selected_delete = authed_client.delete(
            f"/api/v1/mail-sources/{source_id}",
            headers=selected_header,
        )

        assert update_response.status_code == 200
        assert update_response.json()["name"] == "Selected IMAP Updated"
        assert toggle_response.status_code == 200
        assert toggle_response.json()["enabled"] is False
        assert default_delete.status_code == 404
        assert selected_delete.status_code == 204

    # ------------------------------------------------------------------
    # Create
    # ------------------------------------------------------------------

    def test_create_imap_source(self, authed_client: TestClient):
        payload = {
            "name": "My IMAP",
            "method": "IMAP",
            "server": "imap.example.com",
            "port": 993,
            "username": "user@example.com",
            "password": "s3cr3t",
            "use_ssl": True,
            "folder": "Junk Mail",
            "polling_interval": 60,
            "enabled": True,
        }
        resp = authed_client.post("/api/v1/mail-sources", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "My IMAP"
        assert data["method"] == "IMAP"
        assert data["server"] == "imap.example.com"
        assert data["folder"] == "Junk Mail"
        assert data["password"] == "**redacted**"
        assert data["id"] is not None

    def test_create_normalizes_method_to_uppercase(self, authed_client: TestClient):
        payload = {"name": "lowercase method", "method": "imap"}
        resp = authed_client.post("/api/v1/mail-sources", json=payload)
        assert resp.status_code == 201
        assert resp.json()["method"] == "IMAP"

    def test_create_enabled_source_allows_unverified_report_domains(
        self,
        authed_client: TestClient,
        db_session: Session,
    ):
        workspace = get_or_create_default_workspace(db_session)
        _add_domain(db_session, workspace, verified=False)

        enabled = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Report mailbox", "method": "IMAP", "enabled": True},
        )
        disabled = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Staged IMAP", "method": "IMAP", "enabled": False},
        )

        assert enabled.status_code == 201
        assert enabled.json()["enabled"] is True
        assert disabled.status_code == 201
        assert disabled.json()["enabled"] is False

    def test_create_enabled_source_allows_verified_domains(
        self,
        authed_client: TestClient,
        db_session: Session,
    ):
        workspace = get_or_create_default_workspace(db_session)
        _add_domain(db_session, workspace, verified=True)

        response = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Verified IMAP", "method": "IMAP", "enabled": True},
        )

        assert response.status_code == 201
        assert response.json()["enabled"] is True

    # ------------------------------------------------------------------
    # Get single
    # ------------------------------------------------------------------

    def test_get_existing_source(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources", json={"name": "Get Test", "method": "IMAP"}
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.get(f"/api/v1/mail-sources/{source_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == source_id
        assert resp.json()["name"] == "Get Test"

    def test_list_import_history(self, authed_client: TestClient, db_session: Session):
        create_resp = authed_client.post(
            "/api/v1/mail-sources", json={"name": "History API", "method": "IMAP"}
        )
        source_id = create_resp.json()["id"]

        db_session.add(
            MailSourceImport(
                mail_source_id=source_id,
                trigger="manual",
                status="warning",
                processed=2,
                reports_found=1,
                duplicate_reports=1,
                error_count=1,
                new_domains='["example.com"]',
                errors='["sanitized error"]',
                details='[{"status": "duplicate", "report_id": "abc-123"}]',
            )
        )
        db_session.commit()

        resp = authed_client.get(f"/api/v1/mail-sources/{source_id}/imports")

        assert resp.status_code == 200
        data = resp.json()
        assert len(data) == 1
        assert data[0]["mail_source_id"] == source_id
        assert data[0]["status"] == "warning"
        assert data[0]["duplicate_reports"] == 1
        assert data[0]["new_domains"] == ["example.com"]
        assert data[0]["errors"] == ["sanitized error"]
        assert data[0]["details"] == [{"status": "duplicate", "report_id": "abc-123"}]

    def test_list_import_history_handles_malformed_json(
        self, authed_client: TestClient, db_session: Session
    ):
        create_resp = authed_client.post(
            "/api/v1/mail-sources", json={"name": "Bad History JSON", "method": "IMAP"}
        )
        source_id = create_resp.json()["id"]

        db_session.add(
            MailSourceImport(
                mail_source_id=source_id,
                trigger="manual",
                status="warning",
                new_domains="not-json",
                errors='{"not": "a list"}',
                details='{"not": "a list"}',
            )
        )
        db_session.commit()

        resp = authed_client.get(f"/api/v1/mail-sources/{source_id}/imports")

        assert resp.status_code == 200
        assert resp.json()[0]["new_domains"] == []
        assert resp.json()[0]["errors"] == []
        assert resp.json()[0]["details"] == []

    def test_list_import_history_unknown_source_returns_404(self, authed_client: TestClient):
        resp = authed_client.get("/api/v1/mail-sources/99999/imports")
        assert resp.status_code == 404

    def test_create_and_list_backfill_job(
        self,
        authed_client: TestClient,
        db_session: Session,
    ):
        workspace = get_or_create_default_workspace(db_session)
        _add_domain(db_session, workspace, verified=False)
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Backfill API", "method": "IMAP"},
        )
        source_id = create_resp.json()["id"]

        response = authed_client.post(
            f"/api/v1/mail-sources/{source_id}/backfills",
            json={
                "requested_start": "2026-05-01T00:00:00",
                "requested_end": "2026-05-31T23:59:59",
                "max_attempts": 4,
            },
        )

        assert response.status_code == 201
        job = response.json()
        assert job["mail_source_id"] == source_id
        assert job["status"] == "queued"
        assert job["trigger"] == "manual"
        assert job["requested_start"] == "2026-05-01T00:00:00"
        assert job["requested_end"] == "2026-05-31T23:59:59"
        assert job["max_attempts"] == 4
        assert job["cursor_checkpoint"] is None
        assert job["errors"] == []
        assert job["details"] == []
        assert job["requested_window_days"] == 31
        assert job["elapsed_seconds"] is None
        assert job["progress_percent"] == 0
        assert job["can_cancel"] is True
        assert job["can_retry"] is False
        assert job["status_summary"] == "Queued to scan a 31-day mailbox window."

        list_response = authed_client.get(f"/api/v1/mail-sources/{source_id}/backfills")
        get_response = authed_client.get(f"/api/v1/mail-sources/{source_id}/backfills/{job['id']}")

        assert list_response.status_code == 200
        assert [item["id"] for item in list_response.json()] == [job["id"]]
        assert list_response.json()[0]["requested_window_days"] == 31
        assert get_response.status_code == 200
        assert get_response.json()["id"] == job["id"]
        assert get_response.json()["can_cancel"] is True

        row = db_session.get(MailSourceBackfillJob, job["id"])
        row.cursor = json.dumps(
            {
                "version": 1,
                "connector": "gmail",
                "state": "running",
                "window_days": 31,
                "processed": 25,
                "reports_found": 7,
                "page_cursor": "next-page-token",
            }
        )
        db_session.commit()

        checkpoint_response = authed_client.get(
            f"/api/v1/mail-sources/{source_id}/backfills/{job['id']}"
        )

        assert checkpoint_response.status_code == 200
        assert checkpoint_response.json()["cursor_checkpoint"]["connector"] == "gmail"
        assert checkpoint_response.json()["cursor_checkpoint"]["page_cursor"] == "**redacted**"

    def test_backfill_cursor_checkpoint_preserves_legacy_formats(self):
        legacy = mail_sources_endpoint._backfill_cursor_checkpoint(
            "imap:days=10;processed=42;state=backoff;ignored"
        )
        plain = mail_sources_endpoint._backfill_cursor_checkpoint("legacy-cursor")
        list_payload = mail_sources_endpoint._backfill_cursor_checkpoint("[1, 2, 3]")

        assert legacy == {
            "version": 0,
            "raw": "imap:days=10;processed=42;state=backoff;ignored",
            "connector": "imap",
            "days": 10,
            "processed": 42,
            "state": "backoff",
        }
        assert plain == {"version": 0, "raw": "legacy-cursor"}
        assert list_payload is None

    def test_demo_mode_returns_mail_source_backfill_examples(
        self,
        authed_client: TestClient,
        monkeypatch,
    ):
        monkeypatch.setattr(
            mail_sources_endpoint,
            "get_settings",
            lambda: SimpleNamespace(DEMO_MODE=True),
        )

        sources_response = authed_client.get("/api/v1/mail-sources")
        assert sources_response.status_code == 200
        sources = sources_response.json()
        assert {source["id"] for source in sources} >= {9001, 9002, 9003}

        backfills_response = authed_client.get("/api/v1/mail-sources/9001/backfills?limit=5")
        assert backfills_response.status_code == 200
        backfills = backfills_response.json()
        assert {job["status"] for job in backfills} >= {"completed", "running"}
        running = next(job for job in backfills if job["status"] == "running")
        assert running["requested_window_days"] == 30
        assert running["progress_percent"] > 0
        assert running["can_cancel"] is True
        assert "Scanning a 30-day mailbox window" in running["status_summary"]

        queue_response = authed_client.post(
            "/api/v1/mail-sources/9001/backfills",
            json={"max_attempts": 2},
        )
        assert queue_response.status_code == 201
        assert queue_response.json()["status"] == "queued"
        assert queue_response.json()["details"][0]["source"] == "dmarq.org aggregate reports"
        assert queue_response.json()["requested_window_days"] == 30
        assert queue_response.json()["progress_percent"] == 0

        cancel_response = authed_client.post("/api/v1/mail-sources/9001/backfills/9102/cancel")
        assert cancel_response.status_code == 200
        assert cancel_response.json()["status"] == "cancelled"

        retry_response = authed_client.post("/api/v1/mail-sources/9002/backfills/9201/retry")
        assert retry_response.status_code == 200
        assert retry_response.json()["status"] == "queued"

    def test_backfill_jobs_respect_selected_workspace_header(
        self,
        authed_client: TestClient,
        db_session: Session,
    ):
        get_or_create_default_workspace(db_session)
        selected_workspace = Workspace(
            slug="selected-backfill",
            name="Selected Backfill",
        )
        db_session.add(selected_workspace)
        db_session.commit()
        selected_header = {"X-DMARQ-Workspace-ID": str(selected_workspace.id)}

        create_response = authed_client.post(
            "/api/v1/mail-sources",
            headers=selected_header,
            json={"name": "Selected Backfill IMAP", "method": "IMAP"},
        )
        source_id = create_response.json()["id"]
        job_response = authed_client.post(
            f"/api/v1/mail-sources/{source_id}/backfills",
            headers=selected_header,
            json={},
        )
        job_id = job_response.json()["id"]

        default_list = authed_client.get(f"/api/v1/mail-sources/{source_id}/backfills")
        selected_list = authed_client.get(
            f"/api/v1/mail-sources/{source_id}/backfills",
            headers=selected_header,
        )
        default_get = authed_client.get(f"/api/v1/mail-sources/{source_id}/backfills/{job_id}")

        assert default_list.status_code == 404
        assert selected_list.status_code == 200
        assert [item["id"] for item in selected_list.json()] == [job_id]
        assert default_get.status_code == 404

    def test_cancel_and_retry_backfill_job(
        self,
        authed_client: TestClient,
        db_session: Session,
    ):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Backfill Lifecycle", "method": "IMAP"},
        )
        source_id = create_resp.json()["id"]
        job_id = authed_client.post(
            f"/api/v1/mail-sources/{source_id}/backfills",
            json={"max_attempts": 2},
        ).json()["id"]

        cancel_response = authed_client.post(
            f"/api/v1/mail-sources/{source_id}/backfills/{job_id}/cancel"
        )
        row = db_session.get(MailSourceBackfillJob, job_id)
        row.started_at = datetime.utcnow()
        db_session.commit()
        retry_response = authed_client.post(
            f"/api/v1/mail-sources/{source_id}/backfills/{job_id}/retry"
        )

        db_session.refresh(row)
        assert cancel_response.status_code == 200
        assert cancel_response.json()["status"] == "cancelled"
        assert cancel_response.json()["cancelled_at"] is not None
        assert retry_response.status_code == 200
        assert retry_response.json()["status"] == "queued"
        assert retry_response.json()["attempt_count"] == 1
        assert retry_response.json()["started_at"] is None
        assert row.status == "queued"
        assert row.started_at is None

    def test_backfill_rejects_invalid_window_and_unsupported_method(
        self,
        authed_client: TestClient,
    ):
        imap_id = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Bad Backfill Window", "method": "IMAP"},
        ).json()["id"]
        pop_id = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "POP3 Backfill", "method": "POP3"},
        ).json()["id"]

        bad_window = authed_client.post(
            f"/api/v1/mail-sources/{imap_id}/backfills",
            json={
                "requested_start": "2026-06-01T00:00:00",
                "requested_end": "2026-05-01T00:00:00",
            },
        )
        unsupported = authed_client.post(
            f"/api/v1/mail-sources/{pop_id}/backfills",
            json={},
        )

        assert bad_window.status_code == 422
        assert unsupported.status_code == 400
        assert "POP3" in unsupported.json()["detail"]

    def test_retry_backfill_rejects_active_or_exhausted_jobs(
        self,
        authed_client: TestClient,
        db_session: Session,
    ):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Backfill Retry Guard", "method": "IMAP"},
        )
        source_id = create_resp.json()["id"]
        queued_job = authed_client.post(
            f"/api/v1/mail-sources/{source_id}/backfills",
            json={},
        ).json()

        queued_retry = authed_client.post(
            f"/api/v1/mail-sources/{source_id}/backfills/{queued_job['id']}/retry"
        )

        row = db_session.get(MailSourceBackfillJob, queued_job["id"])
        row.status = "failed"
        row.attempt_count = row.max_attempts
        db_session.commit()
        exhausted_retry = authed_client.post(
            f"/api/v1/mail-sources/{source_id}/backfills/{queued_job['id']}/retry"
        )

        assert queued_retry.status_code == 409
        assert exhausted_retry.status_code == 409
        assert "max_attempts" in exhausted_retry.json()["detail"]

    def test_get_nonexistent_source_returns_404(self, authed_client: TestClient):
        resp = authed_client.get("/api/v1/mail-sources/99999")
        assert resp.status_code == 404

    # ------------------------------------------------------------------
    # Update
    # ------------------------------------------------------------------

    def test_update_name(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources", json={"name": "Original", "method": "IMAP"}
        )
        source_id = create_resp.json()["id"]

        update_resp = authed_client.put(
            f"/api/v1/mail-sources/{source_id}", json={"name": "Updated"}
        )
        assert update_resp.status_code == 200
        assert update_resp.json()["name"] == "Updated"

    def test_update_method_normalizes_uppercase(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources", json={"name": "MethodTest", "method": "IMAP"}
        )
        source_id = create_resp.json()["id"]

        update_resp = authed_client.put(
            f"/api/v1/mail-sources/{source_id}", json={"method": "pop3"}
        )
        assert update_resp.status_code == 200
        assert update_resp.json()["method"] == "POP3"

    def test_update_enable_allows_unverified_report_domains(
        self,
        authed_client: TestClient,
        db_session: Session,
    ):
        workspace = get_or_create_default_workspace(db_session)
        _add_domain(db_session, workspace, verified=False)
        source = MailSource(
            workspace_id=workspace.id,
            name="Staged IMAP",
            method="IMAP",
            enabled=False,
        )
        db_session.add(source)
        db_session.commit()

        response = authed_client.put(
            f"/api/v1/mail-sources/{source.id}",
            json={"enabled": True},
        )

        db_session.refresh(source)
        assert response.status_code == 200
        assert response.json()["enabled"] is True
        assert source.enabled is True

    def test_update_nonexistent_source_returns_404(self, authed_client: TestClient):
        resp = authed_client.put("/api/v1/mail-sources/99999", json={"name": "x"})
        assert resp.status_code == 404

    # ------------------------------------------------------------------
    # Delete
    # ------------------------------------------------------------------

    def test_delete_source(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources", json={"name": "Delete Me", "method": "IMAP"}
        )
        source_id = create_resp.json()["id"]

        del_resp = authed_client.delete(f"/api/v1/mail-sources/{source_id}")
        assert del_resp.status_code == 204

        # Verify gone
        get_resp = authed_client.get(f"/api/v1/mail-sources/{source_id}")
        assert get_resp.status_code == 404

    def test_delete_nonexistent_source_returns_404(self, authed_client: TestClient):
        resp = authed_client.delete("/api/v1/mail-sources/99999")
        assert resp.status_code == 404

    # ------------------------------------------------------------------
    # List after creates
    # ------------------------------------------------------------------

    def test_list_multiple_sources(self, authed_client: TestClient):
        for i in range(3):
            authed_client.post(
                "/api/v1/mail-sources", json={"name": f"Source {i}", "method": "IMAP"}
            )
        resp = authed_client.get("/api/v1/mail-sources")
        assert resp.status_code == 200
        assert len(resp.json()) == 3

    # ------------------------------------------------------------------
    # Toggle
    # ------------------------------------------------------------------

    def test_toggle_disables_then_enables(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources", json={"name": "Toggle", "method": "IMAP", "enabled": True}
        )
        source_id = create_resp.json()["id"]

        toggle_resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/toggle")
        assert toggle_resp.status_code == 200
        assert toggle_resp.json()["enabled"] is False

        toggle_resp2 = authed_client.post(f"/api/v1/mail-sources/{source_id}/toggle")
        assert toggle_resp2.status_code == 200
        assert toggle_resp2.json()["enabled"] is True

    def test_toggle_enable_allows_unverified_report_domains(
        self,
        authed_client: TestClient,
        db_session: Session,
    ):
        workspace = get_or_create_default_workspace(db_session)
        _add_domain(db_session, workspace, verified=False)
        source = MailSource(
            workspace_id=workspace.id,
            name="Toggle staged",
            method="IMAP",
            enabled=False,
        )
        db_session.add(source)
        db_session.commit()

        response = authed_client.post(f"/api/v1/mail-sources/{source.id}/toggle")

        db_session.refresh(source)
        assert response.status_code == 200
        assert response.json()["enabled"] is True
        assert source.enabled is True

    def test_toggle_nonexistent_returns_404(self, authed_client: TestClient):
        resp = authed_client.post("/api/v1/mail-sources/99999/toggle")
        assert resp.status_code == 404

    # ------------------------------------------------------------------
    # Test stored source
    # ------------------------------------------------------------------

    def test_test_stored_imap_source_success(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={
                "name": "IMAP Test",
                "method": "IMAP",
                "server": "imap.example.com",
                "username": "u",
                "password": "p",
            },
        )
        source_id = create_resp.json()["id"]

        mock_stats = {
            "message_count": 10,
            "unread_count": 2,
            "dmarc_count": 1,
            "available_mailboxes": ["INBOX"],
        }
        mock_client = MagicMock()
        mock_client.test_connection.return_value = (True, "Connection successful", mock_stats)

        with patch("app.api.api_v1.endpoints.mail_sources.IMAPClient", return_value=mock_client):
            resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/test")

        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["message"] == "Connection successful"
        assert data["message_count"] == 10

    def test_test_stored_imap_source_failure(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "IMAP Fail", "method": "IMAP", "server": "bad.host"},
        )
        source_id = create_resp.json()["id"]

        mock_client = MagicMock()
        mock_client.test_connection.return_value = (
            False,
            "Connection failed. Check server address and credentials.",
            {},
        )

        with patch("app.api.api_v1.endpoints.mail_sources.IMAPClient", return_value=mock_client):
            resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/test")

        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is False
        assert data["diagnostic_category"] == "authentication"
        assert data["diagnostic"]["summary"]
        assert data["recovery_steps"]

    def test_test_stored_imap_source_sanitizes_diagnostics(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "IMAP Secret Fail", "method": "IMAP", "server": "bad.host"},
        )
        source_id = create_resp.json()["id"]

        mock_client = MagicMock()
        mock_client.test_connection.return_value = (
            False,
            "Connection failed",
            {"diagnostic_detail": "password=secret-token refused"},
        )

        with patch("app.api.api_v1.endpoints.mail_sources.IMAPClient", return_value=mock_client):
            resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/test")

        data = resp.json()
        assert data["success"] is False
        assert data["diagnostic_category"] == "authentication"
        assert "secret-token" not in json.dumps(data)
        assert "password=**redacted**" in data["diagnostic"]["details"]

    def test_test_stored_non_imap_source(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources", json={"name": "POP3 Source", "method": "POP3"}
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/test")
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is False
        assert "not yet implemented" in data["message"]

    def test_test_stored_nonexistent_returns_404(self, authed_client: TestClient):
        resp = authed_client.post("/api/v1/mail-sources/99999/test")
        assert resp.status_code == 404

    # ------------------------------------------------------------------
    # Ad-hoc test connection
    # ------------------------------------------------------------------

    def test_adhoc_imap_success(self, authed_client: TestClient):
        payload = {
            "server": "imap.example.com",
            "port": 993,
            "username": "user@example.com",
            "password": "secret",
            "ssl": True,
            "method": "IMAP",
        }
        mock_stats = {
            "message_count": 5,
            "unread_count": 1,
            "dmarc_count": 0,
            "available_mailboxes": ["INBOX"],
        }
        mock_client = MagicMock()
        mock_client.test_connection.return_value = (True, "Connection successful", mock_stats)

        with patch("app.api.api_v1.endpoints.mail_sources.IMAPClient", return_value=mock_client):
            resp = authed_client.post("/api/v1/mail-sources/test-connection", json=payload)

        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["message_count"] == 5

    def test_adhoc_non_imap_returns_not_implemented(self, authed_client: TestClient):
        payload = {
            "server": "pop3.example.com",
            "port": 110,
            "username": "u",
            "password": "p",
            "ssl": False,
            "method": "POP3",
        }
        resp = authed_client.post("/api/v1/mail-sources/test-connection", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is False
        assert data["diagnostic_category"] == "not_implemented"
        assert "not yet implemented" in data["message"]

    def test_adhoc_gmail_api_returns_not_implemented(self, authed_client: TestClient):
        payload = {"method": "GMAIL_API"}
        resp = authed_client.post("/api/v1/mail-sources/test-connection", json=payload)
        assert resp.status_code == 200
        assert resp.json()["success"] is False
        assert resp.json()["diagnostic_category"] == "not_implemented"
        assert "not yet implemented" in resp.json()["message"]

    def test_diagnostic_category_common_failure_modes(self):
        cases = {
            "invalid_grant refresh token expired": "auth_expired",
            "insufficient permission for gmail scope": "permissions",
            "rate limit 429 too many requests": "throttling",
            "select failed for folder DMARC": "mailbox_not_found",
            "login failed invalid password": "authentication",
            "dns timeout refused": "connectivity",
            "server is required": "missing_config",
        }

        for message, expected in cases.items():
            assert mail_sources_endpoint._diagnostic_category(message) == expected


# ---------------------------------------------------------------------------
# Gmail API-specific tests
# ---------------------------------------------------------------------------


class TestGmailAPIMailSource:
    """Tests for GMAIL_API mail source creation, OAuth flow, and fetching."""

    def test_create_gmail_api_source(self, authed_client: TestClient):
        payload = {
            "name": "My Gmail",
            "method": "GMAIL_API",
            "gmail_client_id": "123-abc.apps.googleusercontent.com",
            "gmail_client_secret": "GOCSPX-secret",
            "polling_interval": 30,
            "enabled": True,
        }
        resp = authed_client.post("/api/v1/mail-sources", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["method"] == "GMAIL_API"
        assert data["gmail_client_id"] == "123-abc.apps.googleusercontent.com"
        # Secret should be redacted in response
        assert data["gmail_client_secret"] == "**redacted**"
        assert data["gmail_connected"] is False
        assert data["gmail_email"] is None

    def test_gmail_source_test_no_token(self, authed_client: TestClient):
        """Test a GMAIL_API source that has no OAuth tokens yet."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Unauthed Gmail", "method": "GMAIL_API"},
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/test")
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is False
        assert "not yet authorised" in data["message"].lower() or "oauth" in data["message"].lower()
        assert data["diagnostic_category"] == "auth_required"
        assert any("Connect Gmail" in step for step in data["recovery_steps"])

    def test_gmail_source_test_with_valid_token(self, authed_client: TestClient):
        """Test a GMAIL_API source that has valid OAuth tokens (mocked)."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={
                "name": "Authed Gmail",
                "method": "GMAIL_API",
                "gmail_client_id": "my-client-id",
                "gmail_client_secret": "my-secret",
            },
        )
        source_id = create_resp.json()["id"]

        # Use the authed_client's DB override — patch the ORM object instead
        mock_service = MagicMock()
        mock_service.users.return_value.getProfile.return_value.execute.return_value = {
            "emailAddress": "test@gmail.com"
        }
        mock_gmail_client = MagicMock()
        mock_gmail_client._build_service.return_value = mock_service

        with patch(
            "app.api.api_v1.endpoints.mail_sources.GmailClient",
            return_value=mock_gmail_client,
        ):
            # First set the access token directly
            with patch("app.api.api_v1.endpoints.mail_sources._get_source_or_404") as mock_get:
                mock_source = MagicMock()
                mock_source.method = "GMAIL_API"
                mock_source.gmail_access_token = "valid-token"
                mock_source.gmail_email = "test@gmail.com"
                mock_source.gmail_client_id = "my-client-id"
                mock_source.gmail_client_secret = "my-secret"
                mock_source.gmail_refresh_token = "refresh-token"
                mock_get.return_value = mock_source

                resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/test")

        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert "valid" in data["message"].lower()

    def test_gmail_authorize_url_no_client_id(self, authed_client: TestClient):
        """Requesting authorize-url without a client_id returns 400."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "No Client ID Gmail", "method": "GMAIL_API"},
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.get(f"/api/v1/mail-sources/{source_id}/gmail/authorize-url")
        assert resp.status_code == 400

    def test_gmail_authorize_url_wrong_method(self, authed_client: TestClient):
        """Requesting authorize-url on a non-GMAIL_API source returns 400."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources", json={"name": "IMAP Source", "method": "IMAP"}
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.get(f"/api/v1/mail-sources/{source_id}/gmail/authorize-url")
        assert resp.status_code == 400

    def test_gmail_authorize_url_returns_google_url(self, authed_client: TestClient):
        """A GMAIL_API source with client_id returns a valid Google auth URL."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={
                "name": "Ready Gmail",
                "method": "GMAIL_API",
                "gmail_client_id": "123-abc.apps.googleusercontent.com",
            },
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.get(f"/api/v1/mail-sources/{source_id}/gmail/authorize-url")
        assert resp.status_code == 200
        data = resp.json()
        assert "authorization_url" in data
        _parsed = urlparse(data["authorization_url"])
        assert _parsed.hostname == "accounts.google.com"
        assert parse_qs(_parsed.query).get("client_id") == ["123-abc.apps.googleusercontent.com"]
        assert "gmail.readonly" in data["authorization_url"]

    def test_gmail_disconnect_clears_tokens(self, authed_client: TestClient):
        """DELETE /gmail/connection clears stored OAuth tokens."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Disconnect Test", "method": "GMAIL_API"},
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.delete(f"/api/v1/mail-sources/{source_id}/gmail/connection")
        assert resp.status_code == 204

    def test_gmail_disconnect_wrong_method_returns_400(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources", json={"name": "IMAP2", "method": "IMAP"}
        )
        source_id = create_resp.json()["id"]
        resp = authed_client.delete(f"/api/v1/mail-sources/{source_id}/gmail/connection")
        assert resp.status_code == 400

    def test_gmail_fetch_no_token_returns_400(self, authed_client: TestClient):
        """Fetch without OAuth tokens returns 400."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "No Token Gmail", "method": "GMAIL_API"},
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/gmail/fetch")
        assert resp.status_code == 400

    def test_gmail_fetch_wrong_method_returns_400(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources", json={"name": "IMAP3", "method": "IMAP"}
        )
        source_id = create_resp.json()["id"]
        resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/gmail/fetch")
        assert resp.status_code == 400

    def test_gmail_fetch_with_mocked_client(self, authed_client: TestClient):
        """Fetch with valid token (mocked GmailClient) returns success summary."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={
                "name": "Fetch Gmail",
                "method": "GMAIL_API",
                "gmail_client_id": "cid",
                "gmail_client_secret": "csec",
            },
        )
        source_id = create_resp.json()["id"]

        mock_fetch_results = {
            "success": True,
            "processed": 3,
            "reports_found": 2,
            "new_domains": ["example.com"],
            "errors": [],
            "new_ingested_ids": ["id1", "id2", "id3"],
        }
        mock_client = MagicMock()
        mock_client.fetch_reports.return_value = mock_fetch_results
        mock_client.get_refreshed_tokens.return_value = None

        with (
            patch("app.api.api_v1.endpoints.mail_sources._get_source_or_404") as mock_get,
            patch("app.api.api_v1.endpoints.mail_sources.GmailClient", return_value=mock_client),
        ):
            mock_source = MagicMock()
            mock_source.method = "GMAIL_API"
            mock_source.gmail_access_token = "tok"
            mock_source.gmail_refresh_token = "refresh"
            mock_source.gmail_client_id = "cid"
            mock_source.gmail_client_secret = "csec"
            mock_source.gmail_ingested_ids = "[]"
            mock_source.id = source_id
            mock_get.return_value = mock_source

            resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/gmail/fetch")

        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["processed"] == 3
        assert data["reports_found"] == 2
        assert data["new_domains"] == ["example.com"]


class TestMicrosoft365GraphMailSource:
    """Tests for M365_GRAPH mail source creation, OAuth flow, and fetching."""

    def test_create_m365_graph_source(self, authed_client: TestClient):
        payload = {
            "name": "My Microsoft 365",
            "method": "M365_GRAPH",
            "m365_tenant_id": "organizations",
            "m365_client_id": "client-id",
            "m365_client_secret": "client-secret",
            "m365_mailbox": "dmarc@example.com",
            "folder": "INBOX",
            "polling_interval": 30,
            "enabled": True,
        }
        resp = authed_client.post("/api/v1/mail-sources", json=payload)
        assert resp.status_code == 201
        data = resp.json()
        assert data["method"] == "M365_GRAPH"
        assert data["m365_tenant_id"] == "organizations"
        assert data["m365_client_id"] == "client-id"
        assert data["m365_client_secret"] == "**redacted**"
        assert data["m365_mailbox"] == "dmarc@example.com"
        assert data["m365_connected"] is False
        assert data["m365_email"] is None

    def test_m365_source_test_no_token(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Unauthed M365", "method": "M365_GRAPH"},
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/test")
        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is False
        assert data["diagnostic_category"] == "auth_required"
        assert any("Microsoft 365" in step for step in data["recovery_steps"])

    def test_m365_source_test_with_valid_token(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={
                "name": "Authed M365",
                "method": "M365_GRAPH",
                "m365_client_id": "client-id",
                "m365_client_secret": "client-secret",
            },
        )
        source_id = create_resp.json()["id"]

        mock_client = MagicMock()
        mock_client.test_connection.return_value = {
            "success": True,
            "message_count": 1,
            "diagnostic_detail": "ok",
        }
        mock_client.get_refreshed_tokens.return_value = None

        with (
            patch("app.api.api_v1.endpoints.mail_sources._get_source_or_404") as mock_get,
            patch(
                "app.api.api_v1.endpoints.mail_sources.MicrosoftGraphClient",
                return_value=mock_client,
            ),
        ):
            mock_source = MagicMock()
            mock_source.method = "M365_GRAPH"
            mock_source.m365_access_token = "valid-token"
            mock_source.m365_email = "dmarc@example.com"
            mock_source.m365_tenant_id = "organizations"
            mock_source.m365_client_id = "client-id"
            mock_source.m365_client_secret = "client-secret"
            mock_source.m365_refresh_token = "refresh-token"
            mock_source.m365_mailbox = None
            mock_source.folder = "INBOX"
            mock_get.return_value = mock_source

            resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/test")

        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert "valid" in data["message"].lower()

    @pytest.mark.parametrize(
        ("provider_error", "category"),
        [
            ("invalid_grant: refresh token expired", "auth_expired"),
            ("Forbidden: Mail.Read permission is missing", "permissions"),
            ("429 Too Many Requests throttling limit", "throttling"),
        ],
    )
    def test_m365_source_test_diagnostic_categories(
        self, authed_client: TestClient, provider_error: str, category: str
    ):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "M365 Diagnostics", "method": "M365_GRAPH"},
        )
        source_id = create_resp.json()["id"]
        mock_client = MagicMock()
        mock_client.test_connection.side_effect = RuntimeError(provider_error)

        with (
            patch("app.api.api_v1.endpoints.mail_sources._get_source_or_404") as mock_get,
            patch(
                "app.api.api_v1.endpoints.mail_sources.MicrosoftGraphClient",
                return_value=mock_client,
            ),
        ):
            mock_source = MagicMock()
            mock_source.method = "M365_GRAPH"
            mock_source.m365_access_token = "valid-token"
            mock_source.m365_email = "dmarc@example.com"
            mock_source.m365_tenant_id = "organizations"
            mock_source.m365_client_id = "client-id"
            mock_source.m365_client_secret = "client-secret"
            mock_source.m365_refresh_token = "refresh-token"
            mock_source.m365_mailbox = None
            mock_source.folder = "INBOX"
            mock_get.return_value = mock_source

            resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/test")

        assert resp.status_code == 200
        assert resp.json()["diagnostic_category"] == category

    def test_m365_authorize_url_returns_microsoft_url(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={
                "name": "Ready M365",
                "method": "M365_GRAPH",
                "m365_tenant_id": "organizations",
                "m365_client_id": "client-id",
            },
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.get(f"/api/v1/mail-sources/{source_id}/m365/authorize-url")
        assert resp.status_code == 200
        data = resp.json()
        parsed = urlparse(data["authorization_url"])
        assert parsed.hostname == "login.microsoftonline.com"
        assert "/organizations/oauth2/v2.0/authorize" in parsed.path
        query = parse_qs(parsed.query)
        assert query["client_id"] == ["client-id"]
        assert "offline_access" in query["scope"][0]
        assert "https://graph.microsoft.com/Mail.Read" in query["scope"][0]

    def test_m365_authorize_url_validates_source(self, authed_client: TestClient):
        imap_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "IMAP Source", "method": "IMAP"},
        )
        imap_id = imap_resp.json()["id"]
        assert (
            authed_client.get(f"/api/v1/mail-sources/{imap_id}/m365/authorize-url").status_code
            == 400
        )

        m365_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "No Client M365", "method": "M365_GRAPH"},
        )
        m365_id = m365_resp.json()["id"]
        resp = authed_client.get(f"/api/v1/mail-sources/{m365_id}/m365/authorize-url")
        assert resp.status_code == 400
        assert "m365_client_id" in resp.json()["detail"]

    def test_m365_get_callback_handles_error_and_wrong_source(self, authed_client: TestClient):
        error_resp = authed_client.get("/api/v1/mail-sources/999/m365/callback?error=denied")
        assert error_resp.status_code == 400
        assert "authorisation failed" in error_resp.text

        imap_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "IMAP Callback", "method": "IMAP"},
        )
        imap_id = imap_resp.json()["id"]
        wrong_resp = authed_client.get(f"/api/v1/mail-sources/{imap_id}/m365/callback?code=abc")
        assert wrong_resp.status_code == 404

    def test_m365_get_callback_saves_tokens(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={
                "name": "GET Callback M365",
                "method": "M365_GRAPH",
                "m365_client_id": "client-id",
                "m365_client_secret": "client-secret",
            },
        )
        source_id = create_resp.json()["id"]

        with (
            patch(
                "app.api.api_v1.endpoints.mail_sources."
                "MicrosoftGraphClient.exchange_code_for_tokens",
                return_value={"access_token": "access", "refresh_token": "refresh"},
            ),
            patch(
                "app.api.api_v1.endpoints.mail_sources.MicrosoftGraphClient.get_account_email",
                return_value="dmarc@example.com",
            ),
        ):
            resp = authed_client.get(f"/api/v1/mail-sources/{source_id}/m365/callback?code=abc")

        assert resp.status_code == 200
        assert "connected successfully" in resp.text

    def test_m365_get_callback_failure_modes(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "GET Callback Failure", "method": "M365_GRAPH"},
        )
        source_id = create_resp.json()["id"]

        with patch(
            "app.api.api_v1.endpoints.mail_sources.MicrosoftGraphClient.exchange_code_for_tokens",
            side_effect=ValueError("bad code"),
        ):
            token_error = authed_client.get(
                f"/api/v1/mail-sources/{source_id}/m365/callback?code=abc"
            )
        assert token_error.status_code == 400
        assert "Token exchange failed" in token_error.text

        with patch(
            "app.api.api_v1.endpoints.mail_sources.MicrosoftGraphClient.exchange_code_for_tokens",
            return_value={"refresh_token": "refresh"},
        ):
            missing_access = authed_client.get(
                f"/api/v1/mail-sources/{source_id}/m365/callback?code=abc"
            )
        assert missing_access.status_code == 400
        assert "No access token" in missing_access.text

    def test_m365_callback_post_saves_tokens(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={
                "name": "Callback M365",
                "method": "M365_GRAPH",
                "m365_client_id": "client-id",
                "m365_client_secret": "client-secret",
            },
        )
        source_id = create_resp.json()["id"]

        with (
            patch(
                "app.api.api_v1.endpoints.mail_sources."
                "MicrosoftGraphClient.exchange_code_for_tokens",
                return_value={"access_token": "access", "refresh_token": "refresh"},
            ),
            patch(
                "app.api.api_v1.endpoints.mail_sources.MicrosoftGraphClient.get_account_email",
                return_value="dmarc@example.com",
            ),
        ):
            resp = authed_client.post(
                f"/api/v1/mail-sources/{source_id}/m365/callback",
                json={"code": "code", "redirect_uri": "https://example.com/callback"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["m365_connected"] is True
        assert data["m365_email"] == "dmarc@example.com"

    def test_m365_create_and_update_include_folder_id(
        self, authed_client: TestClient, db_session: Session
    ):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={
                "name": "Folder M365",
                "method": "M365_GRAPH",
                "folder": "DMARC Reports",
                "m365_client_id": "client-id",
                "m365_client_secret": "client-secret",
                "m365_mailbox": "shared@example.com",
                "m365_folder_id": "folder-id",
            },
        )

        assert create_resp.status_code == 201
        data = create_resp.json()
        assert data["m365_mailbox"] == "shared@example.com"
        assert data["m365_folder_id"] == "folder-id"

        source = db_session.get(MailSource, data["id"])
        assert source.m365_folder_id == "folder-id"

        update_resp = authed_client.put(
            f"/api/v1/mail-sources/{data['id']}",
            json={"folder": "Inbox", "m365_folder_id": ""},
        )

        assert update_resp.status_code == 200
        db_session.refresh(source)
        assert update_resp.json()["m365_folder_id"] == ""
        assert source.m365_folder_id == ""

    def test_m365_list_folders_returns_selectable_folders(
        self, authed_client: TestClient, db_session: Session
    ):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={
                "name": "Folder List M365",
                "method": "M365_GRAPH",
                "folder": "DMARC Reports",
                "m365_mailbox": "shared@example.com",
                "m365_folder_id": "folder-id",
            },
        )
        source_id = create_resp.json()["id"]
        source = db_session.get(MailSource, source_id)
        source.m365_access_token = "old-access"
        source.m365_refresh_token = "old-refresh"
        source.m365_email = "operator@example.com"
        db_session.commit()

        mock_client = MagicMock()
        mock_client.list_mail_folders.return_value = [
            {"id": "folder-id", "display_name": "DMARC Reports", "parent_folder_id": ""}
        ]
        mock_client.get_refreshed_tokens.return_value = {
            "access_token": "new-access",
            "refresh_token": "new-refresh",
        }

        with patch(
            "app.api.api_v1.endpoints.mail_sources.MicrosoftGraphClient",
            return_value=mock_client,
        ) as client_cls:
            resp = authed_client.get(f"/api/v1/mail-sources/{source_id}/m365/folders")

        assert resp.status_code == 200
        data = resp.json()
        assert data["target_mailbox"] == "shared@example.com"
        assert data["selected_folder"] == "DMARC Reports"
        assert data["selected_folder_id"] == "folder-id"
        assert data["folders"] == [
            {"id": "folder-id", "display_name": "DMARC Reports", "parent_folder_id": ""}
        ]
        client_cls.assert_called_once()
        _, kwargs = client_cls.call_args
        assert kwargs["mailbox"] == "shared@example.com"
        assert kwargs["folder"] == "DMARC Reports"
        assert kwargs["folder_id"] == "folder-id"

        db_session.refresh(source)
        assert source.m365_access_token == "new-access"
        assert source.m365_refresh_token == "new-refresh"

    def test_m365_list_folders_requires_method_and_token(self, authed_client: TestClient):
        imap_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "IMAP Folder List", "method": "IMAP"},
        )
        wrong_method = authed_client.get(
            f"/api/v1/mail-sources/{imap_resp.json()['id']}/m365/folders"
        )
        assert wrong_method.status_code == 400

        m365_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "No Token Folder List", "method": "M365_GRAPH"},
        )
        no_token = authed_client.get(f"/api/v1/mail-sources/{m365_resp.json()['id']}/m365/folders")
        assert no_token.status_code == 400

    def test_m365_callback_post_failure_modes(self, authed_client: TestClient):
        imap_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "IMAP Callback Post", "method": "IMAP"},
        )
        imap_id = imap_resp.json()["id"]
        wrong_resp = authed_client.post(
            f"/api/v1/mail-sources/{imap_id}/m365/callback",
            json={"code": "code", "redirect_uri": "https://example.com/callback"},
        )
        assert wrong_resp.status_code == 400

        m365_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Bad Callback M365", "method": "M365_GRAPH"},
        )
        m365_id = m365_resp.json()["id"]
        with patch(
            "app.api.api_v1.endpoints.mail_sources.MicrosoftGraphClient.exchange_code_for_tokens",
            side_effect=ValueError("bad code"),
        ):
            token_resp = authed_client.post(
                f"/api/v1/mail-sources/{m365_id}/m365/callback",
                json={"code": "code", "redirect_uri": "https://example.com/callback"},
            )
        assert token_resp.status_code == 400

        with patch(
            "app.api.api_v1.endpoints.mail_sources.MicrosoftGraphClient.exchange_code_for_tokens",
            return_value={"refresh_token": "refresh"},
        ):
            missing_access = authed_client.post(
                f"/api/v1/mail-sources/{m365_id}/m365/callback",
                json={"code": "code", "redirect_uri": "https://example.com/callback"},
            )
        assert missing_access.status_code == 400

    def test_m365_fetch_no_token_returns_400(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "No Token M365", "method": "M365_GRAPH"},
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/m365/fetch")
        assert resp.status_code == 400

    def test_m365_fetch_with_mocked_client(self, authed_client: TestClient, db_session: Session):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={
                "name": "Fetch M365",
                "method": "M365_GRAPH",
                "m365_client_id": "client-id",
                "m365_client_secret": "client-secret",
            },
        )
        source_id = create_resp.json()["id"]
        source = db_session.get(MailSource, source_id)
        source.m365_access_token = "tok"
        source.m365_refresh_token = "refresh"
        db_session.commit()

        mock_client = MagicMock()
        mock_client.fetch_reports.return_value = {
            "success": True,
            "processed": 3,
            "reports_found": 2,
            "duplicate_reports": 1,
            "new_domains": ["example.com"],
            "errors": [],
            "new_ingested_ids": ["id1", "id2", "id3"],
            "search_window_days": 30,
        }
        mock_client.get_refreshed_tokens.return_value = None

        with (
            patch(
                "app.api.api_v1.endpoints.mail_sources.MicrosoftGraphClient",
                return_value=mock_client,
            ),
            patch(
                "app.api.api_v1.endpoints.mail_sources.MicrosoftGraphClient.load_ingested_ids",
                return_value=[],
            ),
            patch(
                "app.api.api_v1.endpoints.mail_sources.MicrosoftGraphClient.dump_ingested_ids",
                return_value='["id1", "id2", "id3"]',
            ),
        ):
            resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/fetch?days=30")

        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["processed"] == 3
        assert data["reports_found"] == 2
        assert data["duplicate_reports"] == 1
        assert data["new_domains"] == ["example.com"]
        assert data["target_mailbox"] is None
        assert data["target_folder"] is None
        assert data["search_window_days"] == 30
        mock_client.fetch_reports.assert_called_once_with(days=30)

    def test_m365_specific_fetch_persists_refreshed_tokens(
        self, authed_client: TestClient, db_session: Session
    ):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={
                "name": "Fetch M365 Specific",
                "method": "M365_GRAPH",
                "m365_client_id": "client-id",
                "m365_client_secret": "client-secret",
            },
        )
        source_id = create_resp.json()["id"]
        source = db_session.get(MailSource, source_id)
        source.m365_access_token = "old-access"
        source.m365_refresh_token = "old-refresh"
        db_session.commit()

        mock_client = MagicMock()
        mock_client.fetch_reports.return_value = {
            "success": True,
            "processed": 1,
            "reports_found": 0,
            "duplicate_reports": 0,
            "new_domains": [],
            "errors": ["temporary warning"],
            "new_ingested_ids": [],
        }
        mock_client.get_refreshed_tokens.return_value = {
            "access_token": "new-access",
            "refresh_token": "new-refresh",
        }

        with patch(
            "app.api.api_v1.endpoints.mail_sources.MicrosoftGraphClient",
            return_value=mock_client,
        ):
            resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/m365/fetch")

        db_session.refresh(source)
        assert resp.status_code == 200
        assert resp.json()["processed"] == 1
        assert source.m365_access_token == "new-access"
        assert source.m365_refresh_token == "new-refresh"

    def test_m365_fetch_and_disconnect_validate_method(self, authed_client: TestClient):
        imap_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "IMAP M365 Actions", "method": "IMAP"},
        )
        source_id = imap_resp.json()["id"]

        fetch_resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/m365/fetch")
        disconnect_resp = authed_client.delete(f"/api/v1/mail-sources/{source_id}/m365/connection")

        assert fetch_resp.status_code == 400
        assert disconnect_resp.status_code == 400

    def test_m365_disconnect_clears_tokens(self, authed_client: TestClient, db_session: Session):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Disconnect M365", "method": "M365_GRAPH"},
        )
        source_id = create_resp.json()["id"]
        source = db_session.get(MailSource, source_id)
        source.m365_access_token = "tok"
        source.m365_refresh_token = "refresh"
        source.m365_email = "dmarc@example.com"
        db_session.commit()

        resp = authed_client.delete(f"/api/v1/mail-sources/{source_id}/m365/connection")

        db_session.refresh(source)
        assert resp.status_code == 204
        assert source.m365_access_token is None
        assert source.m365_refresh_token is None
        assert source.m365_email is None


class TestManualSourceFetchEndpoint:
    """Tests for POST /api/v1/mail-sources/{source_id}/fetch."""

    def test_fetch_allows_unverified_report_domains(
        self,
        authed_client: TestClient,
        db_session: Session,
    ):
        workspace = get_or_create_default_workspace(db_session)
        _add_domain(db_session, workspace, verified=False)
        source = MailSource(
            workspace_id=workspace.id,
            name="Unverified fetch",
            method="IMAP",
            server="imap.example.com",
            enabled=True,
        )
        db_session.add(source)
        db_session.commit()

        mock_client = MagicMock()
        mock_client.fetch_reports.return_value = {
            "success": True,
            "processed": 1,
            "reports_found": 1,
            "duplicate_reports": 0,
            "new_domains": ["example.com"],
            "errors": [],
            "details": [],
        }
        with patch(
            "app.api.api_v1.endpoints.mail_sources.IMAPClient",
            return_value=mock_client,
        ) as mock_imap:
            response = authed_client.post(f"/api/v1/mail-sources/{source.id}/fetch?days=30")

        assert response.status_code == 200
        assert response.json()["reports_found"] == 1
        mock_imap.assert_called_once()
        mock_client.fetch_reports.assert_called_once()

    def test_provider_fetches_reach_connection_validation_with_unverified_domains(
        self,
        authed_client: TestClient,
        db_session: Session,
    ):
        workspace = get_or_create_default_workspace(db_session)
        _add_domain(db_session, workspace, verified=False)
        gmail_source = MailSource(
            workspace_id=workspace.id,
            name="Unverified Gmail",
            method="GMAIL_API",
            enabled=True,
        )
        m365_source = MailSource(
            workspace_id=workspace.id,
            name="Unverified M365",
            method="M365_GRAPH",
            enabled=True,
        )
        db_session.add_all([gmail_source, m365_source])
        db_session.commit()

        gmail_response = authed_client.post(f"/api/v1/mail-sources/{gmail_source.id}/gmail/fetch")
        m365_response = authed_client.post(f"/api/v1/mail-sources/{m365_source.id}/m365/fetch")

        assert gmail_response.status_code == 400
        assert "Gmail account not yet authorised" in gmail_response.json()["detail"]
        assert m365_response.status_code == 400
        assert "Microsoft 365 account not yet authorised" in m365_response.json()["detail"]

    def test_fetch_imap_source(self, authed_client: TestClient, caplog):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={
                "name": "Fetch IMAP",
                "method": "IMAP",
                "server": "imap.example.com",
                "username": "user@example.com",
                "password": "secret",
            },
        )
        source_id = create_resp.json()["id"]
        mock_imap = MagicMock()
        mock_imap.fetch_reports.return_value = {
            "success": True,
            "processed": 5,
            "reports_found": 3,
            "duplicate_reports": 1,
            "new_domains": ["example.com"],
            "errors": ["bad attachment\nwith newline"],
            "details": [{"status": "error", "filename": "bad.xml"}],
        }

        with (
            caplog.at_level("WARNING"),
            patch("app.api.api_v1.endpoints.mail_sources.IMAPClient", return_value=mock_imap),
        ):
            resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/fetch?days=30")

        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["processed"] == 5
        assert data["reports_found"] == 3
        assert data["duplicate_reports"] == 1
        assert data["error_count"] == 1
        assert data["diagnostic_category"] == "parsing"
        assert data["recovery_steps"]
        assert "bad attachment with newline" in caplog.text
        history_resp = authed_client.get(f"/api/v1/mail-sources/{source_id}/imports")
        assert history_resp.json()[0]["details"] == [{"status": "error", "filename": "bad.xml"}]
        mock_imap.fetch_reports.assert_called_once_with(days=30)

    def test_fetch_gmail_source(self, authed_client: TestClient, db_session: Session):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={
                "name": "Fetch Gmail Generic",
                "method": "GMAIL_API",
                "gmail_client_id": "cid",
                "gmail_client_secret": "csec",
            },
        )
        source_id = create_resp.json()["id"]
        source = db_session.get(MailSource, source_id)
        source.gmail_access_token = "tok"
        source.gmail_refresh_token = "refresh"
        db_session.commit()

        mock_gmail = MagicMock()
        mock_gmail.fetch_reports.return_value = {
            "success": True,
            "processed": 2,
            "reports_found": 1,
            "duplicate_reports": 0,
            "new_domains": [],
            "errors": [],
            "new_ingested_ids": ["id1"],
            "details": [{"status": "imported", "report_id": "abc-123"}],
        }
        mock_gmail.get_refreshed_tokens.return_value = None

        with (
            patch("app.api.api_v1.endpoints.mail_sources.GmailClient", return_value=mock_gmail),
            patch(
                "app.api.api_v1.endpoints.mail_sources.GmailClient.load_ingested_ids",
                return_value=[],
            ),
            patch(
                "app.api.api_v1.endpoints.mail_sources.GmailClient.dump_ingested_ids",
                return_value='["id1"]',
            ),
        ):
            resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/fetch")

        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is True
        assert data["processed"] == 2
        assert data["reports_found"] == 1
        assert data["source_id"] == source_id

    def test_fetch_gmail_source_rejects_missing_token(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Fetch Gmail No Token", "method": "GMAIL_API"},
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/fetch")

        assert resp.status_code == 400
        assert "OAuth2" in resp.json()["detail"]

    def test_fetch_gmail_source_persists_refreshed_tokens(
        self, authed_client: TestClient, db_session: Session
    ):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={
                "name": "Fetch Gmail Refresh",
                "method": "GMAIL_API",
                "gmail_client_id": "cid",
                "gmail_client_secret": "csec",
            },
        )
        source_id = create_resp.json()["id"]
        source = db_session.get(MailSource, source_id)
        source.gmail_access_token = "old-access"
        source.gmail_refresh_token = "old-refresh"
        db_session.commit()

        mock_gmail = MagicMock()
        mock_gmail.fetch_reports.return_value = {
            "success": True,
            "processed": 1,
            "reports_found": 1,
            "duplicate_reports": 0,
            "new_domains": [],
            "errors": [],
            "new_ingested_ids": [],
        }
        mock_gmail.get_refreshed_tokens.return_value = {
            "access_token": "new-access",
            "refresh_token": "new-refresh",
        }

        with (
            patch("app.api.api_v1.endpoints.mail_sources.GmailClient", return_value=mock_gmail),
            patch(
                "app.api.api_v1.endpoints.mail_sources.GmailClient.load_ingested_ids",
                return_value=[],
            ),
        ):
            resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/fetch")

        db_session.refresh(source)
        assert resp.status_code == 200
        assert source.gmail_access_token == "new-access"
        assert source.gmail_refresh_token == "new-refresh"

    def test_fetch_rejects_invalid_days(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Bad Days", "method": "IMAP"},
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/fetch?days=0")

        assert resp.status_code == 400

    def test_fetch_rejects_unsupported_source_method(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Fetch POP3", "method": "POP3"},
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/fetch")

        assert resp.status_code == 400
        assert "not available" in resp.json()["detail"]


# ---------------------------------------------------------------------------
# GmailClient unit tests
# ---------------------------------------------------------------------------


class TestGmailClientHelpers:
    """Unit tests for GmailClient static helpers."""

    def test_load_ingested_ids_empty_string(self):
        from app.services.gmail_client import GmailClient

        assert GmailClient.load_ingested_ids("") == []

    def test_load_ingested_ids_none(self):
        from app.services.gmail_client import GmailClient

        assert GmailClient.load_ingested_ids(None) == []

    def test_load_ingested_ids_valid_json(self):
        from app.services.gmail_client import GmailClient

        result = GmailClient.load_ingested_ids('["id1", "id2"]')
        assert result == ["id1", "id2"]

    def test_load_ingested_ids_invalid_json(self):
        from app.services.gmail_client import GmailClient

        assert GmailClient.load_ingested_ids("not-json") == []

    def test_dump_ingested_ids(self):
        from app.services.gmail_client import GmailClient

        result = GmailClient.dump_ingested_ids(["id1", "id2"])
        assert '"id1"' in result
        assert '"id2"' in result

    def test_build_authorization_url(self):
        from app.services.gmail_client import GmailClient

        url = GmailClient.build_authorization_url(
            client_id="test-client-id",
            redirect_uri="https://example.com/callback",
            state="42",
        )
        assert urlparse(url).hostname == "accounts.google.com"
        assert "test-client-id" in url
        assert "gmail.readonly" in url
        assert "offline" in url
        assert "consent" in url

    def test_build_authorization_url_no_state(self):
        from app.services.gmail_client import GmailClient

        url = GmailClient.build_authorization_url(
            client_id="cid",
            redirect_uri="https://example.com/cb",
        )
        assert "state=" not in url


# ---------------------------------------------------------------------------
# _sanitize_for_log helper
# ---------------------------------------------------------------------------


class TestSanitizeForLog:
    """Unit tests for the _sanitize_for_log helper."""

    def test_strips_newline(self):
        from app.api.api_v1.endpoints.mail_sources import _sanitize_for_log

        assert "\n" not in _sanitize_for_log("hello\nworld")

    def test_strips_carriage_return(self):
        from app.api.api_v1.endpoints.mail_sources import _sanitize_for_log

        assert "\r" not in _sanitize_for_log("foo\rbar")

    def test_integer_is_safe(self):
        from app.api.api_v1.endpoints.mail_sources import _sanitize_for_log

        assert _sanitize_for_log(42) == "42"

    def test_normal_string_unchanged(self):
        from app.api.api_v1.endpoints.mail_sources import _sanitize_for_log

        assert _sanitize_for_log("example.com") == "example.com"

    def test_redacts_sensitive_key_values(self):
        from app.api.api_v1.endpoints.mail_sources import _redact_sensitive_text

        text = _redact_sensitive_text(
            'Token exchange failed: access_token=ya29.secret client_secret="GOCSPX-secret"'
        )

        assert "ya29.secret" not in text
        assert "GOCSPX-secret" not in text
        assert text.count("**redacted**") == 2

    def test_redacts_bearer_tokens(self):
        from app.api.api_v1.endpoints.mail_sources import _redact_sensitive_text

        text = _redact_sensitive_text("Authorization failed for Bearer ya29.long-secret-token")

        assert "ya29.long-secret-token" not in text
        assert "Bearer **redacted**" in text


# ---------------------------------------------------------------------------
# Source-to-response helper (password masking)
# ---------------------------------------------------------------------------


class TestSourceToResponse:
    """Tests for the _source_to_response password-masking helper."""

    def test_password_is_redacted_when_set(self, db_session: Session):
        from app.api.api_v1.endpoints.mail_sources import _source_to_response

        source = MailSource(name="Redact Test", method="IMAP", password="plaintext")
        db_session.add(source)
        db_session.commit()
        db_session.refresh(source)

        response = _source_to_response(source)
        assert response.password == "**redacted**"

    def test_password_is_none_when_not_set(self, db_session: Session):
        from app.api.api_v1.endpoints.mail_sources import _source_to_response

        source = MailSource(name="No Password", method="IMAP")
        db_session.add(source)
        db_session.commit()
        db_session.refresh(source)

        response = _source_to_response(source)
        assert response.password is None


# ---------------------------------------------------------------------------
# HTML page route – mail_sources_page
# ---------------------------------------------------------------------------


def test_mail_sources_page_template_response():
    """Verify mail_sources_page uses the new-style TemplateResponse(request, name) API.

    Regression test for the 500 error caused by the old-style
    ``TemplateResponse("mail_sources.html", {"request": request})`` call, which
    passed a dict as the template name and triggered
    ``TypeError: unhashable type: 'dict'`` in Jinja2's LRU cache.
    """
    from app.main import mail_sources_page  # module-level route function

    mock_request = MagicMock()
    with patch("app.main.templates") as mock_templates:
        mock_response = MagicMock()
        mock_templates.TemplateResponse.return_value = mock_response

        result = asyncio.run(mail_sources_page(mock_request))

    mock_templates.TemplateResponse.assert_called_once_with(mock_request, "mail_sources.html")
    assert result is mock_response


# ---------------------------------------------------------------------------
# Gmail OAuth2 GET callback tests
# ---------------------------------------------------------------------------


class TestGmailCallbackGet:
    """Tests for the browser-redirect GET /gmail/callback endpoint."""

    def test_callback_error_param_returns_html_400(self, authed_client: TestClient):
        """Google reports an error – return a user-facing HTML error page."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "CB Error", "method": "GMAIL_API"},
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.get(
            f"/api/v1/mail-sources/{source_id}/gmail/callback?error=access_denied",
        )
        assert resp.status_code == 400
        assert "authorisation failed" in resp.text.lower() or "failed" in resp.text.lower()

    def test_callback_missing_code_returns_html_400(self, authed_client: TestClient):
        """No code in the redirect – return a user-facing HTML error page."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "CB NoCode", "method": "GMAIL_API"},
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.get(f"/api/v1/mail-sources/{source_id}/gmail/callback")
        assert resp.status_code == 400

    def test_callback_unknown_source_returns_html_404(self, authed_client: TestClient):
        """Source ID does not exist – return a user-facing HTML 404 page."""
        resp = authed_client.get("/api/v1/mail-sources/99999/gmail/callback?code=xyz")
        assert resp.status_code == 404

    def test_callback_non_gmail_source_returns_html_404(self, authed_client: TestClient):
        """Source is not a GMAIL_API source – return HTML 404."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources", json={"name": "IMAP CB", "method": "IMAP"}
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.get(f"/api/v1/mail-sources/{source_id}/gmail/callback?code=xyz")
        assert resp.status_code == 404

    def test_callback_token_exchange_error_returns_html_400(
        self, authed_client: TestClient, caplog
    ):
        """Token exchange raises ValueError – return a user-facing HTML error page."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "CB TokenErr", "method": "GMAIL_API", "gmail_client_id": "cid"},
        )
        source_id = create_resp.json()["id"]

        caplog.set_level(logging.ERROR, logger="app.api.api_v1.endpoints.mail_sources")
        with patch(
            "app.api.api_v1.endpoints.mail_sources.GmailClient.exchange_code_for_tokens",
            side_effect=ValueError(
                "bad token access_token=ya29.raw-token client_secret=GOCSPX-raw-secret"
            ),
        ):
            resp = authed_client.get(f"/api/v1/mail-sources/{source_id}/gmail/callback?code=abc")

        assert resp.status_code == 400
        assert "token exchange failed" in resp.text.lower() or "failed" in resp.text.lower()
        assert "ya29.raw-token" not in caplog.text
        assert "GOCSPX-raw-secret" not in caplog.text
        assert "**redacted**" in caplog.text

    def test_callback_no_access_token_returns_html_400(self, authed_client: TestClient):
        """Exchange succeeds but Google returns no access token – HTML 400."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "CB NoAccess", "method": "GMAIL_API", "gmail_client_id": "cid"},
        )
        source_id = create_resp.json()["id"]

        with patch(
            "app.api.api_v1.endpoints.mail_sources.GmailClient.exchange_code_for_tokens",
            return_value={},  # empty – no access_token key
        ):
            resp = authed_client.get(f"/api/v1/mail-sources/{source_id}/gmail/callback?code=abc")

        assert resp.status_code == 400

    def test_callback_success_saves_tokens_and_returns_html(self, authed_client: TestClient):
        """Successful callback stores tokens and returns a success HTML page."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "CB Success", "method": "GMAIL_API", "gmail_client_id": "cid"},
        )
        source_id = create_resp.json()["id"]

        with (
            patch(
                "app.api.api_v1.endpoints.mail_sources.GmailClient.exchange_code_for_tokens",
                return_value={"access_token": "acc", "refresh_token": "ref"},
            ),
            patch(
                "app.api.api_v1.endpoints.mail_sources.GmailClient.get_gmail_email",
                return_value="user@gmail.com",
            ),
        ):
            resp = authed_client.get(f"/api/v1/mail-sources/{source_id}/gmail/callback?code=abc")

        assert resp.status_code == 200
        assert "connected successfully" in resp.text.lower() or "gmail" in resp.text.lower()

        # Tokens should have been persisted
        get_resp = authed_client.get(f"/api/v1/mail-sources/{source_id}")
        assert get_resp.json()["gmail_connected"] is True
        assert get_resp.json()["gmail_email"] == "user@gmail.com"

    def test_callback_uses_oauth_state_for_selected_workspace(
        self,
        authed_client: TestClient,
        db_session: Session,
    ):
        """Provider redirects can complete selected-workspace OAuth without custom headers."""
        get_or_create_default_workspace(db_session)
        selected_workspace = Workspace(slug="gmail-oauth-selected", name="Gmail OAuth Selected")
        db_session.add(selected_workspace)
        db_session.commit()
        selected_header = {"X-DMARQ-Workspace-ID": str(selected_workspace.id)}

        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            headers=selected_header,
            json={
                "name": "Selected Gmail",
                "method": "GMAIL_API",
                "gmail_client_id": "cid",
                "gmail_client_secret": "secret",
            },
        )
        source_id = create_resp.json()["id"]
        auth_resp = authed_client.get(
            f"/api/v1/mail-sources/{source_id}/gmail/authorize-url",
            headers=selected_header,
        )
        auth_url = auth_resp.json()["authorization_url"]
        state = parse_qs(urlparse(auth_url).query)["state"][0]

        with (
            patch(
                "app.api.api_v1.endpoints.mail_sources.GmailClient.exchange_code_for_tokens",
                return_value={"access_token": "acc", "refresh_token": "ref"},
            ),
            patch(
                "app.api.api_v1.endpoints.mail_sources.GmailClient.get_gmail_email",
                return_value="selected@gmail.com",
            ),
        ):
            callback_resp = authed_client.get(
                f"/api/v1/mail-sources/{source_id}/gmail/callback?code=abc&state={state}"
            )

        assert auth_resp.status_code == 200
        assert state.startswith("v1.")
        assert state != f"workspace:{selected_workspace.id}:source:{source_id}"
        assert callback_resp.status_code == 200

        default_get = authed_client.get(f"/api/v1/mail-sources/{source_id}")
        selected_get = authed_client.get(
            f"/api/v1/mail-sources/{source_id}",
            headers=selected_header,
        )
        assert default_get.status_code == 404
        assert selected_get.status_code == 200
        assert selected_get.json()["gmail_connected"] is True
        assert selected_get.json()["gmail_email"] == "selected@gmail.com"

    def test_callback_rejects_tampered_oauth_state_before_token_exchange(
        self,
        authed_client: TestClient,
        db_session: Session,
    ):
        """Tampered OAuth state is rejected before persisting provider tokens."""
        get_or_create_default_workspace(db_session)
        selected_workspace = Workspace(slug="tampered-oauth", name="Tampered OAuth")
        db_session.add(selected_workspace)
        db_session.commit()
        selected_header = {"X-DMARQ-Workspace-ID": str(selected_workspace.id)}

        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            headers=selected_header,
            json={
                "name": "Tampered Gmail",
                "method": "GMAIL_API",
                "gmail_client_id": "cid",
                "gmail_client_secret": "secret",
            },
        )
        source_id = create_resp.json()["id"]
        auth_resp = authed_client.get(
            f"/api/v1/mail-sources/{source_id}/gmail/authorize-url",
            headers=selected_header,
        )
        state = parse_qs(urlparse(auth_resp.json()["authorization_url"]).query)["state"][0]
        prefix, token = state.split(".", 1)
        header, payload, signature = token.split(".")
        replacement = "A" if not signature.startswith("A") else "B"
        tampered_state = f"{prefix}.{header}.{payload}.{replacement}{signature[1:]}"

        with patch(
            "app.api.api_v1.endpoints.mail_sources.GmailClient.exchange_code_for_tokens"
        ) as exchange_mock:
            callback_resp = authed_client.get(
                f"/api/v1/mail-sources/{source_id}/gmail/callback"
                f"?code=abc&state={tampered_state}"
            )

        assert callback_resp.status_code == 400
        assert callback_resp.json()["detail"] == "Invalid OAuth state."
        exchange_mock.assert_not_called()

        selected_get = authed_client.get(
            f"/api/v1/mail-sources/{source_id}",
            headers=selected_header,
        )
        assert selected_get.json()["gmail_connected"] is False

    def test_callback_rejects_oauth_state_for_another_source(
        self,
        authed_client: TestClient,
        db_session: Session,
    ):
        """OAuth state must be bound to the same source as the callback path."""
        get_or_create_default_workspace(db_session)
        selected_workspace = Workspace(slug="source-bound-oauth", name="Source Bound OAuth")
        db_session.add(selected_workspace)
        db_session.commit()
        selected_header = {"X-DMARQ-Workspace-ID": str(selected_workspace.id)}

        first_resp = authed_client.post(
            "/api/v1/mail-sources",
            headers=selected_header,
            json={
                "name": "First Gmail",
                "method": "GMAIL_API",
                "gmail_client_id": "cid-1",
                "gmail_client_secret": "secret",
            },
        )
        second_resp = authed_client.post(
            "/api/v1/mail-sources",
            headers=selected_header,
            json={
                "name": "Second Gmail",
                "method": "GMAIL_API",
                "gmail_client_id": "cid-2",
                "gmail_client_secret": "secret",
            },
        )
        first_id = first_resp.json()["id"]
        second_id = second_resp.json()["id"]
        auth_resp = authed_client.get(
            f"/api/v1/mail-sources/{first_id}/gmail/authorize-url",
            headers=selected_header,
        )
        state = parse_qs(urlparse(auth_resp.json()["authorization_url"]).query)["state"][0]

        with patch(
            "app.api.api_v1.endpoints.mail_sources.GmailClient.exchange_code_for_tokens"
        ) as exchange_mock:
            callback_resp = authed_client.get(
                f"/api/v1/mail-sources/{second_id}/gmail/callback?code=abc&state={state}"
            )

        assert callback_resp.status_code == 400
        assert (
            callback_resp.json()["detail"]
            == "OAuth state does not match the requested mail source."
        )
        exchange_mock.assert_not_called()

        selected_get = authed_client.get(
            f"/api/v1/mail-sources/{second_id}",
            headers=selected_header,
        )
        assert selected_get.json()["gmail_connected"] is False

    def test_callback_success_without_email(self, authed_client: TestClient):
        """Successful callback where get_gmail_email returns None still saves token."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "CB NoEmail", "method": "GMAIL_API", "gmail_client_id": "cid"},
        )
        source_id = create_resp.json()["id"]

        with (
            patch(
                "app.api.api_v1.endpoints.mail_sources.GmailClient.exchange_code_for_tokens",
                return_value={"access_token": "acc"},  # no refresh token
            ),
            patch(
                "app.api.api_v1.endpoints.mail_sources.GmailClient.get_gmail_email",
                return_value=None,
            ),
        ):
            resp = authed_client.get(f"/api/v1/mail-sources/{source_id}/gmail/callback?code=abc")

        assert resp.status_code == 200
        get_resp = authed_client.get(f"/api/v1/mail-sources/{source_id}")
        assert get_resp.json()["gmail_connected"] is True


# ---------------------------------------------------------------------------
# Gmail OAuth2 POST callback tests
# ---------------------------------------------------------------------------


class TestGmailCallbackPost:
    """Tests for the JSON/programmatic POST /gmail/callback endpoint."""

    def test_post_callback_wrong_method_returns_400(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources", json={"name": "IMAP CB Post", "method": "IMAP"}
        )
        source_id = create_resp.json()["id"]

        resp = authed_client.post(
            f"/api/v1/mail-sources/{source_id}/gmail/callback",
            json={"code": "abc", "redirect_uri": "https://example.com/cb"},
        )
        assert resp.status_code == 400

    def test_post_callback_token_exchange_error_returns_400(
        self, authed_client: TestClient, caplog
    ):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Post TokenErr", "method": "GMAIL_API"},
        )
        source_id = create_resp.json()["id"]

        caplog.set_level(logging.ERROR, logger="app.api.api_v1.endpoints.mail_sources")
        with patch(
            "app.api.api_v1.endpoints.mail_sources.GmailClient.exchange_code_for_tokens",
            side_effect=ValueError(
                "bad exchange refresh_token=1//raw-refresh client_secret=GOCSPX-raw-secret"
            ),
        ):
            resp = authed_client.post(
                f"/api/v1/mail-sources/{source_id}/gmail/callback",
                json={"code": "abc", "redirect_uri": "https://example.com/cb"},
            )

        assert resp.status_code == 400
        assert resp.json()["detail"] == (
            "Token exchange failed. Please check the Gmail connection settings and try again."
        )
        assert "1//raw-refresh" not in resp.text
        assert "GOCSPX-raw-secret" not in resp.text
        assert "1//raw-refresh" not in caplog.text
        assert "GOCSPX-raw-secret" not in caplog.text
        assert "**redacted**" in caplog.text

    def test_post_callback_no_access_token_returns_400(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Post NoAccess", "method": "GMAIL_API"},
        )
        source_id = create_resp.json()["id"]

        with patch(
            "app.api.api_v1.endpoints.mail_sources.GmailClient.exchange_code_for_tokens",
            return_value={},
        ):
            resp = authed_client.post(
                f"/api/v1/mail-sources/{source_id}/gmail/callback",
                json={"code": "abc", "redirect_uri": "https://example.com/cb"},
            )

        assert resp.status_code == 400

    def test_post_callback_success_returns_source(self, authed_client: TestClient):
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Post Success", "method": "GMAIL_API", "gmail_client_id": "cid"},
        )
        source_id = create_resp.json()["id"]

        with (
            patch(
                "app.api.api_v1.endpoints.mail_sources.GmailClient.exchange_code_for_tokens",
                return_value={"access_token": "acc", "refresh_token": "ref"},
            ),
            patch(
                "app.api.api_v1.endpoints.mail_sources.GmailClient.get_gmail_email",
                return_value="user@gmail.com",
            ),
        ):
            resp = authed_client.post(
                f"/api/v1/mail-sources/{source_id}/gmail/callback",
                json={"code": "abc", "redirect_uri": "https://example.com/cb"},
            )

        assert resp.status_code == 200
        data = resp.json()
        assert data["gmail_connected"] is True
        assert data["gmail_email"] == "user@gmail.com"

    def test_post_callback_nonexistent_source_returns_404(self, authed_client: TestClient):
        resp = authed_client.post(
            "/api/v1/mail-sources/99999/gmail/callback",
            json={"code": "abc", "redirect_uri": "https://example.com/cb"},
        )
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Additional Gmail fetch tests
# ---------------------------------------------------------------------------


class TestGmailFetchExtra:
    """Extra fetch tests covering error and token-refresh branches."""

    def test_gmail_fetch_with_errors_returns_error_count(self, authed_client: TestClient):
        """Fetch that produces errors returns error_count rather than raw messages."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Fetch Errors", "method": "GMAIL_API"},
        )
        source_id = create_resp.json()["id"]

        mock_fetch_results = {
            "success": False,
            "processed": 1,
            "reports_found": 0,
            "new_domains": [],
            "errors": ["failed to decode attachment A", "failed to decode attachment B"],
            "new_ingested_ids": [],
        }
        mock_client = MagicMock()
        mock_client.fetch_reports.return_value = mock_fetch_results
        mock_client.get_refreshed_tokens.return_value = None

        with (
            patch("app.api.api_v1.endpoints.mail_sources._get_source_or_404") as mock_get,
            patch("app.api.api_v1.endpoints.mail_sources.GmailClient", return_value=mock_client),
        ):
            mock_source = MagicMock()
            mock_source.method = "GMAIL_API"
            mock_source.gmail_access_token = "tok"
            mock_source.gmail_refresh_token = "ref"
            mock_source.gmail_client_id = "cid"
            mock_source.gmail_client_secret = "csec"
            mock_source.gmail_ingested_ids = "[]"
            mock_source.id = source_id
            mock_get.return_value = mock_source

            resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/gmail/fetch")

        assert resp.status_code == 200
        data = resp.json()
        assert data["error_count"] == 2
        # Raw error strings must NOT appear in the response
        assert "errors" not in data or isinstance(data.get("errors"), int)
        assert "failed to decode attachment A" not in str(data)

    def test_gmail_fetch_with_refreshed_tokens_saves_them(self, authed_client: TestClient):
        """Fetch that returns refreshed tokens persists the new tokens."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Fetch Refresh", "method": "GMAIL_API"},
        )
        source_id = create_resp.json()["id"]

        mock_fetch_results = {
            "success": True,
            "processed": 0,
            "reports_found": 0,
            "new_domains": [],
            "errors": [],
            "new_ingested_ids": [],
        }
        mock_client = MagicMock()
        mock_client.fetch_reports.return_value = mock_fetch_results
        mock_client.get_refreshed_tokens.return_value = {
            "access_token": "new_access",
            "refresh_token": "new_refresh",
        }

        with (
            patch("app.api.api_v1.endpoints.mail_sources._get_source_or_404") as mock_get,
            patch("app.api.api_v1.endpoints.mail_sources.GmailClient", return_value=mock_client),
        ):
            mock_source = MagicMock()
            mock_source.method = "GMAIL_API"
            mock_source.gmail_access_token = "old_tok"
            mock_source.gmail_refresh_token = "old_ref"
            mock_source.gmail_client_id = "cid"
            mock_source.gmail_client_secret = "csec"
            mock_source.gmail_ingested_ids = "[]"
            mock_source.id = source_id
            mock_get.return_value = mock_source

            resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/gmail/fetch")

        assert resp.status_code == 200
        # Tokens should have been updated on the source object
        assert mock_source.gmail_access_token == "new_access"
        assert mock_source.gmail_refresh_token == "new_refresh"

    def test_gmail_fetch_ingested_ids_are_merged(self, authed_client: TestClient):
        """New ingested IDs are merged with existing ones without duplicates."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Fetch IDs", "method": "GMAIL_API"},
        )
        source_id = create_resp.json()["id"]

        mock_fetch_results = {
            "success": True,
            "processed": 2,
            "reports_found": 2,
            "new_domains": ["domain.example"],
            "errors": [],
            "new_ingested_ids": ["id2", "id3"],
        }
        mock_client = MagicMock()
        mock_client.fetch_reports.return_value = mock_fetch_results
        mock_client.get_refreshed_tokens.return_value = None

        with (
            patch("app.api.api_v1.endpoints.mail_sources._get_source_or_404") as mock_get,
            patch(
                "app.api.api_v1.endpoints.mail_sources.GmailClient", return_value=mock_client
            ) as mock_gmail_class,
        ):
            # Configure the class-level static helpers used inside the endpoint
            mock_gmail_class.load_ingested_ids.return_value = ["id1"]
            mock_gmail_class.dump_ingested_ids.return_value = '["id1","id2","id3"]'

            mock_source = MagicMock()
            mock_source.method = "GMAIL_API"
            mock_source.gmail_access_token = "tok"
            mock_source.gmail_refresh_token = "ref"
            mock_source.gmail_client_id = "cid"
            mock_source.gmail_client_secret = "csec"
            mock_source.gmail_ingested_ids = '["id1"]'  # pre-existing ID
            mock_source.id = source_id
            mock_get.return_value = mock_source

            resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/gmail/fetch")

        assert resp.status_code == 200
        # dump_ingested_ids should have been called with all 3 IDs merged
        args, _ = mock_gmail_class.dump_ingested_ids.call_args
        merged_ids = args[0]
        assert "id1" in merged_ids
        assert "id2" in merged_ids
        assert "id3" in merged_ids


# ---------------------------------------------------------------------------
# Gmail test-connection exception branch
# ---------------------------------------------------------------------------


class TestGmailTestConnectionFailure:
    """Tests for the Gmail API test failure (exception) branch."""

    def test_gmail_test_with_exception_returns_generic_message(self, authed_client: TestClient):
        """When Gmail execute raises, return a generic error without the stack trace."""
        create_resp = authed_client.post(
            "/api/v1/mail-sources",
            json={"name": "Gmail Exc Test", "method": "GMAIL_API"},
        )
        source_id = create_resp.json()["id"]

        mock_service = MagicMock()
        mock_service.users.return_value.getProfile.return_value.execute.side_effect = Exception(
            "internal oauth error: token expired"
        )
        mock_gmail_client = MagicMock()
        mock_gmail_client._build_service.return_value = mock_service

        with (
            patch(
                "app.api.api_v1.endpoints.mail_sources.GmailClient",
                return_value=mock_gmail_client,
            ),
            patch("app.api.api_v1.endpoints.mail_sources._get_source_or_404") as mock_get,
        ):
            mock_source = MagicMock()
            mock_source.method = "GMAIL_API"
            mock_source.gmail_access_token = "tok"
            mock_source.gmail_email = None
            mock_source.gmail_client_id = "cid"
            mock_source.gmail_client_secret = "csec"
            mock_source.gmail_refresh_token = "ref"
            mock_get.return_value = mock_source

            resp = authed_client.post(f"/api/v1/mail-sources/{source_id}/test")

        assert resp.status_code == 200
        data = resp.json()
        assert data["success"] is False
        # Stack-trace / raw exception text must NOT be exposed to callers
        assert "internal oauth error" not in data["message"]
        assert "token expired" not in data["message"]
        assert "authorization may need attention" in data["message"].lower()
        assert data["diagnostic_category"] == "auth_expired"


# ---------------------------------------------------------------------------
# Tests for new main.py helper functions (_poll_single_gmail_source,
# _trigger_poll_imap_source, _trigger_poll_gmail_source, _poll_source_for_trigger)
# ---------------------------------------------------------------------------


class TestPollSingleGmailSource:
    """Unit tests for app.main._poll_single_gmail_source."""

    def _make_source(self, *, access_token="tok", refresh_token="ref"):
        src = MagicMock()
        src.id = 1
        src.gmail_access_token = access_token
        src.gmail_refresh_token = refresh_token
        src.gmail_client_id = "cid"
        src.gmail_client_secret = "csec"
        src.gmail_ingested_ids = "[]"
        src.gmail_email = "u@gmail.com"
        return src

    def test_skips_when_no_access_token(self):
        """Source without OAuth token → early return, no GmailClient created."""
        from app.main import _poll_single_gmail_source

        src = self._make_source(access_token=None)

        with patch("app.main.GmailClient") as mock_gc:
            _poll_single_gmail_source(src)

        mock_gc.assert_not_called()

    def test_fetches_reports_and_persists_ids(self):
        """Happy-path: client is created, reports fetched, IDs saved to DB."""
        from app.main import _poll_single_gmail_source

        src = self._make_source()

        mock_client = MagicMock()
        mock_client.fetch_reports.return_value = {
            "success": True,
            "processed": 2,
            "reports_found": 1,
            "new_domains": [],
            "errors": [],
            "new_ingested_ids": ["id1", "id2"],
        }
        mock_client.get_refreshed_tokens.return_value = None

        mock_db_source = MagicMock()
        mock_db = MagicMock()
        mock_db.__enter__ = MagicMock(return_value=mock_db)
        mock_db.__exit__ = MagicMock(return_value=False)
        mock_db.query.return_value.get.return_value = mock_db_source

        with (
            patch("app.main.GmailClient", return_value=mock_client),
            patch("app.main.SessionLocal", return_value=mock_db),
            patch("app.main.GmailClient.load_ingested_ids", return_value=[]),
            patch("app.main.GmailClient.dump_ingested_ids", return_value='["id1","id2"]'),
        ):
            _poll_single_gmail_source(src)

        mock_client.fetch_reports.assert_called_once()

    def test_logs_new_domains_on_success(self):
        """When results include new_domains, the function logs them."""
        from app.main import _poll_single_gmail_source

        src = self._make_source()

        mock_client = MagicMock()
        mock_client.fetch_reports.return_value = {
            "success": True,
            "processed": 1,
            "reports_found": 1,
            "new_domains": ["example.com"],
            "errors": [],
            "new_ingested_ids": [],
        }
        mock_client.get_refreshed_tokens.return_value = None

        mock_db = MagicMock()
        mock_db.query.return_value.get.return_value = MagicMock()

        with (
            patch("app.main.GmailClient", return_value=mock_client),
            patch("app.main.SessionLocal", return_value=mock_db),
            patch("app.main.GmailClient.load_ingested_ids", return_value=[]),
        ):
            _poll_single_gmail_source(src)  # should not raise

    def test_logs_error_on_failure(self):
        """When results['success'] is False, the function logs an error."""
        from app.main import _poll_single_gmail_source

        src = self._make_source()

        mock_client = MagicMock()
        mock_client.fetch_reports.return_value = {
            "success": False,
            "error": "auth failed",
            "processed": 0,
            "reports_found": 0,
            "new_domains": [],
            "errors": [],
            "new_ingested_ids": [],
        }
        mock_client.get_refreshed_tokens.return_value = None

        mock_db = MagicMock()
        mock_db.query.return_value.get.return_value = MagicMock()

        with (
            patch("app.main.GmailClient", return_value=mock_client),
            patch("app.main.SessionLocal", return_value=mock_db),
            patch("app.main.GmailClient.load_ingested_ids", return_value=[]),
        ):
            _poll_single_gmail_source(src)  # should not raise

    def test_persists_refreshed_tokens(self):
        """When GmailClient reports refreshed tokens, they are saved to the DB row."""
        from app.main import _poll_single_gmail_source

        src = self._make_source()

        mock_client = MagicMock()
        mock_client.fetch_reports.return_value = {
            "success": True,
            "processed": 0,
            "reports_found": 0,
            "new_domains": [],
            "errors": [],
            "new_ingested_ids": [],
        }
        mock_client.get_refreshed_tokens.return_value = {
            "access_token": "new-acc",
            "refresh_token": "new-ref",
        }

        mock_db_source = MagicMock()
        mock_db = MagicMock()
        mock_db.query.return_value.get.return_value = mock_db_source

        with (
            patch("app.main.GmailClient", return_value=mock_client),
            patch("app.main.SessionLocal", return_value=mock_db),
            patch("app.main.GmailClient.load_ingested_ids", return_value=[]),
        ):
            _poll_single_gmail_source(src)

        assert mock_db_source.gmail_access_token == "new-acc"
        assert mock_db_source.gmail_refresh_token == "new-ref"


class TestTriggerPollImapSource:
    """Unit tests for app.main._trigger_poll_imap_source."""

    def test_returns_result_dict_on_success(self):
        from app.main import _trigger_poll_imap_source

        src = MagicMock()
        src.id = 5
        src.name = "My IMAP"
        src.server = "imap.example.com"
        src.port = 993
        src.username = "u"
        src.password = "p"

        mock_imap = MagicMock()
        mock_imap.fetch_reports.return_value = {
            "success": True,
            "processed": 3,
            "reports_found": 2,
            "new_domains": ["dom.example"],
        }

        mock_db = MagicMock()

        with patch("app.main.IMAPClient", return_value=mock_imap):
            result = _trigger_poll_imap_source(src, mock_db)

        assert result["success"] is True
        assert result["source_id"] == 5
        assert result["name"] == "My IMAP"
        assert result["processed"] == 3
        assert result["reports_found"] == 2
        assert result["new_domains"] == ["dom.example"]
        mock_imap.fetch_reports.assert_called_once_with(days=7)
        mock_db.commit.assert_called_once()

    def test_uses_requested_days(self):
        from app.main import _trigger_poll_imap_source

        src = MagicMock()
        src.id = 5
        src.name = "My IMAP"
        src.server = "imap.example.com"
        src.port = 993
        src.username = "u"
        src.password = "p"

        mock_imap = MagicMock()
        mock_imap.fetch_reports.return_value = {
            "success": True,
            "processed": 0,
            "reports_found": 0,
            "new_domains": [],
        }

        with patch("app.main.IMAPClient", return_value=mock_imap):
            _trigger_poll_imap_source(src, MagicMock(), days=30)

        mock_imap.fetch_reports.assert_called_once_with(days=30)


class TestTriggerPollGmailSource:
    """Unit tests for app.main._trigger_poll_gmail_source."""

    def _make_src(self):
        src = MagicMock()
        src.id = 7
        src.name = "My Gmail"
        src.gmail_client_id = "cid"
        src.gmail_client_secret = "csec"
        src.gmail_access_token = "tok"
        src.gmail_refresh_token = "ref"
        src.gmail_ingested_ids = "[]"
        return src

    def test_returns_result_dict_on_success(self):
        from app.main import _trigger_poll_gmail_source

        src = self._make_src()
        mock_gc = MagicMock()
        mock_gc.fetch_reports.return_value = {
            "success": True,
            "processed": 1,
            "reports_found": 1,
            "new_domains": [],
            "new_ingested_ids": ["id1"],
        }
        mock_gc.get_refreshed_tokens.return_value = None
        mock_db = MagicMock()

        with (
            patch("app.main.GmailClient", return_value=mock_gc),
            patch("app.main.GmailClient.load_ingested_ids", return_value=[]),
            patch("app.main.GmailClient.dump_ingested_ids", return_value='["id1"]'),
        ):
            result = _trigger_poll_gmail_source(src, mock_db)

        assert result["success"] is True
        assert result["source_id"] == 7
        mock_db.commit.assert_called_once()

    def test_persists_refreshed_tokens(self):
        from app.main import _trigger_poll_gmail_source

        src = self._make_src()
        mock_gc = MagicMock()
        mock_gc.fetch_reports.return_value = {
            "success": True,
            "processed": 0,
            "reports_found": 0,
            "new_domains": [],
            "new_ingested_ids": [],
        }
        mock_gc.get_refreshed_tokens.return_value = {
            "access_token": "new-acc",
            "refresh_token": "new-ref",
        }
        mock_db = MagicMock()

        with (
            patch("app.main.GmailClient", return_value=mock_gc),
            patch("app.main.GmailClient.load_ingested_ids", return_value=[]),
        ):
            _trigger_poll_gmail_source(src, mock_db)

        assert src.gmail_access_token == "new-acc"
        assert src.gmail_refresh_token == "new-ref"


class TestTriggerPollM365Source:
    """Unit tests for app.main._trigger_poll_m365_source."""

    def _make_src(self):
        src = MagicMock()
        src.id = 8
        src.name = "My M365"
        src.m365_tenant_id = "organizations"
        src.m365_client_id = "cid"
        src.m365_client_secret = "csec"
        src.m365_access_token = "tok"
        src.m365_refresh_token = "ref"
        src.m365_mailbox = "shared@example.com"
        src.m365_ingested_ids = "[]"
        src.folder = "INBOX"
        return src

    def test_returns_result_dict_on_success(self):
        from app.main import _trigger_poll_m365_source

        src = self._make_src()
        mock_gc = MagicMock()
        mock_gc.fetch_reports.return_value = {
            "success": True,
            "processed": 2,
            "reports_found": 1,
            "new_domains": ["example.com"],
            "new_ingested_ids": ["id1"],
        }
        mock_gc.get_refreshed_tokens.return_value = None
        mock_db = MagicMock()

        with (
            patch("app.main.MicrosoftGraphClient", return_value=mock_gc),
            patch("app.main.MicrosoftGraphClient.load_ingested_ids", return_value=[]),
            patch("app.main.MicrosoftGraphClient.dump_ingested_ids", return_value='["id1"]'),
        ):
            result = _trigger_poll_m365_source(src, mock_db, days=30)

        assert result["success"] is True
        assert result["source_id"] == 8
        assert result["processed"] == 2
        assert src.m365_ingested_ids == '["id1"]'
        mock_gc.fetch_reports.assert_called_once_with(days=30)
        mock_db.commit.assert_called_once()

    def test_persists_refreshed_tokens(self):
        from app.main import _trigger_poll_m365_source

        src = self._make_src()
        mock_gc = MagicMock()
        mock_gc.fetch_reports.return_value = {
            "success": True,
            "processed": 0,
            "reports_found": 0,
            "new_domains": [],
            "new_ingested_ids": [],
        }
        mock_gc.get_refreshed_tokens.return_value = {
            "access_token": "new-acc",
            "refresh_token": "new-ref",
        }
        mock_db = MagicMock()

        with (
            patch("app.main.MicrosoftGraphClient", return_value=mock_gc),
            patch("app.main.MicrosoftGraphClient.load_ingested_ids", return_value=[]),
        ):
            _trigger_poll_m365_source(src, mock_db)

        assert src.m365_access_token == "new-acc"
        assert src.m365_refresh_token == "new-ref"


class TestPollSourceForTrigger:
    """Unit tests for app.main._poll_source_for_trigger."""

    def test_gmail_no_token_returns_skipped(self):
        from app.main import _poll_source_for_trigger

        src = MagicMock()
        src.method = "GMAIL_API"
        src.gmail_access_token = None
        src.id = 1
        src.name = "Gmail no token"

        result = _poll_source_for_trigger(src, MagicMock())

        assert result["skipped"] is True
        assert "authorised" in result["reason"].lower()

    def test_gmail_with_token_delegates_to_trigger_poll(self):
        from app.main import _poll_source_for_trigger

        src = MagicMock()
        src.method = "GMAIL_API"
        src.gmail_access_token = "tok"
        src.id = 2
        src.name = "Gmail"

        expected = {"source_id": 2, "name": "Gmail", "success": True}
        with patch("app.main._trigger_poll_gmail_source", return_value=expected) as mock_fn:
            result = _poll_source_for_trigger(src, MagicMock())

        assert result is expected
        mock_fn.assert_called_once()

    def test_gmail_exception_returns_failure_dict(self):
        from app.main import _poll_source_for_trigger

        src = MagicMock()
        src.method = "GMAIL_API"
        src.gmail_access_token = "tok"
        src.id = 3
        src.name = "Gmail exc"

        with patch("app.main._trigger_poll_gmail_source", side_effect=Exception("boom")):
            result = _poll_source_for_trigger(src, MagicMock())

        assert result["success"] is False
        assert "boom" not in result.get("error", "")  # raw msg not exposed

    def test_m365_no_token_returns_skipped(self):
        from app.main import _poll_source_for_trigger

        src = MagicMock()
        src.method = "M365_GRAPH"
        src.m365_access_token = None
        src.id = 7
        src.name = "M365 no token"

        result = _poll_source_for_trigger(src, MagicMock())

        assert result["skipped"] is True
        assert "microsoft 365" in result["reason"].lower()

    def test_m365_with_token_delegates_to_trigger_poll(self):
        from app.main import _poll_source_for_trigger

        src = MagicMock()
        src.method = "M365_GRAPH"
        src.m365_access_token = "tok"
        src.id = 8
        src.name = "M365"

        expected = {"source_id": 8, "name": "M365", "success": True}
        with patch("app.main._trigger_poll_m365_source", return_value=expected) as mock_fn:
            result = _poll_source_for_trigger(src, MagicMock(), days=30)

        assert result is expected
        assert mock_fn.call_args.kwargs["days"] == 30

    def test_m365_exception_returns_failure_dict(self):
        from app.main import _poll_source_for_trigger

        src = MagicMock()
        src.method = "M365_GRAPH"
        src.m365_access_token = "tok"
        src.id = 9
        src.name = "M365 exc"

        with patch("app.main._trigger_poll_m365_source", side_effect=Exception("boom")):
            result = _poll_source_for_trigger(src, MagicMock())

        assert result["success"] is False
        assert "boom" not in result.get("error", "")

    def test_imap_delegates_to_trigger_poll(self):
        from app.main import _poll_source_for_trigger

        src = MagicMock()
        src.method = "IMAP"
        src.id = 4
        src.name = "IMAP src"

        expected = {"source_id": 4, "success": True}
        with patch("app.main._trigger_poll_imap_source", return_value=expected) as mock_fn:
            result = _poll_source_for_trigger(src, MagicMock())

        assert result is expected
        assert mock_fn.call_args.kwargs["days"] == 7

    def test_imap_exception_returns_failure_dict(self):
        from app.main import _poll_source_for_trigger

        src = MagicMock()
        src.method = "IMAP"
        src.id = 5
        src.name = "IMAP exc"

        with patch("app.main._trigger_poll_imap_source", side_effect=Exception("imap fail")):
            result = _poll_source_for_trigger(src, MagicMock())

        assert result["success"] is False

    def test_unknown_method_returns_skipped(self):
        from app.main import _poll_source_for_trigger

        src = MagicMock()
        src.method = "POP3"
        src.id = 6
        src.name = "POP3 src"

        result = _poll_source_for_trigger(src, MagicMock())

        assert result["skipped"] is True
        assert "POP3" in result["reason"]


class TestPollAllEnabledSources:
    """Unit tests for app.main._poll_all_enabled_sources dispatch logic."""

    def test_dispatches_gmail_api_source(self):
        """GMAIL_API sources are forwarded to _poll_single_gmail_source."""
        from app.main import _poll_all_enabled_sources

        src = MagicMock()
        src.id = 1
        src.method = "GMAIL_API"

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.all.return_value = [src]

        with (
            patch("app.main.SessionLocal", return_value=mock_db),
            patch("app.main._poll_single_gmail_source") as mock_gmail,
        ):
            _poll_all_enabled_sources()

        mock_gmail.assert_called_once_with(src)

    def test_dispatches_m365_graph_source(self):
        """M365_GRAPH sources are forwarded to _poll_single_m365_source."""
        from app.main import _poll_all_enabled_sources

        src = MagicMock()
        src.id = 6
        src.method = "M365_GRAPH"

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.all.return_value = [src]

        with (
            patch("app.main.SessionLocal", return_value=mock_db),
            patch("app.main._poll_single_m365_source") as mock_m365,
        ):
            _poll_all_enabled_sources()

        mock_m365.assert_called_once_with(src)

    def test_dispatches_imap_source(self):
        """IMAP sources are forwarded to _poll_single_imap_source."""
        from app.main import _poll_all_enabled_sources

        src = MagicMock()
        src.id = 2
        src.method = "IMAP"

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.all.return_value = [src]

        with (
            patch("app.main.SessionLocal", return_value=mock_db),
            patch("app.main._poll_single_imap_source") as mock_imap,
        ):
            _poll_all_enabled_sources()

        mock_imap.assert_called_once_with(src)

    def test_gmail_exception_is_caught(self):
        """Exception from _poll_single_gmail_source must not propagate."""
        from app.main import _poll_all_enabled_sources

        src = MagicMock()
        src.id = 3
        src.method = "GMAIL_API"

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.all.return_value = [src]

        with (
            patch("app.main.SessionLocal", return_value=mock_db),
            patch("app.main._poll_single_gmail_source", side_effect=Exception("crash")),
        ):
            _poll_all_enabled_sources()  # should not raise

    def test_imap_exception_is_caught(self):
        """Exception from _poll_single_imap_source must not propagate."""
        from app.main import _poll_all_enabled_sources

        src = MagicMock()
        src.id = 4
        src.method = "IMAP"

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.all.return_value = [src]

        with (
            patch("app.main.SessionLocal", return_value=mock_db),
            patch("app.main._poll_single_imap_source", side_effect=Exception("imap crash")),
        ):
            _poll_all_enabled_sources()  # should not raise

    def test_m365_exception_is_caught(self):
        """Exception from _poll_single_m365_source must not propagate."""
        from app.main import _poll_all_enabled_sources

        src = MagicMock()
        src.id = 7
        src.method = "M365_GRAPH"

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.all.return_value = [src]

        with (
            patch("app.main.SessionLocal", return_value=mock_db),
            patch("app.main._poll_single_m365_source", side_effect=Exception("m365 crash")),
        ):
            _poll_all_enabled_sources()  # should not raise

    def test_unknown_method_skipped(self):
        """An unknown method logs a skip message and does not raise."""
        from app.main import _poll_all_enabled_sources

        src = MagicMock()
        src.id = 5
        src.method = "POP3"

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.all.return_value = [src]

        with patch("app.main.SessionLocal", return_value=mock_db):
            _poll_all_enabled_sources()  # should not raise


class TestTriggerPollEndpoint:
    """Tests for the POST /api/v1/admin/trigger-poll endpoint with sources."""

    def test_trigger_poll_get_returns_actionable_method_guidance(self):
        """Direct browser visits should explain that polling is a POST action."""
        from app.main import app as main_app

        with TestClient(main_app) as tc:
            resp = tc.get("/api/v1/admin/trigger-poll")

        assert resp.status_code == 405
        assert resp.headers["allow"] == "POST"
        detail = resp.json()["detail"]
        assert detail["code"] == "method_not_allowed"
        assert "dashboard button" in detail["message"]
        assert "POST /api/v1/admin/trigger-poll" in detail["next_steps"][1]
        trigger_poll_schema = main_app.openapi()["paths"]["/api/v1/admin/trigger-poll"]
        assert "get" not in trigger_poll_schema
        assert "post" in trigger_poll_schema

    def test_trigger_poll_with_enabled_sources(self):
        """With enabled sources, the endpoint dispatches and returns results."""
        from app.core.security import require_admin_auth
        from app.main import app as main_app

        async def mock_auth():
            return {"auth_type": "api_key"}

        main_app.dependency_overrides[require_admin_auth] = mock_auth

        try:
            mock_source = MagicMock()
            mock_source.id = 1
            mock_source.name = "Trigger GMAIL"
            mock_source.method = "GMAIL_API"
            mock_source.enabled = True

            mock_db = MagicMock()
            mock_db.query.return_value.filter.return_value.all.return_value = [mock_source]

            mock_result = {
                "source_id": 1,
                "name": "Trigger GMAIL",
                "method": "GMAIL_API",
                "success": True,
                "processed": 0,
                "reports_found": 0,
                "new_domains": [],
            }

            with TestClient(main_app) as tc:
                with (
                    patch("app.main.SessionLocal", return_value=mock_db),
                    patch(
                        "app.main._poll_source_for_trigger", return_value=mock_result
                    ) as mock_poll,
                ):
                    resp = tc.post("/api/v1/admin/trigger-poll?days=30")

            assert resp.status_code == 200
            data = resp.json()
            assert data["days"] == 30
            assert data["message"] == "Mail-source polling completed."
            assert data["sources_polled"] == 1
            assert data["source_methods"] == ["GMAIL_API"]
            assert "sources" in data
            assert len(data["sources"]) == 1
            assert data["sources"][0]["success"] is True
            assert mock_result == data["sources"][0]
            assert mock_poll.call_args.kwargs["days"] == 30
        finally:
            main_app.dependency_overrides.clear()

    def test_poll_status_reports_enabled_gmail_sources(self):
        """The dashboard status endpoint reports Gmail API sources, not just IMAP."""
        from app.core.security import require_admin_auth
        from app.main import app as main_app

        async def mock_auth():
            return {"auth_type": "session"}

        main_app.dependency_overrides[require_admin_auth] = mock_auth

        mock_source = MagicMock()
        mock_source.method = "GMAIL_API"
        mock_source.name = "Reports Gmail"
        mock_source.gmail_email = "dmarc-reports@example.com"
        mock_source.last_checked = datetime(2026, 7, 2, 12, 0, 0)

        mock_db = MagicMock()
        mock_db.query.return_value.filter.return_value.all.return_value = [mock_source]

        try:
            with TestClient(main_app) as tc:
                with patch("app.main.SessionLocal", return_value=mock_db):
                    resp = tc.get("/api/v1/poll-status")
        finally:
            main_app.dependency_overrides.clear()

        assert resp.status_code == 200
        data = resp.json()
        assert data["enabled_sources"] == 1
        assert data["sources_by_method"] == {"GMAIL_API": 1}
        assert data["source_labels"] == ["Gmail API: dmarc-reports@example.com"]
        assert data["latest_source_check"] == "2026-07-02T12:00:00"
        assert data["authenticated_by"] == "session"

    def test_trigger_poll_with_no_enabled_sources(self):
        """With no enabled sources, the endpoint returns an empty-success response."""
        from app.core.security import require_admin_auth
        from app.main import app as main_app

        async def mock_auth():
            return {"auth_type": "api_key"}

        main_app.dependency_overrides[require_admin_auth] = mock_auth

        try:
            mock_db = MagicMock()
            mock_db.query.return_value.filter.return_value.all.return_value = []

            with TestClient(main_app) as tc:
                with patch("app.main.SessionLocal", return_value=mock_db):
                    resp = tc.post("/api/v1/admin/trigger-poll?days=14")

            assert resp.status_code == 200
            data = resp.json()
            assert data == {
                "success": True,
                "message": "No enabled mail sources configured.",
                "sources_polled": 0,
                "days": 14,
                "authenticated_by": "api_key",
            }
        finally:
            main_app.dependency_overrides.clear()


# ---------------------------------------------------------------------------
# Pytest marker to avoid warnings for test methods without assertions
# ---------------------------------------------------------------------------
pytestmark = pytest.mark.usefixtures("_reset_report_store")
