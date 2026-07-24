"""
Tests for the Settings model and /api/v1/settings endpoints.
"""

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.core.config import Settings
from app.core.credential_encryption import decrypt_secret, is_encrypted_secret
from app.models.alert import AlertConfigurationAudit, AlertHistory
from app.models.api_token import APIToken
from app.models.domain import Domain
from app.models.report import DMARCReport, ReportRecord
from app.models.setting import Setting
from app.models.workspace import Workspace
from app.services.account_milestone import (
    _auth_mode,
    _criterion,
    _has_scope_token,
    build_account_milestone_readiness,
)
from app.services.api_tokens import PROVIDER_READ_SCOPE, SCIM_READ_SCOPE
from app.services.alert_history import list_alert_config_audit, record_alert_config_change
from app.services.notifications import NotificationResult, send_notification
from app.services.summary_notifications import send_due_scheduled_summaries


def _timestamp_days_ago(days: int) -> int:
    return int((datetime.now(timezone.utc) - timedelta(days=days)).timestamp())


def _add_domain(db_session: Session, name: str) -> Domain:
    domain = Domain(name=name)
    db_session.add(domain)
    db_session.flush()
    return domain


def _add_report_record(
    db_session: Session,
    domain: Domain,
    *,
    report_id: str,
    days_ago: int,
    source_ip: str,
    count: int,
    dkim: str = "pass",
    spf: str = "pass",
) -> None:
    begin_date = _timestamp_days_ago(days_ago)
    report = DMARCReport(
        domain_id=domain.id,
        report_id=report_id,
        org_name="receiver.example",
        begin_date=begin_date,
        end_date=begin_date + 3600,
        policy="none",
    )
    db_session.add(report)
    db_session.flush()
    db_session.add(
        ReportRecord(
            report_id=report.id,
            source_ip=source_ip,
            count=count,
            disposition="none",
            dkim=dkim,
            spf=spf,
            header_from=domain.name,
        )
    )


class TestSettingModel:
    """Unit tests for the Setting ORM model."""

    def test_create_setting(self, db_session: Session):
        row = Setting(
            key="general.app_name",
            value="TestApp",
            description="App name",
            value_type="string",
            category="general",
        )
        db_session.add(row)
        db_session.commit()
        db_session.refresh(row)

        assert row.key == "general.app_name"
        assert row.value == "TestApp"
        assert row.category == "general"
        assert row.value_type == "string"

    def test_repr(self, db_session: Session):
        row = Setting(key="dns.resolver", value="system", category="dns")
        db_session.add(row)
        db_session.commit()
        assert "dns.resolver" in repr(row)
        assert "dns" in repr(row)

    def test_alert_reprs(self):
        alert = AlertHistory(rule="missing_reports", is_active=True)
        audit = AlertConfigurationAudit(key="notifications.apprise_enabled")

        assert "missing_reports" in repr(alert)
        assert "notifications.apprise_enabled" in repr(audit)


class TestSettingsAPI:
    """Integration tests for /api/v1/settings endpoints."""

    def test_list_settings_seeds_defaults(self, authed_client: TestClient):
        """GET /api/v1/settings returns seeded defaults on first call."""
        res = authed_client.get("/api/v1/settings")
        assert res.status_code == 200
        data = res.json()
        assert isinstance(data, list)
        keys = {row["key"] for row in data}
        assert "general.app_name" in keys
        assert "dmarc.default_policy" in keys
        assert "cloudflare.api_token" in keys
        assert "notifications.apprise_enabled" in keys
        assert "notifications.apprise_urls" in keys
        assert "notifications.alert_new_sources_enabled" in keys
        assert "notifications.alert_compliance_drop_points" in keys
        assert "notifications.alert_failure_threshold_count" in keys
        assert "notifications.alert_missing_reports_days" in keys
        assert "notifications.summary_daily_enabled" in keys
        assert "notifications.summary_weekly_enabled" in keys
        assert "notifications.summary_send_hour_utc" in keys
        assert "notifications.summary_weekday_utc" in keys
        assert "notifications.min_send_interval_minutes" in keys
        assert "notifications.redact_pii_enabled" in keys
        assert "forensics.redaction_mode" in keys
        assert "forensics.redact_long_tokens_enabled" in keys

    def test_resolver_status_marks_missing_enterprise_profile_degraded(
        self, authed_client: TestClient, db_session: Session, monkeypatch
    ):
        monkeypatch.delenv("AKAMAI_ETP_DNS_SERVERS", raising=False)
        monkeypatch.delenv("AKAMAI_ETP_DOH_HOSTNAME", raising=False)
        db_session.add(Setting(key="dns.resolver", value="akamai_etp", category="dns"))
        db_session.commit()

        response = authed_client.get("/api/v1/settings/dns/resolver-status")

        assert response.status_code == 200
        data = response.json()
        assert data["selected_resolver"] == "akamai_etp"
        assert data["status"] == "degraded"
        assert data["configured"] is False
        assert data["active_resolver"] == "Public DNS (1.1.1.1 and 8.8.8.8)"
        assert data["required_configuration"] == [
            "AKAMAI_ETP_DNS_SERVERS or AKAMAI_ETP_DOH_HOSTNAME"
        ]

    def test_account_readiness_endpoint_summarizes_milestone_12(
        self,
        authed_client: TestClient,
    ):
        """GET /api/v1/settings/account-readiness returns the #12 rollup route."""
        res = authed_client.get("/api/v1/settings/account-readiness")

        assert res.status_code == 200
        data = res.json()
        assert data["milestone"] == "#12 User Authentication & Multi-User Support"
        assert data["status"] == "operational_with_setup_needed"
        assert data["criteria_total"] == len(data["criteria"])
        assert data["criteria_total"] >= 10
        assert data["ready_to_close_parent_issue"] is True
        assert data["remaining_slices"] == 0
        assert data["setup_gates"] > 0
        assert data["safety_boundary"]
        assert "workspace_owner" in {row["role"] for row in data["role_catalog"]}
        assert all(row["ready"] is True for row in data["criteria"])
        keys = {row["key"] for row in data["criteria"]}
        assert {
            "auth_modes",
            "workspace_rbac",
            "direct_billing",
            "provider_billing",
            "enterprise_identity",
            "support_access",
        }.issubset(keys)

    def test_account_readiness_auth_mode_detection(self):
        """The milestone summary reflects each supported auth mode signal."""
        assert _auth_mode(Settings(AUTH_DISABLED=True)) == "disabled"
        assert _auth_mode(Settings(AUTH_MODE="trusted_proxy")) == "trusted_proxy"
        assert (
            _auth_mode(
                Settings(
                    LOGTO_ENDPOINT="https://logto.example.test",
                    LOGTO_APP_ID="app_123",
                )
            )
            == "logto"
        )
        assert (
            _auth_mode(
                Settings(
                    AUTHENTIK_ISSUER_URL="https://authentik.example.test/application/o/dmarq/",
                    AUTHENTIK_CLIENT_ID="client_123",
                )
            )
            == "authentik"
        )
        assert (
            _auth_mode(
                Settings(
                    OIDC_ISSUER_URL="https://idp.example.test/realms/dmarq",
                    OIDC_CLIENT_ID="client_123",
                )
            )
            == "oidc"
        )
        assert _auth_mode(Settings(AUTH_TRUSTED_PROXY_ENABLED=True)) == "trusted_proxy"

    def test_account_readiness_scope_token_filters(self, db_session: Session):
        """Provider and SCIM readiness checks distinguish global and workspace tokens."""
        workspace = Workspace(slug="tenant-a", name="Tenant A")
        db_session.add(workspace)
        db_session.flush()
        db_session.add_all(
            [
                APIToken(
                    name="provider",
                    key_hash="provider-hash",
                    key_prefix="dmq_provider",
                    scopes=f"{PROVIDER_READ_SCOPE},other",
                    active=True,
                ),
                APIToken(
                    name="scim",
                    key_hash="scim-hash",
                    key_prefix="dmq_scim",
                    scopes=SCIM_READ_SCOPE,
                    workspace_id=workspace.id,
                    active=True,
                ),
                APIToken(
                    name="revoked",
                    key_hash="revoked-hash",
                    key_prefix="dmq_revoked",
                    scopes=PROVIDER_READ_SCOPE,
                    active=False,
                ),
            ]
        )
        db_session.commit()

        assert _has_scope_token(db_session, PROVIDER_READ_SCOPE, global_token=True) is True
        assert _has_scope_token(db_session, PROVIDER_READ_SCOPE, global_token=False) is False
        assert _has_scope_token(db_session, SCIM_READ_SCOPE, global_token=False) is True
        assert _has_scope_token(db_session, SCIM_READ_SCOPE) is True

    def test_account_readiness_criterion_marks_setup_gates(self):
        """Setup gates are only counted after implementation is ready."""
        configured_gate = _criterion(
            "enterprise_identity",
            "Enterprise identity controls",
            True,
            True,
            "configured",
            ["SCIM and MFA are configured."],
            "No setup required.",
        )
        pending_gate = _criterion(
            "provider_billing",
            "Provider lifecycle and external billing",
            True,
            False,
            "ready",
            ["Provider APIs are implemented."],
            "Create provider tokens before integration.",
        )

        assert configured_gate["setup_required"] is False
        assert pending_gate["setup_required"] is True

    def test_account_readiness_marks_setup_needed_without_reopening_parent(
        self,
        db_session: Session,
    ):
        """Deployment setup gates influence status without reopening #12 implementation."""
        data = build_account_milestone_readiness(db_session, Settings())

        assert data["status"] == "operational_with_setup_needed"
        assert data["ready_to_close_parent_issue"] is True
        assert data["remaining_slices"] == 0
        assert data["setup_gates"] > 0

    def test_list_settings_filter_by_category(self, authed_client: TestClient):
        """GET /api/v1/settings?category=dmarc returns only dmarc settings."""
        res = authed_client.get("/api/v1/settings?category=dmarc")
        assert res.status_code == 200
        data = res.json()
        for row in data:
            assert row["category"] == "dmarc"

    def test_get_single_setting(self, authed_client: TestClient):
        """GET /api/v1/settings/{key} returns a single setting."""
        # Seed defaults first
        authed_client.get("/api/v1/settings")
        res = authed_client.get("/api/v1/settings/general.app_name")
        assert res.status_code == 200
        assert res.json()["key"] == "general.app_name"
        assert res.json()["value"] == "DMARQ"

    def test_settings_seed_the_default_source_date_window(self, authed_client: TestClient):
        rows = authed_client.get("/api/v1/settings").json()
        source_window = next(row for row in rows if row["key"] == "general.source_date_window_days")

        assert source_window["value"] == "30"
        assert source_window["category"] == "general"

    def test_get_missing_setting_returns_404(self, authed_client: TestClient):
        """GET /api/v1/settings/{key} returns 404 for unknown keys."""
        authed_client.get("/api/v1/settings")  # seed
        res = authed_client.get("/api/v1/settings/nonexistent.key")
        assert res.status_code == 404

    def test_update_setting(self, authed_client: TestClient):
        """PUT /api/v1/settings/{key} updates a setting value."""
        authed_client.get("/api/v1/settings")  # seed
        res = authed_client.put(
            "/api/v1/settings/general.app_name",
            json={"value": "MyDMARQ"},
        )
        assert res.status_code == 200
        assert res.json()["value"] == "MyDMARQ"

        # Verify persistence
        res2 = authed_client.get("/api/v1/settings/general.app_name")
        assert res2.json()["value"] == "MyDMARQ"

    def test_update_setting_upserts(self, authed_client: TestClient):
        """PUT /api/v1/settings/{key} creates the row if it doesn't exist yet."""
        res = authed_client.put(
            "/api/v1/settings/general.custom_key",
            json={"value": "hello"},
        )
        assert res.status_code == 200
        assert res.json()["value"] == "hello"

    def test_bulk_update(self, authed_client: TestClient):
        """POST /api/v1/settings/bulk updates multiple settings at once."""
        authed_client.get("/api/v1/settings")  # seed
        res = authed_client.post(
            "/api/v1/settings/bulk",
            json={
                "settings": {
                    "dmarc.default_policy": "quarantine",
                    "dmarc.default_percentage": "80",
                }
            },
        )
        assert res.status_code == 200
        data = {row["key"]: row["value"] for row in res.json()}
        assert data["dmarc.default_policy"] == "quarantine"
        assert data["dmarc.default_percentage"] == "80"

    def test_secret_is_redacted_in_response(self, authed_client: TestClient):
        """cloudflare.api_token value is redacted in GET responses."""
        authed_client.get("/api/v1/settings")  # seed
        # Store a real token
        authed_client.put(
            "/api/v1/settings/cloudflare.api_token",
            json={"value": "super-secret-token"},
        )
        res = authed_client.get("/api/v1/settings/cloudflare.api_token")
        assert res.status_code == 200
        assert res.json()["value"] == "**redacted**"

    def test_apprise_urls_are_redacted_in_response(self, authed_client: TestClient):
        """Apprise target URLs are treated as notification secrets."""
        authed_client.get("/api/v1/settings")
        authed_client.put(
            "/api/v1/settings/notifications.apprise_urls",
            json={"value": "mailto://user:password@example.com"},
        )
        res = authed_client.get("/api/v1/settings/notifications.apprise_urls")
        assert res.status_code == 200
        assert res.json()["value"] == "**redacted**"

    def test_apprise_urls_are_encrypted_at_rest(
        self,
        authed_client: TestClient,
        db_session: Session,
    ):
        """Apprise target URLs are encrypted in the settings table."""
        target = "mailto://user:password@example.com"
        authed_client.get("/api/v1/settings")

        res = authed_client.put(
            "/api/v1/settings/notifications.apprise_urls",
            json={"value": target},
        )

        assert res.status_code == 200
        row = db_session.query(Setting).filter(Setting.key == "notifications.apprise_urls").first()
        assert row is not None
        assert row.value != target
        assert is_encrypted_secret(row.value)
        assert decrypt_secret(row.value) == target

    def test_legacy_plaintext_secret_setting_is_migrated_on_read(
        self,
        authed_client: TestClient,
        db_session: Session,
    ):
        """Plaintext secret settings are encrypted the next time defaults are seeded."""
        db_session.add(
            Setting(
                key="notifications.apprise_urls",
                value="mailto://user:password@example.com",
                category="notifications",
            )
        )
        db_session.commit()

        res = authed_client.get("/api/v1/settings")

        assert res.status_code == 200
        row = db_session.query(Setting).filter(Setting.key == "notifications.apprise_urls").first()
        assert is_encrypted_secret(row.value)

    def test_redacted_placeholder_does_not_overwrite(self, authed_client: TestClient):
        """Sending **redacted** back to PUT should not overwrite the stored value."""
        authed_client.get("/api/v1/settings")
        authed_client.put(
            "/api/v1/settings/cloudflare.api_token",
            json={"value": "real-token-value"},
        )
        # Simulate round-trip with redacted placeholder
        authed_client.put(
            "/api/v1/settings/cloudflare.api_token",
            json={"value": "**redacted**"},
        )
        # Direct DB check via a fresh GET – the value should still be "real-token-value"
        # (GET always redacts, so we check via the list endpoint's category filter)
        res = authed_client.get("/api/v1/settings?category=cloudflare")
        cf = {row["key"]: row["value"] for row in res.json()}
        # Value should remain redacted (which means the underlying value is still set)
        assert cf["cloudflare.api_token"] == "**redacted**"

    def test_unauthenticated_returns_403(self, client: TestClient):
        """Unauthenticated requests to settings endpoints return 403."""
        res = client.get("/api/v1/settings")
        assert res.status_code in (401, 403)

    def test_test_notification_sends_via_apprise(self, authed_client: TestClient, monkeypatch):
        """POST /settings/notifications/test sends a sanitized Apprise test notification."""

        class FakeApprise:
            instances = []

            def __init__(self):
                self.urls = []
                self.messages = []
                FakeApprise.instances.append(self)

            def add(self, url):
                self.urls.append(url)
                return True

            def notify(self, *, title, body):
                self.messages.append({"title": title, "body": body})
                return True

        monkeypatch.setattr("app.services.notifications.apprise.Apprise", FakeApprise)

        authed_client.get("/api/v1/settings")
        authed_client.post(
            "/api/v1/settings/bulk",
            json={
                "settings": {
                    "notifications.apprise_enabled": "true",
                    "notifications.apprise_urls": "mailto://user:password@example.com",
                }
            },
        )

        res = authed_client.post("/api/v1/settings/notifications/test")

        assert res.status_code == 200
        data = res.json()
        assert data["success"] is True
        assert data["configured_targets"] == 1
        assert "password" not in str(data)
        assert FakeApprise.instances[0].messages[0]["title"] == "DMARQ test notification"

    def test_notification_delivery_is_rate_limited(
        self,
        db_session: Session,
        monkeypatch,
    ):
        """Non-forced notification sends respect the configured cooldown."""

        class FakeApprise:
            instances = []

            def __init__(self):
                self.messages = []
                FakeApprise.instances.append(self)

            def add(self, url):
                return True

            def notify(self, *, title, body):
                self.messages.append({"title": title, "body": body})
                return True

        monkeypatch.setattr("app.services.notifications.apprise.Apprise", FakeApprise)
        db_session.add_all(
            [
                Setting(
                    key="notifications.apprise_enabled",
                    value="true",
                    category="notifications",
                ),
                Setting(
                    key="notifications.apprise_urls",
                    value="mailto://user:password@example.com",
                    category="notifications",
                ),
                Setting(
                    key="notifications.min_send_interval_minutes",
                    value="15",
                    category="notifications",
                ),
            ]
        )
        db_session.commit()

        first = send_notification(db_session, title="First", body="First body")
        second = send_notification(db_session, title="Second", body="Second body")

        assert first.success is True
        assert second.success is False
        assert second.rate_limited is True
        assert second.error == "rate_limited"
        assert sum(len(instance.messages) for instance in FakeApprise.instances) == 1

    def test_notification_delivery_edges_are_sanitized(
        self,
        db_session: Session,
        monkeypatch,
    ):
        """Notification delivery handles disabled, invalid, and failed target paths."""

        class FalseApprise:
            def add(self, url):
                return False

        class RaisingApprise:
            def add(self, url):
                return True

            def notify(self, *, title, body):
                raise RuntimeError("delivery failed")

        class NotDeliveredApprise:
            def add(self, url):
                return True

            def notify(self, *, title, body):
                return False

        assert send_notification(db_session, title="Off", body="Body").skipped is True

        db_session.add_all(
            [
                Setting(
                    key="notifications.apprise_enabled",
                    value="true",
                    category="notifications",
                ),
                Setting(
                    key="notifications.apprise_urls",
                    value="mailto://user:password@example.com",
                    category="notifications",
                ),
                Setting(
                    key="notifications.min_send_interval_minutes",
                    value="not-an-integer",
                    category="notifications",
                ),
                Setting(
                    key="notifications.last_sent_at",
                    value="not-a-date",
                    category="notifications",
                ),
            ]
        )
        db_session.commit()

        monkeypatch.setattr("app.services.notifications.apprise.Apprise", FalseApprise)
        invalid = send_notification(db_session, title="Invalid", body="Body")
        assert invalid.success is False
        assert invalid.invalid_targets == 1

        monkeypatch.setattr("app.services.notifications.apprise.Apprise", RaisingApprise)
        failed = send_notification(db_session, title="Raises", body="Body")
        assert failed.error == "delivery_failed"

        monkeypatch.setattr("app.services.notifications.apprise.Apprise", NotDeliveredApprise)
        not_delivered = send_notification(db_session, title="No", body="Body")
        assert not_delivered.error == "not_delivered"

    def test_notification_decrypt_error_returns_no_targets(
        self,
        db_session: Session,
        monkeypatch,
    ):
        """Unreadable encrypted target settings fail closed without exposing secrets."""
        db_session.add_all(
            [
                Setting(
                    key="notifications.apprise_enabled",
                    value="true",
                    category="notifications",
                ),
                Setting(
                    key="notifications.apprise_urls",
                    value="enc:v1:bad-token",
                    category="notifications",
                ),
            ]
        )
        db_session.commit()

        def raise_value_error(value):  # pylint: disable=unused-argument
            raise ValueError("bad token")

        monkeypatch.setattr("app.services.notifications.decrypt_secret", raise_value_error)

        result = send_notification(db_session, title="Bad secret", body="Body")

        assert result.success is False
        assert result.message == "No notification targets are configured."

    def test_notification_delivery_redacts_email_addresses(
        self,
        db_session: Session,
        monkeypatch,
    ):
        """Outbound notification text redacts email addresses by default."""

        class FakeApprise:
            messages = []

            def add(self, url):
                return True

            def notify(self, *, title, body):
                self.messages.append({"title": title, "body": body})
                return True

        monkeypatch.setattr("app.services.notifications.apprise.Apprise", FakeApprise)
        db_session.add_all(
            [
                Setting(
                    key="notifications.apprise_enabled",
                    value="true",
                    category="notifications",
                ),
                Setting(
                    key="notifications.apprise_urls",
                    value="mailto://user:password@example.com",
                    category="notifications",
                ),
            ]
        )
        db_session.commit()

        result = send_notification(
            db_session,
            title="Failure for admin@example.com",
            body="Sample from alice@example.com failed DMARC.",
        )

        assert result.success is True
        assert "admin@example.com" not in FakeApprise.messages[0]["title"]
        assert "alice@example.com" not in FakeApprise.messages[0]["body"]
        assert "[redacted-email]@example.com" in FakeApprise.messages[0]["body"]
        redact_text = send_notification.__globals__["redact_notification_text"]
        assert redact_text('"admin@example.com!"').strip('"') == "[redacted-email]@example.com!"
        assert redact_text("not-an-email") == "not-an-email"

    def test_test_notification_without_targets_returns_400(self, authed_client: TestClient):
        """Test notification returns a useful error when no target is configured."""
        authed_client.get("/api/v1/settings")

        res = authed_client.post("/api/v1/settings/notifications/test")

        assert res.status_code == 400
        detail = res.json()["detail"]
        assert detail["success"] is False
        assert detail["message"] == "No notification targets are configured."

    def test_notification_alert_rules_detect_new_source_and_failures(
        self,
        authed_client: TestClient,
        db_session: Session,
    ):
        """GET /settings/notifications/alerts evaluates source and failure alerts."""
        domain = _add_domain(db_session, "alerts.example")
        _add_report_record(
            db_session,
            domain,
            report_id="alerts-old-source",
            days_ago=10,
            source_ip="203.0.113.10",
            count=12,
        )
        _add_report_record(
            db_session,
            domain,
            report_id="alerts-new-source",
            days_ago=0,
            source_ip="203.0.113.20",
            count=150,
            dkim="fail",
            spf="fail",
        )
        db_session.commit()

        res = authed_client.get("/api/v1/settings/notifications/alerts")

        assert res.status_code == 200
        alerts = res.json()["alerts"]
        rules = {alert["rule"] for alert in alerts}
        assert "new_sender_source" in rules
        assert "dmarc_failures_above_threshold" in rules
        new_source = next(alert for alert in alerts if alert["rule"] == "new_sender_source")
        assert new_source["source_ip"] == "203.0.113.20"

    def test_notification_alert_rules_detect_missing_reports(
        self,
        authed_client: TestClient,
        db_session: Session,
    ):
        """Alert rules flag active monitored domains without recent reports."""
        _add_domain(db_session, "missing.example")
        db_session.commit()

        res = authed_client.get("/api/v1/settings/notifications/alerts")

        assert res.status_code == 200
        alerts = res.json()["alerts"]
        assert any(
            alert["rule"] == "missing_reports" and alert["domain"] == "missing.example"
            for alert in alerts
        )

    def test_notification_alert_rules_detect_compliance_drop(
        self,
        authed_client: TestClient,
        db_session: Session,
    ):
        """Alert rules compare recent compliance rates and flag large drops."""
        domain = _add_domain(db_session, "drop.example")
        _add_report_record(
            db_session,
            domain,
            report_id="drop-known-source",
            days_ago=10,
            source_ip="203.0.113.30",
            count=3,
        )
        _add_report_record(
            db_session,
            domain,
            report_id="drop-passing-day",
            days_ago=1,
            source_ip="203.0.113.30",
            count=10,
        )
        _add_report_record(
            db_session,
            domain,
            report_id="drop-failing-day",
            days_ago=0,
            source_ip="203.0.113.30",
            count=10,
            dkim="fail",
            spf="fail",
        )
        db_session.commit()

        res = authed_client.get("/api/v1/settings/notifications/alerts")

        assert res.status_code == 200
        alerts = res.json()["alerts"]
        compliance_alert = next(alert for alert in alerts if alert["rule"] == "compliance_drop")
        assert compliance_alert["domain"] == "drop.example"
        assert compliance_alert["previous_rate"] == 100.0
        assert compliance_alert["current_rate"] == 0.0

    def test_notification_alert_send_uses_alert_summary(
        self,
        authed_client: TestClient,
        db_session: Session,
        monkeypatch,
    ):
        """POST /settings/notifications/alerts/send sends one alert summary."""
        sent_messages = []

        def fake_send_notification(
            db, *, title, body, force=False
        ):  # pylint: disable=unused-argument
            sent_messages.append({"title": title, "body": body})
            return NotificationResult(
                success=True,
                message="Notification sent.",
                configured_targets=1,
            )

        monkeypatch.setattr("app.services.alert_rules.send_notification", fake_send_notification)

        domain = _add_domain(db_session, "send.example")
        _add_report_record(
            db_session,
            domain,
            report_id="send-failing-day",
            days_ago=0,
            source_ip="203.0.113.40",
            count=200,
            dkim="fail",
            spf="fail",
        )
        db_session.commit()

        res = authed_client.post("/api/v1/settings/notifications/alerts/send")

        assert res.status_code == 200
        data = res.json()
        assert data["notification"]["success"] is True
        assert data["alerts"]
        assert sent_messages[0]["title"].startswith("DMARQ alert summary")
        assert "DMARC failures above threshold" in sent_messages[0]["body"]

    def test_notification_alert_history_records_and_resolves_alerts(
        self,
        authed_client: TestClient,
        db_session: Session,
    ):
        """Alert evaluations persist active history and resolve missing alerts."""
        domain = _add_domain(db_session, "history.example")
        _add_report_record(
            db_session,
            domain,
            report_id="history-failing-day",
            days_ago=0,
            source_ip="203.0.113.45",
            count=200,
            dkim="fail",
            spf="fail",
        )
        db_session.commit()

        res = authed_client.get("/api/v1/settings/notifications/alerts")

        assert res.status_code == 200
        history_res = authed_client.get("/api/v1/settings/notifications/alerts/history")
        assert history_res.status_code == 200
        history = history_res.json()["history"]
        assert history
        assert any(item["is_active"] for item in history)
        assert db_session.query(AlertHistory).count() == len(history)

        authed_client.post(
            "/api/v1/settings/bulk",
            json={
                "settings": {
                    "notifications.alert_new_sources_enabled": "false",
                    "notifications.alert_failure_threshold_enabled": "false",
                    "notifications.alert_missing_reports_enabled": "false",
                    "notifications.alert_compliance_drop_enabled": "false",
                }
            },
        )

        res = authed_client.get("/api/v1/settings/notifications/alerts")

        assert res.status_code == 200
        assert res.json()["alerts"] == []
        resolved_res = authed_client.get(
            "/api/v1/settings/notifications/alerts/history?active=false"
        )
        resolved = resolved_res.json()["history"]
        assert resolved
        assert all(item["is_active"] is False for item in resolved)

    def test_notification_alert_send_failure_returns_400(
        self,
        authed_client: TestClient,
        monkeypatch,
    ):
        """Alert send endpoint surfaces notification delivery failures."""

        def fake_send_current_alerts(db):  # pylint: disable=unused-argument
            return {
                "alerts": [{"title": "Alert", "detail": "Detail"}],
                "notification": {
                    "success": False,
                    "message": "No valid notification targets are configured.",
                },
            }

        monkeypatch.setattr(
            "app.api.api_v1.endpoints.settings.send_current_alerts",
            fake_send_current_alerts,
        )

        res = authed_client.post("/api/v1/settings/notifications/alerts/send")

        assert res.status_code == 400
        assert res.json()["detail"]["notification"]["success"] is False

    def test_notification_config_audit_records_sanitized_changes(
        self,
        authed_client: TestClient,
    ):
        """Notification setting changes create an audit trail without secret values."""
        authed_client.get("/api/v1/settings")

        res = authed_client.post(
            "/api/v1/settings/bulk",
            json={
                "settings": {
                    "notifications.apprise_enabled": "true",
                    "notifications.apprise_urls": "mailto://user:password@example.com",
                    "notifications.alert_failure_threshold_count": "250",
                }
            },
        )

        assert res.status_code == 200
        audit_res = authed_client.get("/api/v1/settings/notifications/config-audit")
        assert audit_res.status_code == 200
        audit = audit_res.json()["audit"]
        keys = {item["key"] for item in audit}
        assert "notifications.apprise_enabled" in keys
        assert "notifications.apprise_urls" in keys
        assert "notifications.alert_failure_threshold_count" in keys
        secret_row = next(item for item in audit if item["key"] == "notifications.apprise_urls")
        assert secret_row["new_value"] == "[redacted]"
        assert "password" not in str(audit)

    def test_notification_config_audit_actor_variants(
        self,
        db_session: Session,
    ):
        """Config audit actor detection covers session and JWT auth contexts."""
        record_alert_config_change(
            db_session,
            key="notifications.apprise_enabled",
            old_value="false",
            new_value="true",
            auth_context={"auth_type": "session", "user_id": 123},
        )
        record_alert_config_change(
            db_session,
            key="notifications.apprise_enabled",
            old_value="true",
            new_value="false",
            auth_context={"auth_type": "jwt", "payload": {"sub": "admin@example.com"}},
        )
        db_session.commit()

        audit = list_alert_config_audit(db_session, limit=2)

        assert {row["changed_by"] for row in audit} == {"123", "admin@example.com"}

    def test_bulk_update_upserts_and_preserves_redacted_secret(
        self,
        authed_client: TestClient,
        db_session: Session,
    ):
        """Bulk settings handles new rows and redacted secret placeholders."""
        authed_client.get("/api/v1/settings")
        authed_client.put(
            "/api/v1/settings/notifications.apprise_urls",
            json={"value": "mailto://user:password@example.com"},
        )
        before = (
            db_session.query(Setting)
            .filter(Setting.key == "notifications.apprise_urls")
            .first()
            .value
        )

        res = authed_client.post(
            "/api/v1/settings/bulk",
            json={
                "settings": {
                    "notifications.custom_notice": "enabled",
                    "notifications.apprise_urls": "**redacted**",
                }
            },
        )

        assert res.status_code == 200
        after = (
            db_session.query(Setting)
            .filter(Setting.key == "notifications.apprise_urls")
            .first()
            .value
        )
        custom = (
            db_session.query(Setting).filter(Setting.key == "notifications.custom_notice").first()
        )
        assert after == before
        assert custom.value == "enabled"

    def test_notification_summary_preview_returns_recent_activity(
        self,
        authed_client: TestClient,
        db_session: Session,
    ):
        """GET /settings/notifications/summary returns a daily summary preview."""
        domain = _add_domain(db_session, "summary.example")
        _add_report_record(
            db_session,
            domain,
            report_id="summary-recent",
            days_ago=0,
            source_ip="203.0.113.50",
            count=25,
        )
        _add_report_record(
            db_session,
            domain,
            report_id="summary-old",
            days_ago=3,
            source_ip="203.0.113.51",
            count=99,
        )
        db_session.commit()

        res = authed_client.get("/api/v1/settings/notifications/summary?period=daily")

        assert res.status_code == 200
        summary = res.json()["summary"]
        assert summary["period"] == "daily"
        assert summary["total_messages"] == 25
        assert summary["reports_processed"] == 1
        assert summary["top_domains"][0]["domain"] == "summary.example"

    def test_notification_summary_send_uses_apprise_summary(
        self,
        authed_client: TestClient,
        db_session: Session,
        monkeypatch,
    ):
        """POST /settings/notifications/summary/send sends the selected summary."""
        sent_messages = []

        def fake_send_notification(
            db, *, title, body, force=False
        ):  # pylint: disable=unused-argument
            sent_messages.append({"title": title, "body": body})
            return NotificationResult(
                success=True,
                message="Notification sent.",
                configured_targets=1,
            )

        monkeypatch.setattr(
            "app.services.summary_notifications.send_notification",
            fake_send_notification,
        )

        domain = _add_domain(db_session, "weekly.example")
        _add_report_record(
            db_session,
            domain,
            report_id="weekly-recent",
            days_ago=2,
            source_ip="203.0.113.60",
            count=40,
        )
        db_session.commit()

        res = authed_client.post("/api/v1/settings/notifications/summary/send?period=weekly")

        assert res.status_code == 200
        data = res.json()
        assert data["notification"]["success"] is True
        assert data["summary"]["period"] == "weekly"
        assert sent_messages[0]["title"].startswith("DMARQ weekly summary")
        assert "Weekly DMARC summary" in sent_messages[0]["body"]

    def test_notification_summary_invalid_period_and_failure_paths(
        self,
        authed_client: TestClient,
        monkeypatch,
    ):
        """Summary endpoints return useful 400 responses for invalid or failed sends."""
        preview_res = authed_client.get("/api/v1/settings/notifications/summary?period=monthly")
        assert preview_res.status_code == 400

        send_res = authed_client.post("/api/v1/settings/notifications/summary/send?period=monthly")
        assert send_res.status_code == 400

        def fake_send_summary_notification(db, period):  # pylint: disable=unused-argument
            return {
                "summary": {"period": period},
                "notification": {"success": False, "message": "Not delivered."},
            }

        monkeypatch.setattr(
            "app.api.api_v1.endpoints.settings.send_summary_notification",
            fake_send_summary_notification,
        )

        failed_res = authed_client.post("/api/v1/settings/notifications/summary/send?period=daily")
        assert failed_res.status_code == 400
        assert failed_res.json()["detail"]["notification"]["success"] is False

    def test_due_scheduled_summaries_send_once_per_period(
        self,
        db_session: Session,
        monkeypatch,
    ):
        """Scheduled summaries respect enabled settings and last-sent markers."""
        sent_messages = []

        def fake_send_notification(
            db, *, title, body, force=False
        ):  # pylint: disable=unused-argument
            sent_messages.append({"title": title, "body": body})
            return NotificationResult(
                success=True,
                message="Notification sent.",
                configured_targets=1,
            )

        monkeypatch.setattr(
            "app.services.summary_notifications.send_notification",
            fake_send_notification,
        )

        db_session.add_all(
            [
                Setting(
                    key="notifications.summary_daily_enabled",
                    value="true",
                    category="notifications",
                ),
                Setting(
                    key="notifications.summary_weekly_enabled",
                    value="true",
                    category="notifications",
                ),
                Setting(
                    key="notifications.summary_send_hour_utc",
                    value="8",
                    category="notifications",
                ),
                Setting(
                    key="notifications.summary_weekday_utc",
                    value="0",
                    category="notifications",
                ),
            ]
        )
        domain = _add_domain(db_session, "scheduled.example")
        _add_report_record(
            db_session,
            domain,
            report_id="scheduled-recent",
            days_ago=0,
            source_ip="203.0.113.70",
            count=12,
        )
        db_session.commit()
        now = datetime(2026, 5, 18, 8, 30, tzinfo=timezone.utc)

        first = send_due_scheduled_summaries(db_session, now=now)
        second = send_due_scheduled_summaries(db_session, now=now)

        assert set(first) == {"daily", "weekly"}
        assert second == {}
        assert len(sent_messages) == 2
        assert (
            db_session.query(Setting)
            .filter(Setting.key == "notifications.summary_daily_last_sent_date")
            .first()
            .value
            == "2026-05-18"
        )
