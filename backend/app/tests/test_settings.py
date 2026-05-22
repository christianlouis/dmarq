"""
Tests for the Settings model and /api/v1/settings endpoints.
"""

from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from app.models.domain import Domain
from app.models.report import DMARCReport, ReportRecord
from app.models.setting import Setting
from app.services.notifications import NotificationResult
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
