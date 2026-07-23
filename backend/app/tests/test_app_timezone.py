"""Tests for APP_TIMEZONE presentation helpers (#817)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

from app.core.app_timezone import (
    DEFAULT_APP_TIMEZONE,
    format_datetime_for_display,
    present_datetime,
    resolve_app_timezone_name,
)
from app.core.config import Settings


def test_resolve_app_timezone_accepts_valid_iana() -> None:
    assert resolve_app_timezone_name("Europe/Berlin") == "Europe/Berlin"
    assert resolve_app_timezone_name("UTC") == "UTC"


def test_resolve_app_timezone_falls_back_for_invalid(caplog) -> None:
    with caplog.at_level("WARNING"):
        assert resolve_app_timezone_name("Not/AZone") == DEFAULT_APP_TIMEZONE
        assert resolve_app_timezone_name("") == DEFAULT_APP_TIMEZONE
        assert resolve_app_timezone_name(None) == DEFAULT_APP_TIMEZONE
    assert any("Invalid APP_TIMEZONE" in record.message for record in caplog.records)


def test_resolve_app_timezone_handles_non_string_input(caplog) -> None:
    with caplog.at_level("WARNING"):
        assert resolve_app_timezone_name(42) == DEFAULT_APP_TIMEZONE
    assert any("Invalid APP_TIMEZONE" in record.message for record in caplog.records)


def test_settings_validator_falls_back_to_utc() -> None:
    settings = Settings(APP_TIMEZONE="Not/AZone")
    assert settings.APP_TIMEZONE == "UTC"

    berlin = Settings(APP_TIMEZONE="Europe/Berlin")
    assert berlin.APP_TIMEZONE == "Europe/Berlin"


def test_compose_does_not_override_timezone_from_custom_env_file() -> None:
    compose = (Path(__file__).parents[3] / "docker-compose.yml").read_text(encoding="utf-8")
    app_environment = compose.split("    environment:\n", maxsplit=2)[2].split(
        "    volumes:\n", maxsplit=1
    )[0]
    assert "APP_TIMEZONE:" not in app_environment


def test_present_datetime_applies_offset_and_keeps_utc_instant() -> None:
    stored = datetime(2026, 7, 16, 10, 0, 0)  # naive UTC storage
    presented = present_datetime(stored, tz_name="Europe/Berlin")
    assert presented is not None
    assert presented.tzinfo == ZoneInfo("Europe/Berlin")
    # CEST is UTC+2 in July
    assert presented.hour == 12
    assert presented.utcoffset().total_seconds() == 2 * 3600
    assert presented.astimezone(timezone.utc).replace(tzinfo=None) == stored


def test_format_datetime_for_display_includes_offset() -> None:
    stored = datetime(2026, 1, 15, 10, 0, 0, tzinfo=timezone.utc)
    text = format_datetime_for_display(stored, tz_name="Europe/Berlin")
    assert text is not None
    assert "+01:00" in text or text.endswith("+0100")


def test_mail_source_response_presents_last_checked_in_app_timezone(monkeypatch) -> None:
    from types import SimpleNamespace

    from app.api.api_v1.endpoints import mail_sources as mail_sources_api
    from app.core.config import Settings

    berlin = Settings(APP_TIMEZONE="Europe/Berlin")
    monkeypatch.setattr(mail_sources_api, "get_settings", lambda: berlin)

    source = SimpleNamespace(
        id=1,
        name="inbox",
        method="IMAP",
        server="imap.example.com",
        port=993,
        username="user",
        password=None,
        use_ssl=True,
        folder="INBOX",
        polling_interval=60,
        enabled=True,
        last_checked=datetime(2026, 7, 16, 10, 0, 0),
        created_at=datetime(2026, 7, 1, 8, 0, 0),
        updated_at=datetime(2026, 7, 1, 8, 0, 0),
        gmail_client_id=None,
        gmail_client_secret=None,
        gmail_email=None,
        gmail_access_token=None,
        m365_tenant_id=None,
        m365_auth_mode=None,
        m365_client_id=None,
        m365_client_secret=None,
        m365_mailbox=None,
        m365_folder_id=None,
        m365_email=None,
        m365_access_token=None,
    )
    response = mail_sources_api._source_to_response(source)
    assert response.application_timezone == "Europe/Berlin"
    assert response.last_checked is not None
    assert response.last_checked.hour == 12
    # Storage instant unchanged when converted back to UTC.
    assert response.last_checked.astimezone(timezone.utc).hour == 10
