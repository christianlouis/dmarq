"""
Settings API endpoints.

Provides endpoints to read and write application-level settings persisted
in the ``settings`` database table.  Settings are organised into categories:

- ``general``    – App name, base URL, reports-per-page, etc.
- ``dmarc``      – Default DMARC policy, percentage, etc.
- ``dns``        – Default DNS resolver, Cloudflare DoH toggle.
- ``cloudflare`` – Cloudflare API token and Zone ID.
- ``notifications`` – Future alerting/notification settings.
"""

import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.credential_encryption import decrypt_secret, encrypt_secret, is_encrypted_secret
from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.setting import Setting
from app.services.alert_history import (
    list_alert_config_audit,
    list_alert_history,
    record_alert_config_change,
    record_alert_evaluation,
)
from app.services.alert_rules import evaluate_alert_rules, send_current_alerts
from app.services.notifications import send_notification
from app.services.summary_notifications import build_summary, send_summary_notification

router = APIRouter()
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Defaults – used to seed missing keys on first read
# ---------------------------------------------------------------------------

SETTING_DEFAULTS: List[Dict[str, Any]] = [
    # ── General ─────────────────────────────────────────────────────────────
    {
        "key": "general.app_name",
        "value": "DMARQ",
        "description": "Application display name shown in the UI",
        "value_type": "string",
        "category": "general",
    },
    {
        "key": "general.base_url",
        "value": "",
        "description": "Public base URL (e.g. https://dmarc.example.com)",
        "value_type": "string",
        "category": "general",
    },
    {
        "key": "general.reports_per_page",
        "value": "25",
        "description": "Number of reports shown per page in the reports list",
        "value_type": "integer",
        "category": "general",
    },
    {
        "key": "general.session_lifetime_minutes",
        "value": "1440",
        "description": "How long a login session stays valid (minutes)",
        "value_type": "integer",
        "category": "general",
    },
    # ── DMARC ────────────────────────────────────────────────────────────────
    {
        "key": "dmarc.default_policy",
        "value": "none",
        "description": "Default DMARC policy applied when adding a new domain",
        "value_type": "string",
        "category": "dmarc",
    },
    {
        "key": "dmarc.default_percentage",
        "value": "100",
        "description": "Default DMARC percentage (pct) tag for new domains",
        "value_type": "integer",
        "category": "dmarc",
    },
    {
        "key": "dmarc.default_adkim",
        "value": "r",
        "description": "Default DKIM alignment mode: r (relaxed) or s (strict)",
        "value_type": "string",
        "category": "dmarc",
    },
    {
        "key": "dmarc.default_aspf",
        "value": "r",
        "description": "Default SPF alignment mode: r (relaxed) or s (strict)",
        "value_type": "string",
        "category": "dmarc",
    },
    # ── DNS ──────────────────────────────────────────────────────────────────
    {
        "key": "dns.resolver",
        "value": "system",
        "description": "DNS resolver to use: system or cloudflare",
        "value_type": "string",
        "category": "dns",
    },
    # ── Cloudflare ───────────────────────────────────────────────────────────
    {
        "key": "cloudflare.api_token",
        "value": "",
        "description": "Cloudflare API token for DNS record management",
        "value_type": "string",
        "category": "cloudflare",
    },
    {
        "key": "cloudflare.zone_id",
        "value": "",
        "description": "Cloudflare Zone ID for DNS record management",
        "value_type": "string",
        "category": "cloudflare",
    },
    # ── Notifications ─────────────────────────────────────────────────────────
    {
        "key": "notifications.apprise_enabled",
        "value": "false",
        "description": "Send notifications through configured Apprise target URLs",
        "value_type": "boolean",
        "category": "notifications",
    },
    {
        "key": "notifications.apprise_urls",
        "value": "",
        "description": "Newline-separated Apprise notification target URLs",
        "value_type": "string",
        "category": "notifications",
    },
    {
        "key": "notifications.min_send_interval_minutes",
        "value": "15",
        "description": "Minimum minutes between outbound notification deliveries",
        "value_type": "integer",
        "category": "notifications",
    },
    {
        "key": "notifications.redact_pii_enabled",
        "value": "true",
        "description": "Redact email addresses from outbound notification titles and bodies",
        "value_type": "boolean",
        "category": "notifications",
    },
    {
        "key": "notifications.last_sent_at",
        "value": "",
        "description": "Internal timestamp for outbound notification rate limiting",
        "value_type": "string",
        "category": "notifications",
    },
    {
        "key": "notifications.alert_new_sources_enabled",
        "value": "true",
        "description": "Alert when a new sending source appears in recent DMARC reports",
        "value_type": "boolean",
        "category": "notifications",
    },
    {
        "key": "notifications.alert_compliance_drop_enabled",
        "value": "true",
        "description": "Alert when DMARC compliance drops by the configured percentage points",
        "value_type": "boolean",
        "category": "notifications",
    },
    {
        "key": "notifications.alert_compliance_drop_points",
        "value": "10",
        "description": "Minimum compliance-rate drop, in percentage points, before alerting",
        "value_type": "integer",
        "category": "notifications",
    },
    {
        "key": "notifications.alert_failure_threshold_enabled",
        "value": "true",
        "description": "Alert when DMARC failures exceed the configured daily threshold",
        "value_type": "boolean",
        "category": "notifications",
    },
    {
        "key": "notifications.alert_failure_threshold_count",
        "value": "100",
        "description": "Minimum failed message count in the last day before alerting",
        "value_type": "integer",
        "category": "notifications",
    },
    {
        "key": "notifications.alert_missing_reports_enabled",
        "value": "true",
        "description": "Alert when a monitored domain has not received recent DMARC reports",
        "value_type": "boolean",
        "category": "notifications",
    },
    {
        "key": "notifications.alert_missing_reports_days",
        "value": "2",
        "description": "Number of days without DMARC reports before alerting",
        "value_type": "integer",
        "category": "notifications",
    },
    {
        "key": "notifications.summary_daily_enabled",
        "value": "false",
        "description": "Send one daily DMARC activity summary notification",
        "value_type": "boolean",
        "category": "notifications",
    },
    {
        "key": "notifications.summary_weekly_enabled",
        "value": "false",
        "description": "Send one weekly DMARC activity summary notification",
        "value_type": "boolean",
        "category": "notifications",
    },
    {
        "key": "notifications.summary_send_hour_utc",
        "value": "8",
        "description": "UTC hour when scheduled summary notifications can be sent",
        "value_type": "integer",
        "category": "notifications",
    },
    {
        "key": "notifications.summary_weekday_utc",
        "value": "0",
        "description": "UTC weekday for weekly summaries, where 0 is Monday",
        "value_type": "integer",
        "category": "notifications",
    },
    {
        "key": "notifications.summary_daily_last_sent_date",
        "value": "",
        "description": "Internal date marker for the last sent daily summary",
        "value_type": "string",
        "category": "notifications",
    },
    {
        "key": "notifications.summary_weekly_last_sent_week",
        "value": "",
        "description": "Internal ISO week marker for the last sent weekly summary",
        "value_type": "string",
        "category": "notifications",
    },
]

# Keys whose values should be redacted in GET responses (treated as secrets)
_SECRET_KEYS = {
    "cloudflare.api_token",
    "notifications.apprise_urls",
    "notifications.smtp_password",
}


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _seed_defaults(db: Session) -> None:
    """Insert any missing default settings rows (idempotent)."""
    for defaults in SETTING_DEFAULTS:
        key = defaults["key"]
        if db.query(Setting).filter(Setting.key == key).first() is None:
            db.add(
                Setting(
                    key=key,
                    value=defaults["value"],
                    description=defaults["description"],
                    value_type=defaults["value_type"],
                    category=defaults["category"],
                )
            )
    _migrate_plaintext_secret_settings(db)
    db.commit()


def _get_setting(key: str, db: Session) -> Optional[Setting]:
    return db.query(Setting).filter(Setting.key == key).first()


def _migrate_plaintext_secret_settings(db: Session) -> None:
    """Encrypt legacy plaintext secret settings opportunistically."""
    rows = db.query(Setting).filter(Setting.key.in_(_SECRET_KEYS)).all()
    for row in rows:
        if row.value and not is_encrypted_secret(row.value):
            row.value = encrypt_secret(row.value)


def _stored_value_for_setting(key: str, value: Optional[str]) -> Optional[str]:
    if key in _SECRET_KEYS:
        return encrypt_secret(value)
    return value


def _plain_value_for_setting(key: str, value: Optional[str]) -> Optional[str]:
    if key not in _SECRET_KEYS:
        return value
    return decrypt_secret(value)


def _audit_value_for_setting(key: str, value: Optional[str]) -> Optional[str]:
    if key in _SECRET_KEYS:
        return "[redacted]" if value else ""
    return value


def _should_audit_setting(key: str) -> bool:
    return key.startswith("notifications.")


def _audit_setting_change(
    db: Session,
    *,
    key: str,
    old_plain: Optional[str],
    new_plain: Optional[str],
    auth_context: Optional[Dict[str, Any]],
) -> None:
    if not _should_audit_setting(key) or old_plain == new_plain:
        return
    record_alert_config_change(
        db,
        key=key,
        old_value=_audit_value_for_setting(key, old_plain),
        new_value=_audit_value_for_setting(key, new_plain),
        auth_context=auth_context,
    )


def _row_to_dict(row: Setting, redact_secrets: bool = True) -> Dict[str, Any]:
    value = row.value
    if redact_secrets and row.key in _SECRET_KEYS and value:
        value = "**redacted**"
    return {
        "key": row.key,
        "value": value,
        "description": row.description,
        "value_type": row.value_type,
        "category": row.category,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class SettingUpdate(BaseModel):
    """Payload for updating a single setting."""

    value: Optional[str] = None


class BulkSettingsUpdate(BaseModel):
    """Payload for updating multiple settings at once."""

    settings: Dict[str, Optional[str]]


class SettingResponse(BaseModel):
    """Response for a single setting."""

    key: str
    value: Optional[str]
    description: Optional[str]
    value_type: str
    category: str
    updated_at: Optional[str]


class NotificationTestResponse(BaseModel):
    """Sanitized response from a test notification send."""

    success: bool
    message: str
    configured_targets: int = 0
    invalid_targets: int = 0
    skipped: bool = False
    rate_limited: bool = False
    error: Optional[str] = None


class AlertRulesResponse(BaseModel):
    """Current alert-rule evaluation response."""

    alerts: List[Dict[str, Any]]


class AlertNotificationResponse(BaseModel):
    """Alert-rule evaluation plus notification delivery status."""

    alerts: List[Dict[str, Any]]
    notification: Dict[str, Any]


class AlertHistoryResponse(BaseModel):
    """Persisted alert history response."""

    history: List[Dict[str, Any]]


class AlertConfigurationAuditResponse(BaseModel):
    """Persisted alert configuration audit response."""

    audit: List[Dict[str, Any]]


class SummaryResponse(BaseModel):
    """Current DMARC summary notification preview."""

    summary: Dict[str, Any]


class SummaryNotificationResponse(BaseModel):
    """DMARC summary plus notification delivery status."""

    summary: Dict[str, Any]
    notification: Dict[str, Any]


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("", response_model=List[SettingResponse])
async def list_settings(
    category: Optional[str] = None,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> List[SettingResponse]:
    """
    Return all persisted settings, optionally filtered by category.

    Missing rows are seeded from defaults before returning.
    """
    _seed_defaults(db)
    query = db.query(Setting)
    if category:
        query = query.filter(Setting.category == category)
    rows = query.order_by(Setting.category, Setting.key).all()
    return [_row_to_dict(row) for row in rows]


@router.post("/notifications/test", response_model=NotificationTestResponse)
async def test_notification_settings(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> NotificationTestResponse:
    """Send a test notification using the configured Apprise targets."""
    _seed_defaults(db)
    result = send_notification(
        db,
        title="DMARQ test notification",
        body="This confirms that DMARQ can reach the configured notification target.",
        force=True,
    )
    if not result.success:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result.to_dict(),
        )
    return result.to_dict()


@router.get("/notifications/alerts", response_model=AlertRulesResponse)
async def evaluate_notification_alerts(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> AlertRulesResponse:
    """Evaluate enabled notification alert rules against current DMARC data."""
    _seed_defaults(db)
    alerts = evaluate_alert_rules(db)
    record_alert_evaluation(db, alerts)
    return {"alerts": alerts}


@router.post("/notifications/alerts/send", response_model=AlertNotificationResponse)
async def send_notification_alerts(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> AlertNotificationResponse:
    """Evaluate current alert rules and send a notification summary when needed."""
    _seed_defaults(db)
    result = send_current_alerts(db)
    notification = result["notification"]
    if result["alerts"] and not notification.get("success"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result,
        )
    return result


@router.get("/notifications/alerts/history", response_model=AlertHistoryResponse)
async def get_notification_alert_history(
    active: Optional[bool] = None,
    limit: int = 50,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> AlertHistoryResponse:
    """Return persisted alert history rows."""
    return {"history": list_alert_history(db, active=active, limit=max(1, min(limit, 200)))}


@router.get("/notifications/config-audit", response_model=AlertConfigurationAuditResponse)
async def get_notification_config_audit(
    limit: int = 50,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> AlertConfigurationAuditResponse:
    """Return recent notification and alert-rule configuration changes."""
    return {"audit": list_alert_config_audit(db, limit=max(1, min(limit, 200)))}


@router.get("/notifications/summary", response_model=SummaryResponse)
async def preview_notification_summary(
    period: str = "daily",
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> SummaryResponse:
    """Preview a daily or weekly DMARC summary notification."""
    _seed_defaults(db)
    try:
        summary = build_summary(db, period)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    return {"summary": summary}


@router.post("/notifications/summary/send", response_model=SummaryNotificationResponse)
async def send_notification_summary(
    period: str = "daily",
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> SummaryNotificationResponse:
    """Send a daily or weekly DMARC summary notification immediately."""
    _seed_defaults(db)
    try:
        result = send_summary_notification(db, period)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc
    notification = result["notification"]
    if not notification.get("success"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result,
        )
    return result


@router.get("/{key:path}", response_model=SettingResponse)
async def get_setting(
    key: str,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> SettingResponse:
    """Return a single setting by key."""
    _seed_defaults(db)
    row = _get_setting(key, db)
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Setting '{key}' not found",
        )
    return _row_to_dict(row)


@router.put("/{key:path}", response_model=SettingResponse)
async def update_setting(
    key: str,
    payload: SettingUpdate,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> SettingResponse:
    """Update or create a single setting."""
    row = _get_setting(key, db)
    new_value = payload.value
    if row is None:
        # Find matching default metadata
        default_meta = next((d for d in SETTING_DEFAULTS if d["key"] == key), None)
        new_plain = _plain_value_for_setting(key, new_value)
        row = Setting(
            key=key,
            value=_stored_value_for_setting(key, new_value),
            description=default_meta["description"] if default_meta else None,
            value_type=default_meta["value_type"] if default_meta else "string",
            category=default_meta["category"] if default_meta else "general",
        )
        db.add(row)
        _audit_setting_change(
            db,
            key=key,
            old_plain=None,
            new_plain=new_plain,
            auth_context=_auth,
        )
    else:
        # For secret keys, only update if not the redacted placeholder
        if key in _SECRET_KEYS and payload.value == "**redacted**":
            db.refresh(row)
            return _row_to_dict(row)
        old_plain = _plain_value_for_setting(key, row.value)
        new_plain = _plain_value_for_setting(key, new_value)
        row.value = _stored_value_for_setting(key, new_value)
        _audit_setting_change(
            db,
            key=key,
            old_plain=old_plain,
            new_plain=new_plain,
            auth_context=_auth,
        )
    db.commit()
    db.refresh(row)
    return _row_to_dict(row)


@router.post("/bulk", response_model=List[SettingResponse])
async def bulk_update_settings(
    payload: BulkSettingsUpdate,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> List[SettingResponse]:
    """
    Update multiple settings in a single request.

    Accepts ``{"settings": {"key1": "value1", "key2": "value2", ...}}``.
    """
    results = []
    for key, value in payload.settings.items():
        row = _get_setting(key, db)
        if row is None:
            default_meta = next((d for d in SETTING_DEFAULTS if d["key"] == key), None)
            new_plain = _plain_value_for_setting(key, value)
            row = Setting(
                key=key,
                value=_stored_value_for_setting(key, value),
                description=default_meta["description"] if default_meta else None,
                value_type=default_meta["value_type"] if default_meta else "string",
                category=default_meta["category"] if default_meta else "general",
            )
            db.add(row)
            _audit_setting_change(
                db,
                key=key,
                old_plain=None,
                new_plain=new_plain,
                auth_context=_auth,
            )
        else:
            # Skip secret placeholder updates
            if key in _SECRET_KEYS and value == "**redacted**":
                results.append(_row_to_dict(row))
                continue
            old_plain = _plain_value_for_setting(key, row.value)
            new_plain = _plain_value_for_setting(key, value)
            row.value = _stored_value_for_setting(key, value)
            _audit_setting_change(
                db,
                key=key,
                old_plain=old_plain,
                new_plain=new_plain,
                auth_context=_auth,
            )
        results.append(_row_to_dict(row))
    db.commit()
    # Re-read rows to get updated_at timestamps
    refreshed = []
    for item in results:
        row = _get_setting(item["key"], db)
        if row:
            refreshed.append(_row_to_dict(row))
    return refreshed
