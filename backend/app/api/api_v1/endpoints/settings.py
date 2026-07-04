"""
Settings API endpoints.

Provides endpoints to read and write application-level settings persisted
in the ``settings`` database table.  Settings are organised into categories:

- ``general``    - App name, base URL, reports-per-page, etc.
- ``dmarc``      - Default DMARC policy, percentage, etc.
- ``dns``        - Default DNS resolver, Cloudflare DoH toggle.
- ``cloudflare`` - Cloudflare API token and Zone ID.
- ``postmark``  - Postmark account token for read-only sender-domain discovery.
- ``forensics`` - Forensic report privacy and retention controls.
- ``notifications`` - Future alerting/notification settings.
"""

import ipaddress
import logging
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx
from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.credential_encryption import decrypt_secret, encrypt_secret, is_encrypted_secret
from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.setting import Setting
from app.services.ai_assistance import AI_DEFAULTS
from app.services.alert_history import (
    list_alert_config_audit,
    list_alert_history,
    record_alert_config_change,
    record_alert_evaluation,
)
from app.services.alert_rules import (
    enqueue_alert_webhook_events,
    evaluate_alert_rules,
    send_current_alerts,
)
from app.services.notifications import send_notification
from app.services.summary_notifications import build_summary, send_summary_notification
from app.services.workspace_access import (
    PERMISSION_NOTIFICATIONS_WRITE,
    parse_selected_workspace_id,
    resolve_authorized_workspace,
)
from app.services.workspace_audit import record_workspace_audit_log
from app.services.workspaces import assign_default_workspace_to_unscoped_rows

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
    {
        "key": "dmarc.report_mailbox",
        "value": "",
        "description": "Central mailbox for DMARC aggregate reports used in generated rua records",
        "value_type": "string",
        "category": "dmarc",
    },
    {
        "key": "dmarc.tls_report_mailbox",
        "value": "",
        "description": "Central mailbox for SMTP TLS reports used in generated TLS-RPT records",
        "value_type": "string",
        "category": "dmarc",
    },
    # ── DNS ──────────────────────────────────────────────────────────────────
    {
        "key": "dns.resolver",
        "value": "public",
        "description": "DNS resolver to use: public, cloudflare, or akamai_etp",
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
    {
        "key": "cloudflare.auth_mode",
        "value": "",
        "description": "Cloudflare connector authentication mode",
        "value_type": "string",
        "category": "cloudflare",
    },
    {
        "key": "cloudflare.oauth_scopes",
        "value": "",
        "description": "Granted Cloudflare OAuth scopes",
        "value_type": "string",
        "category": "cloudflare",
    },
    {
        "key": "cloudflare.oauth_scope_profile",
        "value": "read_only",
        "description": "Requested Cloudflare OAuth rights profile",
        "value_type": "string",
        "category": "cloudflare",
    },
    {
        "key": "cloudflare.oauth_connected_at",
        "value": "",
        "description": "Last successful Cloudflare OAuth connection time",
        "value_type": "string",
        "category": "cloudflare",
    },
    # ── Mail service integrations ───────────────────────────────────────────
    {
        "key": "postmark.account_token",
        "value": "",
        "description": "Postmark account token for read-only sender-domain discovery",
        "value_type": "string",
        "category": "postmark",
    },
    # ── Forensics ────────────────────────────────────────────────────────────
    {
        "key": "forensics.redaction_mode",
        "value": "balanced",
        "description": (
            "Forensic report email-address redaction mode: balanced, domain_only, or strict"
        ),
        "value_type": "string",
        "category": "forensics",
    },
    {
        "key": "forensics.redact_long_tokens_enabled",
        "value": "true",
        "description": "Redact long opaque tokens in forensic report metadata",
        "value_type": "boolean",
        "category": "forensics",
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
    {
        "key": "notifications.remediation_dispatch_enabled",
        "value": "false",
        "description": "Allow human-reviewed remediation notifications to become dispatch-eligible",
        "value_type": "boolean",
        "category": "notifications",
    },
    {
        "key": "notifications.remediation_dispatch_channel",
        "value": "webhook",
        "description": "Remediation notification dispatch channel; webhook is currently supported",
        "value_type": "string",
        "category": "notifications",
    },
    {
        "key": "notifications.remediation_dispatch_require_acknowledgement",
        "value": "true",
        "description": "Require previewed or acknowledged audit state before remediation dispatch",
        "value_type": "boolean",
        "category": "notifications",
    },
    {
        "key": "notifications.remediation_dispatch_events",
        "value": (
            "dmarq.remediation.approval_required,"
            "dmarq.remediation.manual_action_required,"
            "dmarq.remediation.investigation_required"
        ),
        "description": "Comma-separated remediation events eligible for future dispatch",
        "value_type": "string",
        "category": "notifications",
    },
    # ── Optional AI / MCP ───────────────────────────────────────────────────
    {
        "key": "ai.enabled",
        "value": "false",
        "description": "Enable optional AI assistance endpoints",
        "value_type": "boolean",
        "category": "ai",
    },
    {
        "key": "ai.provider",
        "value": "template",
        "description": "AI provider: template, local, remote, or litellm",
        "value_type": "string",
        "category": "ai",
    },
    {
        "key": "ai.model",
        "value": "",
        "description": "Optional model name for local or remote providers",
        "value_type": "string",
        "category": "ai",
    },
    {
        "key": "ai.api_key",
        "value": "",
        "description": "Optional API key for OpenAI-compatible AI providers",
        "value_type": "string",
        "category": "ai",
    },
    {
        "key": "ai.remote_base_url",
        "value": "",
        "description": (
            "Optional remote provider base URL; credentials should be injected by environment"
        ),
        "value_type": "string",
        "category": "ai",
    },
    {
        "key": "ai.redaction_mode",
        "value": "strict",
        "description": "Redaction mode for AI-safe context: strict or balanced",
        "value_type": "string",
        "category": "ai",
    },
    {
        "key": "ai.action_tools_enabled",
        "value": "false",
        "description": "Allow human-confirmed action proposals to be recorded",
        "value_type": "boolean",
        "category": "ai",
    },
    {
        "key": "ai.remediation_cache_seconds",
        "value": "86400",
        "description": "Cache TTL for AI remediation plans; demo mode uses a longer fixed cache",
        "value_type": "integer",
        "category": "ai",
    },
    {
        "key": "mcp.enabled",
        "value": "false",
        "description": "Enable the scoped read-only MCP endpoint",
        "value_type": "boolean",
        "category": "mcp",
    },
]

# Keys whose values should be redacted in GET responses (treated as secrets)
_SECRET_KEYS = {
    "ai.api_key",
    "cloudflare.api_token",
    "postmark.account_token",
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
    return key.startswith(("notifications.", "forensics.", "ai.", "mcp."))


def _audit_setting_change(
    db: Session,
    *,
    key: str,
    old_plain: Optional[str],
    new_plain: Optional[str],
    auth_context: Optional[Dict[str, Any]],
    request: Optional[Request] = None,
    selected_workspace_id: Optional[int] = None,
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
    if selected_workspace_id is None:
        workspace = assign_default_workspace_to_unscoped_rows(db, commit=False)
    else:
        workspace = resolve_authorized_workspace(
            db,
            auth_context or {},
            PERMISSION_NOTIFICATIONS_WRITE,
            selected_workspace_id=selected_workspace_id,
        )
    record_workspace_audit_log(
        db,
        workspace=workspace,
        action="setting.changed",
        entity_type="setting",
        entity_id=key,
        entity_name=key,
        details={
            "key": key,
            "old_value": _audit_value_for_setting(key, old_plain),
            "new_value": _audit_value_for_setting(key, new_plain),
        },
        auth_context=auth_context,
        request=request,
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


class AIProviderProfileResponse(BaseModel):
    """AI provider profile metadata for the settings UI."""

    id: str
    name: str
    description: str
    default_base_url: str = ""
    requires_base_url: bool = False
    requires_api_key: bool = False
    supports_model_discovery: bool = False
    default_model: str = ""


class AIConnectionTestRequest(BaseModel):
    """Connection-test payload for an AI provider."""

    provider: Optional[str] = None
    base_url: Optional[str] = None
    api_key: Optional[str] = None
    model: Optional[str] = None


class AIConnectionTestResponse(BaseModel):
    """Sanitized AI provider connection-test response."""

    success: bool
    provider: str
    message: str
    models: List[str] = []
    selected_model: Optional[str] = None


AI_PROVIDER_PROFILES: List[Dict[str, Any]] = [
    {
        "id": "template",
        "name": "Offline template",
        "description": "Use deterministic local remediation templates. No token or network call.",
        "default_base_url": "",
        "requires_base_url": False,
        "requires_api_key": False,
        "supports_model_discovery": False,
        "default_model": "",
    },
    {
        "id": "openai",
        "name": "OpenAI direct",
        "description": "Use OpenAI's native OpenAI-compatible API.",
        "default_base_url": "https://api.openai.com/v1",
        "requires_base_url": False,
        "requires_api_key": True,
        "supports_model_discovery": True,
        "default_model": "gpt-4.1-mini",
    },
    {
        "id": "litellm",
        "name": "LiteLLM proxy",
        "description": "Use your LiteLLM gateway for OpenAI, Anthropic, Gemini, or local models.",
        "default_base_url": "",
        "requires_base_url": True,
        "requires_api_key": True,
        "supports_model_discovery": True,
        "default_model": "",
    },
    {
        "id": "openai_compatible",
        "name": "OpenAI-compatible endpoint",
        "description": "Use a self-hosted or vendor API that exposes /v1/models.",
        "default_base_url": "",
        "requires_base_url": True,
        "requires_api_key": True,
        "supports_model_discovery": True,
        "default_model": "",
    },
]


def _ai_provider_profile(provider: Optional[str]) -> Dict[str, Any]:
    normalized = str(provider or "template").strip().lower().replace("-", "_")
    return next(
        (profile for profile in AI_PROVIDER_PROFILES if profile["id"] == normalized),
        AI_PROVIDER_PROFILES[0],
    )


def _setting_plain_or_default(db: Session, key: str) -> str:
    row = _get_setting(key, db)
    if row is not None:
        return _plain_value_for_setting(key, row.value) or ""
    return str(AI_DEFAULTS.get(key, ""))


def _normalize_ai_base_url(provider: str, base_url: str, profile: Dict[str, Any]) -> str:
    value = (base_url or profile.get("default_base_url") or "").strip().rstrip("/")
    if provider == "openai" and not value:
        return "https://api.openai.com/v1"
    return value


def _is_public_address(host: str) -> bool:
    """Return whether a hostname resolves only to public routable addresses."""
    try:
        literal = ipaddress.ip_address(host)
        addresses = [literal]
    except ValueError:
        try:
            addrinfo = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        except socket.gaierror as exc:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="AI base URL host could not be resolved.",
            ) from exc
        addresses = [ipaddress.ip_address(item[4][0]) for item in addrinfo]

    return all(
        not (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_multicast
            or address.is_reserved
            or address.is_unspecified
        )
        for address in addresses
    )


def _validated_ai_base_url(base_url: str) -> str:
    normalized = base_url.strip().rstrip("/")
    parsed = urlparse(normalized)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="AI base URL must be an absolute HTTP(S) URL.",
        )
    if parsed.username or parsed.password:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="AI base URL must not contain credentials.",
        )
    if not _is_public_address(parsed.hostname):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "AI base URL must resolve to public addresses. Private, localhost, "
                "link-local, and reserved targets are blocked for connection tests."
            ),
        )
    return normalized


async def _fetch_openai_compatible_models(*, base_url: str, api_key: str) -> List[str]:
    safe_base_url = _validated_ai_base_url(base_url)
    headers = {"Authorization": f"Bearer {api_key}"}
    async with httpx.AsyncClient(base_url=safe_base_url, timeout=10) as client:
        response = await client.get("/models", headers=headers)
        response.raise_for_status()
        payload = response.json()
    models = []
    for item in payload.get("data", []):
        model_id = str(item.get("id") or "").strip()
        if model_id:
            models.append(model_id)
    return sorted(set(models))


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
    enqueue_alert_webhook_events(db, alerts)
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


@router.get("/ai/provider-profiles", response_model=List[AIProviderProfileResponse])
async def list_ai_provider_profiles(
    _auth: dict = Depends(require_admin_auth),
) -> List[AIProviderProfileResponse]:
    """Return supported AI provider presets without exposing credentials."""
    return AI_PROVIDER_PROFILES


@router.post("/ai/test", response_model=AIConnectionTestResponse)
async def test_ai_connection(
    payload: AIConnectionTestRequest,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> AIConnectionTestResponse:
    """Validate AI provider settings without returning secret material."""
    _seed_defaults(db)
    provider = str(payload.provider or _setting_plain_or_default(db, "ai.provider") or "template")
    provider = provider.strip().lower().replace("-", "_")
    profile = _ai_provider_profile(provider)
    provider = profile["id"]

    if provider == "template":
        return AIConnectionTestResponse(
            success=True,
            provider=provider,
            message="Offline template mode is available. No external AI connection is required.",
            models=[],
            selected_model=None,
        )

    stored_key = _setting_plain_or_default(db, "ai.api_key")
    api_key = str(payload.api_key or "").strip()
    if api_key == "**redacted**":
        api_key = stored_key
    if not api_key:
        api_key = stored_key
    if profile.get("requires_api_key") and not api_key:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Add an API key before testing this AI provider.",
        )

    base_url = _normalize_ai_base_url(
        provider,
        str(payload.base_url or _setting_plain_or_default(db, "ai.remote_base_url") or ""),
        profile,
    )
    if profile.get("requires_base_url") and not base_url:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Add a provider base URL before testing this AI provider.",
        )

    selected_model = str(payload.model or _setting_plain_or_default(db, "ai.model") or "").strip()
    try:
        models = await _fetch_openai_compatible_models(base_url=base_url, api_key=api_key)
    except httpx.HTTPStatusError as exc:
        status_code = getattr(exc.response, "status_code", 0)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"AI provider rejected the connection test with HTTP {status_code}.",
        ) from exc
    except (httpx.RequestError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="AI provider connection test failed. Check the base URL and network path.",
        ) from exc

    if not selected_model and models:
        selected_model = models[0]
    return AIConnectionTestResponse(
        success=True,
        provider=provider,
        message="AI provider connection succeeded.",
        models=models,
        selected_model=selected_model or None,
    )


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
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> SettingResponse:
    """Update or create a single setting."""
    selected_workspace_id = parse_selected_workspace_id(selected_workspace)
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
            request=request,
            selected_workspace_id=selected_workspace_id,
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
            request=request,
            selected_workspace_id=selected_workspace_id,
        )
    db.commit()
    db.refresh(row)
    return _row_to_dict(row)


@router.post("/bulk", response_model=List[SettingResponse])
async def bulk_update_settings(
    payload: BulkSettingsUpdate,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> List[SettingResponse]:
    """
    Update multiple settings in a single request.

    Accepts ``{"settings": {"key1": "value1", "key2": "value2", ...}}``.
    """
    results = []
    selected_workspace_id = parse_selected_workspace_id(selected_workspace)
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
                request=request,
                selected_workspace_id=selected_workspace_id,
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
                request=request,
                selected_workspace_id=selected_workspace_id,
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
