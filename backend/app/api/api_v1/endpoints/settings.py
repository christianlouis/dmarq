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

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.setting import Setting

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
        "key": "notifications.email_enabled",
        "value": "false",
        "description": "Send email notifications when new DMARC failures are detected",
        "value_type": "boolean",
        "category": "notifications",
    },
    {
        "key": "notifications.email_from",
        "value": "",
        "description": "From address used for notification emails",
        "value_type": "string",
        "category": "notifications",
    },
    {
        "key": "notifications.email_to",
        "value": "",
        "description": "Comma-separated list of recipient addresses for notifications",
        "value_type": "string",
        "category": "notifications",
    },
    {
        "key": "notifications.smtp_host",
        "value": "",
        "description": "SMTP server hostname for sending notification emails",
        "value_type": "string",
        "category": "notifications",
    },
    {
        "key": "notifications.smtp_port",
        "value": "587",
        "description": "SMTP server port",
        "value_type": "integer",
        "category": "notifications",
    },
    {
        "key": "notifications.smtp_username",
        "value": "",
        "description": "SMTP authentication username",
        "value_type": "string",
        "category": "notifications",
    },
    {
        "key": "notifications.smtp_password",
        "value": "",
        "description": "SMTP authentication password",
        "value_type": "string",
        "category": "notifications",
    },
    {
        "key": "notifications.smtp_use_tls",
        "value": "true",
        "description": "Use TLS when connecting to the SMTP server",
        "value_type": "boolean",
        "category": "notifications",
    },
]

# Keys whose values should be redacted in GET responses (treated as secrets)
_SECRET_KEYS = {
    "cloudflare.api_token",
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
    db.commit()


def _get_setting(key: str, db: Session) -> Optional[Setting]:
    return db.query(Setting).filter(Setting.key == key).first()


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
    if row is None:
        # Find matching default metadata
        default_meta = next((d for d in SETTING_DEFAULTS if d["key"] == key), None)
        row = Setting(
            key=key,
            value=payload.value,
            description=default_meta["description"] if default_meta else None,
            value_type=default_meta["value_type"] if default_meta else "string",
            category=default_meta["category"] if default_meta else "general",
        )
        db.add(row)
    else:
        # For secret keys, only update if not the redacted placeholder
        if key in _SECRET_KEYS and payload.value == "**redacted**":
            db.refresh(row)
            return _row_to_dict(row)
        row.value = payload.value
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
            row = Setting(
                key=key,
                value=value,
                description=default_meta["description"] if default_meta else None,
                value_type=default_meta["value_type"] if default_meta else "string",
                category=default_meta["category"] if default_meta else "general",
            )
            db.add(row)
        else:
            # Skip secret placeholder updates
            if key in _SECRET_KEYS and value == "**redacted**":
                results.append(_row_to_dict(row))
                continue
            row.value = value
        results.append(_row_to_dict(row))
    db.commit()
    # Re-read rows to get updated_at timestamps
    refreshed = []
    for item in results:
        row = _get_setting(item["key"], db)
        if row:
            refreshed.append(_row_to_dict(row))
    return refreshed
