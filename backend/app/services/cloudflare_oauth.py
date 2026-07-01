"""Cloudflare OAuth connector helpers for DNS-provider access."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from urllib.parse import urlencode

import httpx
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.credential_encryption import encrypt_secret
from app.models.setting import Setting

CLOUDFLARE_AUTHORIZATION_URL = "https://dash.cloudflare.com/oauth2/auth"
CLOUDFLARE_TOKEN_URL = "https://dash.cloudflare.com/oauth2/token"
CLOUDFLARE_DEFAULT_READ_SCOPES = "zone.read dns.read"
_STATE_ALGORITHM = "HS256"
_STATE_TTL = timedelta(minutes=10)


@dataclass(frozen=True)
class CloudflareOAuthConfig:
    """Configured Cloudflare OAuth client settings."""

    client_id: str
    client_secret: str
    scopes: str


def cloudflare_oauth_configured() -> bool:
    """Return whether a Cloudflare OAuth client can be used."""
    settings = get_settings()
    return bool(settings.CLOUDFLARE_OAUTH_CLIENT_ID and settings.CLOUDFLARE_OAUTH_CLIENT_SECRET)


def get_cloudflare_oauth_config() -> CloudflareOAuthConfig:
    """Return the Cloudflare OAuth client config or raise a clear setup error."""
    settings = get_settings()
    if not settings.CLOUDFLARE_OAUTH_CLIENT_ID or not settings.CLOUDFLARE_OAUTH_CLIENT_SECRET:
        raise LookupError(
            "Cloudflare OAuth is not configured. Set CLOUDFLARE_OAUTH_CLIENT_ID and "
            "CLOUDFLARE_OAUTH_CLIENT_SECRET, or use a scoped Cloudflare API token."
        )
    return CloudflareOAuthConfig(
        client_id=settings.CLOUDFLARE_OAUTH_CLIENT_ID,
        client_secret=settings.CLOUDFLARE_OAUTH_CLIENT_SECRET,
        scopes=settings.CLOUDFLARE_OAUTH_SCOPES or CLOUDFLARE_DEFAULT_READ_SCOPES,
    )


def _state_signing_key() -> str:
    return f"{get_settings().SECRET_KEY}:cloudflare-oauth-state"


def build_cloudflare_oauth_state(
    *,
    workspace_id: int,
    return_to: str = "/settings",
) -> str:
    """Return a signed, short-lived state token for Cloudflare OAuth."""
    now = datetime.now(timezone.utc)
    token = jwt.encode(
        {
            "workspace_id": int(workspace_id),
            "return_to": return_to if return_to.startswith("/") else "/settings",
            "iat": now,
            "exp": now + _STATE_TTL,
        },
        _state_signing_key(),
        algorithm=_STATE_ALGORITHM,
    )
    return f"v1.{token}"


def decode_cloudflare_oauth_state(state_value: str) -> Dict[str, Any]:
    """Validate and decode a Cloudflare OAuth state token."""
    token = (state_value or "").removeprefix("v1.")
    if not token:
        raise LookupError("Invalid Cloudflare OAuth state.")
    try:
        payload = jwt.decode(
            token,
            _state_signing_key(),
            algorithms=[_STATE_ALGORITHM],
            options={"verify_aud": False},
        )
        return {
            "workspace_id": int(payload["workspace_id"]),
            "return_to": str(payload.get("return_to") or "/settings"),
        }
    except (JWTError, ValueError, KeyError, TypeError) as exc:
        raise LookupError("Invalid Cloudflare OAuth state.") from exc


def build_cloudflare_authorization_url(
    *,
    redirect_uri: str,
    state: str,
) -> Dict[str, str]:
    """Return the Cloudflare authorization URL and request metadata."""
    config = get_cloudflare_oauth_config()
    params = {
        "client_id": config.client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": config.scopes,
        "state": state,
    }
    return {
        "authorization_url": f"{CLOUDFLARE_AUTHORIZATION_URL}?{urlencode(params)}",
        "redirect_uri": redirect_uri,
        "scopes": config.scopes,
    }


async def exchange_cloudflare_oauth_code(
    *,
    code: str,
    redirect_uri: str,
) -> Dict[str, Any]:
    """Exchange a Cloudflare OAuth authorization code for an access token."""
    config = get_cloudflare_oauth_config()
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                CLOUDFLARE_TOKEN_URL,
                data={
                    "grant_type": "authorization_code",
                    "code": code,
                    "redirect_uri": redirect_uri,
                    "client_id": config.client_id,
                    "client_secret": config.client_secret,
                },
            )
            response.raise_for_status()
            data = response.json()
    except (httpx.RequestError, httpx.HTTPStatusError, ValueError) as exc:
        raise LookupError("Cloudflare OAuth token exchange failed.") from exc

    if not data.get("access_token"):
        raise LookupError("Cloudflare OAuth did not return an access token.")
    return data


def _upsert_setting(
    db: Session,
    *,
    key: str,
    value: str,
    category: str = "cloudflare",
    value_type: str = "string",
    description: Optional[str] = None,
) -> Setting:
    row = db.query(Setting).filter(Setting.key == key).first()
    if row is None:
        row = Setting(
            key=key,
            value=value,
            category=category,
            value_type=value_type,
            description=description,
        )
        db.add(row)
    else:
        row.value = value
        row.category = category
        row.value_type = value_type
        if description is not None:
            row.description = description
    return row


def persist_cloudflare_oauth_tokens(
    db: Session,
    token_data: Dict[str, Any],
) -> None:
    """Persist the Cloudflare OAuth access token as the active provider token."""
    access_token = str(token_data.get("access_token") or "").strip()
    if not access_token:
        raise LookupError("Cloudflare OAuth did not return an access token.")
    scope = str(token_data.get("scope") or get_cloudflare_oauth_config().scopes)
    _upsert_setting(
        db,
        key="cloudflare.api_token",
        value=encrypt_secret(access_token),
        description="Cloudflare OAuth access token for DNS zone discovery",
    )
    _upsert_setting(
        db,
        key="cloudflare.auth_mode",
        value="oauth",
        description="Cloudflare connector authentication mode",
    )
    _upsert_setting(
        db,
        key="cloudflare.oauth_scopes",
        value=scope,
        description="Granted Cloudflare OAuth scopes",
    )
    _upsert_setting(
        db,
        key="cloudflare.oauth_connected_at",
        value=datetime.now(timezone.utc).isoformat(),
        description="Last successful Cloudflare OAuth connection time",
    )
    db.commit()
