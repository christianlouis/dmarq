"""Cloudflare OAuth connector helpers for DNS-provider access."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

import httpx
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.credential_encryption import encrypt_secret
from app.models.setting import Setting

CLOUDFLARE_AUTHORIZATION_URL = "https://dash.cloudflare.com/oauth2/auth"
CLOUDFLARE_TOKEN_URL = "https://api.cloudflare.com/oauth2/token"
CLOUDFLARE_DEFAULT_READ_SCOPES = "zone.read dns.read"
CLOUDFLARE_DEFAULT_SCOPE_PROFILE = "read_only"
CLOUDFLARE_ALLOWED_SCOPES = frozenset({"zone.read", "dns.read", "dns.write", "radar.read"})
_STATE_ALGORITHM = "HS256"
_STATE_TTL = timedelta(minutes=10)


@dataclass(frozen=True)
class CloudflareOAuthConfig:
    """Configured Cloudflare OAuth client settings."""

    client_id: str
    client_secret: str
    scopes: str


@dataclass(frozen=True)
class CloudflareScopeProfile:
    """User-selectable Cloudflare OAuth rights profile."""

    id: str
    name: str
    description: str
    scopes: str
    required_permissions: tuple[str, ...] = ()
    dns_write_enabled: bool = False
    radar_enabled: bool = False
    radar_requires_api_token: bool = False
    requires_client_allowlisting: bool = False
    warning: Optional[str] = None


CLOUDFLARE_SCOPE_PROFILES: Dict[str, CloudflareScopeProfile] = {
    "read_only": CloudflareScopeProfile(
        id="read_only",
        name="Read-only discovery",
        description="Verify ownership, import zones, and inspect DNS records.",
        scopes="zone.read dns.read",
        required_permissions=("Zone Read", "DNS Read"),
    ),
    "read_only_radar": CloudflareScopeProfile(
        id="read_only_radar",
        name="Read-only + Radar context",
        description=("Read DNS zones and request Cloudflare Radar read access for IP enrichment."),
        scopes="zone.read dns.read radar.read",
        required_permissions=("Zone Read", "DNS Read", "Account Radar Read"),
        radar_enabled=True,
        requires_client_allowlisting=True,
        warning=(
            "Includes Account Radar Read for Cloudflare Radar IP lookups. The Cloudflare "
            "OAuth client must allow radar.read."
        ),
    ),
    "full_dns_repair": CloudflareScopeProfile(
        id="full_dns_repair",
        name="Full DNS repair + Radar",
        description=(
            "Read zones, allow human-approved DNS record changes, and request "
            "Cloudflare Radar IP enrichment access."
        ),
        scopes="zone.read dns.read dns.write radar.read",
        required_permissions=("Zone Read", "DNS Read", "DNS Write", "Account Radar Read"),
        dns_write_enabled=True,
        radar_enabled=True,
        requires_client_allowlisting=True,
        warning=(
            "Only use this when you want DMARQ to prepare/apply confirmed DNS repairs "
            "and enrich sending IPs with Cloudflare Radar. The Cloudflare OAuth client "
            "must allow dns.write and radar.read."
        ),
    ),
}


def normalize_cloudflare_scope_profile(profile: Optional[str]) -> str:
    """Return a supported Cloudflare scope profile id."""
    value = str(profile or "").strip().lower().replace("-", "_")
    return value if value in CLOUDFLARE_SCOPE_PROFILES else CLOUDFLARE_DEFAULT_SCOPE_PROFILE


def cloudflare_scope_profile_metadata() -> List[Dict[str, Any]]:
    """Return serializable metadata for the settings UI."""
    metadata: List[Dict[str, Any]] = []
    for profile in CLOUDFLARE_SCOPE_PROFILES.values():
        item = asdict(profile)
        item["required_permissions"] = list(profile.required_permissions)
        metadata.append(item)
    return metadata


def cloudflare_scopes_for_profile(profile: Optional[str]) -> str:
    """Resolve OAuth scopes for a supported profile."""
    return CLOUDFLARE_SCOPE_PROFILES[normalize_cloudflare_scope_profile(profile)].scopes


def _sanitize_cloudflare_scopes(scopes: Optional[str]) -> str:
    requested = str(scopes or "").replace(",", " ").split()
    allowed = [scope for scope in requested if scope in CLOUDFLARE_ALLOWED_SCOPES]
    return " ".join(dict.fromkeys(allowed)) or CLOUDFLARE_DEFAULT_READ_SCOPES


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
        scopes=_sanitize_cloudflare_scopes(settings.CLOUDFLARE_OAUTH_SCOPES),
    )


def _state_signing_key() -> str:
    return f"{get_settings().SECRET_KEY}:cloudflare-oauth-state"


def _safe_return_to(value: str) -> str:
    path = str(value or "")
    if not path.startswith("/") or path.startswith("//") or "\\" in path:
        return "/settings"
    return path


def build_cloudflare_oauth_state(
    *,
    workspace_id: int,
    return_to: str = "/settings",
    scope_profile: Optional[str] = None,
) -> str:
    """Return a signed, short-lived state token for Cloudflare OAuth."""
    now = datetime.now(timezone.utc)
    normalized_profile = normalize_cloudflare_scope_profile(scope_profile)
    token = jwt.encode(
        {
            "workspace_id": int(workspace_id),
            "return_to": _safe_return_to(return_to),
            "scope_profile": normalized_profile,
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
            "return_to": _safe_return_to(str(payload.get("return_to") or "/settings")),
            "scope_profile": normalize_cloudflare_scope_profile(payload.get("scope_profile")),
        }
    except (JWTError, ValueError, KeyError, TypeError) as exc:
        raise LookupError("Invalid Cloudflare OAuth state.") from exc


def build_cloudflare_authorization_url(
    *,
    redirect_uri: str,
    state: str,
    scope_profile: Optional[str] = None,
) -> Dict[str, str]:
    """Return the Cloudflare authorization URL and request metadata."""
    config = get_cloudflare_oauth_config()
    explicit_profile = scope_profile is not None
    normalized_profile = normalize_cloudflare_scope_profile(scope_profile)
    scopes = cloudflare_scopes_for_profile(normalized_profile)
    if not explicit_profile and get_settings().CLOUDFLARE_OAUTH_SCOPES:
        scopes = config.scopes
    params = {
        "client_id": config.client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scopes,
        "state": state,
    }
    return {
        "authorization_url": f"{CLOUDFLARE_AUTHORIZATION_URL}?{urlencode(params)}",
        "redirect_uri": redirect_uri,
        "scopes": scopes,
        "scope_profile": normalized_profile,
    }


def _cloudflare_token_request_data(*, code: str, redirect_uri: str) -> Dict[str, str]:
    return {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": redirect_uri,
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
                    **_cloudflare_token_request_data(code=code, redirect_uri=redirect_uri),
                    "client_id": config.client_id,
                    "client_secret": config.client_secret,
                },
            )
            if getattr(response, "status_code", None) in {401, 403}:
                response = await client.post(
                    CLOUDFLARE_TOKEN_URL,
                    data=_cloudflare_token_request_data(code=code, redirect_uri=redirect_uri),
                    auth=httpx.BasicAuth(config.client_id, config.client_secret),
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
    *,
    scope_profile: Optional[str] = None,
) -> None:
    """Persist the Cloudflare OAuth access token as the active provider token."""
    access_token = str(token_data.get("access_token") or "").strip()
    if not access_token:
        raise LookupError("Cloudflare OAuth did not return an access token.")
    normalized_profile = normalize_cloudflare_scope_profile(scope_profile)
    scope = str(token_data.get("scope") or cloudflare_scopes_for_profile(normalized_profile))
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
        key="cloudflare.oauth_scope_profile",
        value=normalized_profile,
        description="Requested Cloudflare OAuth rights profile",
    )
    _upsert_setting(
        db,
        key="cloudflare.oauth_connected_at",
        value=datetime.now(timezone.utc).isoformat(),
        description="Last successful Cloudflare OAuth connection time",
    )
    db.commit()
