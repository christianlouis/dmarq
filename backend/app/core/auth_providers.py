"""Provider-neutral authentication helpers for external identity providers."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Optional
from urllib.parse import urlencode

import httpx
from fastapi import HTTPException, Request, status
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.models.user import User

logger = logging.getLogger(__name__)

OIDC_STATE_COOKIE = "dmarq_oidc_state"
OIDC_STATE_MAX_AGE = 600


@dataclass(frozen=True)
class OIDCProviderConfig:
    """Runtime OIDC provider configuration."""

    provider: str
    label: str
    issuer_url: str
    client_id: str
    client_secret: str
    redirect_uri: Optional[str]
    scopes: str
    skip_ssl_verify: bool
    allowed_emails: Optional[str] = None
    allowed_domains: Optional[str] = None


@dataclass(frozen=True)
class ExternalIdentityClaims:
    """Normalized user claims from an external IdP or trusted proxy."""

    provider: str
    subject: str
    email: str
    name: Optional[str] = None
    username: Optional[str] = None
    picture: Optional[str] = None
    email_verified: bool = False


def _split_csv(value: Optional[str]) -> set[str]:
    if not value:
        return set()
    return {item.strip().lower() for item in value.split(",") if item.strip()}


def email_allowed(
    email: str,
    *,
    allowed_emails: Optional[str] = None,
    allowed_domains: Optional[str] = None,
) -> bool:
    """Return True when *email* is allowed by optional comma-separated allow lists."""
    normalized = (email or "").strip().lower()
    if not normalized or "@" not in normalized:
        return False
    explicit_emails = _split_csv(allowed_emails)
    explicit_domains = _split_csv(allowed_domains)
    if not explicit_emails and not explicit_domains:
        return True
    domain = normalized.rsplit("@", 1)[1]
    return normalized in explicit_emails or domain in explicit_domains


def configured_oidc_provider(settings: Settings | None = None) -> Optional[OIDCProviderConfig]:
    """Return the active direct-OIDC provider config, if direct OIDC is selected."""
    cfg = settings or get_settings()
    provider = getattr(cfg, "active_auth_provider", "unconfigured")
    if provider == "authentik":
        issuer = cfg.AUTHENTIK_ISSUER_URL or cfg.OIDC_ISSUER_URL
        client_id = cfg.AUTHENTIK_CLIENT_ID or cfg.OIDC_CLIENT_ID
        client_secret = cfg.AUTHENTIK_CLIENT_SECRET or cfg.OIDC_CLIENT_SECRET
        if not issuer or not client_id or not client_secret:
            return None
        return OIDCProviderConfig(
            provider="authentik",
            label="Authentik",
            issuer_url=issuer.rstrip("/"),
            client_id=client_id,
            client_secret=client_secret,
            redirect_uri=cfg.AUTHENTIK_REDIRECT_URI or cfg.OIDC_REDIRECT_URI,
            scopes=cfg.AUTHENTIK_SCOPES or cfg.OIDC_SCOPES,
            skip_ssl_verify=cfg.OIDC_SKIP_SSL_VERIFY,
            allowed_emails=cfg.AUTHENTIK_ALLOWED_EMAILS or cfg.OIDC_ALLOWED_EMAILS,
            allowed_domains=cfg.AUTHENTIK_ALLOWED_DOMAINS or cfg.OIDC_ALLOWED_DOMAINS,
        )
    if provider == "oidc":
        if not cfg.OIDC_ISSUER_URL or not cfg.OIDC_CLIENT_ID or not cfg.OIDC_CLIENT_SECRET:
            return None
        return OIDCProviderConfig(
            provider="oidc",
            label=cfg.OIDC_PROVIDER_LABEL or "OpenID Connect",
            issuer_url=cfg.OIDC_ISSUER_URL.rstrip("/"),
            client_id=cfg.OIDC_CLIENT_ID,
            client_secret=cfg.OIDC_CLIENT_SECRET,
            redirect_uri=cfg.OIDC_REDIRECT_URI,
            scopes=cfg.OIDC_SCOPES,
            skip_ssl_verify=cfg.OIDC_SKIP_SSL_VERIFY,
            allowed_emails=cfg.OIDC_ALLOWED_EMAILS,
            allowed_domains=cfg.OIDC_ALLOWED_DOMAINS,
        )
    return None


def default_redirect_uri(request: Request) -> str:
    """Build the default OIDC callback URL for this request."""
    base = str(request.base_url).rstrip("/")
    return f"{base}/api/v1/auth/callback"


def create_oidc_state(next_url: str, settings: Settings | None = None) -> str:
    """Create a signed, short-lived OIDC state token."""
    cfg = settings or get_settings()
    payload = {
        "type": OIDC_STATE_COOKIE,
        "next": next_url,
        "exp": datetime.utcnow() + timedelta(seconds=OIDC_STATE_MAX_AGE),
    }
    return jwt.encode(payload, cfg.SECRET_KEY, algorithm=cfg.ALGORITHM)


def decode_oidc_state(value: str, settings: Settings | None = None) -> Optional[dict[str, Any]]:
    """Validate a signed OIDC state token and return its payload."""
    cfg = settings or get_settings()
    try:
        payload = jwt.decode(value, cfg.SECRET_KEY, algorithms=[cfg.ALGORITHM])
        if payload.get("type") != OIDC_STATE_COOKIE:
            return None
        return payload
    except (JWTError, TypeError, ValueError):
        return None


async def fetch_oidc_discovery(provider: OIDCProviderConfig) -> dict[str, Any]:
    """Fetch the provider's OIDC discovery document."""
    url = f"{provider.issuer_url}/.well-known/openid-configuration"
    async with httpx.AsyncClient(
        timeout=10,
        verify=not provider.skip_ssl_verify,
        follow_redirects=True,
    ) as client:
        response = await client.get(url)
        response.raise_for_status()
        metadata = response.json()
    if not metadata.get("authorization_endpoint") or not metadata.get("token_endpoint"):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="OIDC discovery document is missing required endpoints.",
        )
    return metadata


async def build_oidc_authorization_url(
    request: Request,
    provider: OIDCProviderConfig,
    *,
    next_url: str,
) -> tuple[str, str]:
    """Return the provider authorization URL and signed state token."""
    metadata = await fetch_oidc_discovery(provider)
    redirect_uri = provider.redirect_uri or default_redirect_uri(request)
    state = create_oidc_state(next_url)
    params = {
        "client_id": provider.client_id,
        "redirect_uri": redirect_uri,
        "response_type": "code",
        "scope": provider.scopes,
        "state": state,
    }
    return f"{metadata['authorization_endpoint']}?{urlencode(params)}", state


async def exchange_oidc_callback(
    request: Request,
    provider: OIDCProviderConfig,
    *,
    code: str,
) -> ExternalIdentityClaims:
    """Exchange an authorization code and return normalized user claims."""
    metadata = await fetch_oidc_discovery(provider)
    redirect_uri = provider.redirect_uri or default_redirect_uri(request)
    async with httpx.AsyncClient(
        timeout=10,
        verify=not provider.skip_ssl_verify,
        follow_redirects=True,
    ) as client:
        token_response = await client.post(
            metadata["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": provider.client_id,
                "client_secret": provider.client_secret,
            },
            headers={"Accept": "application/json"},
        )
        token_response.raise_for_status()
        token_payload = token_response.json()

        access_token = token_payload.get("access_token")
        claims_payload: dict[str, Any] = {}
        userinfo_endpoint = metadata.get("userinfo_endpoint")
        if access_token and userinfo_endpoint:
            userinfo_response = await client.get(
                userinfo_endpoint,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            userinfo_response.raise_for_status()
            claims_payload = userinfo_response.json()
        elif token_payload.get("id_token"):
            claims_payload = jwt.get_unverified_claims(token_payload["id_token"])

    return normalize_external_claims(
        provider.provider,
        claims_payload,
        allowed_emails=provider.allowed_emails,
        allowed_domains=provider.allowed_domains,
    )


def normalize_external_claims(
    provider: str,
    payload: dict[str, Any],
    *,
    allowed_emails: Optional[str] = None,
    allowed_domains: Optional[str] = None,
) -> ExternalIdentityClaims:
    """Normalize provider-specific claim JSON into the DMARQ user shape."""
    subject = str(payload.get("sub") or payload.get("uid") or "").strip()
    email = str(payload.get("email") or "").strip().lower()
    if not subject:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="OIDC provider did not return a stable subject claim.",
        )
    if not email_allowed(email, allowed_emails=allowed_emails, allowed_domains=allowed_domains):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Authenticated identity is not allowed to access this DMARQ instance.",
        )
    return ExternalIdentityClaims(
        provider=provider,
        subject=subject,
        email=email,
        name=payload.get("name"),
        username=payload.get("preferred_username") or payload.get("username"),
        picture=payload.get("picture"),
        email_verified=bool(payload.get("email_verified", False)),
    )


def sync_external_user(claims: ExternalIdentityClaims, db: Session) -> User:
    """Upsert a local user for a non-Logto external identity."""
    identity_id = f"{claims.provider}:{claims.subject}"
    user: Optional[User] = db.query(User).filter(User.logto_id == identity_id).first()
    if user is None:
        user = db.query(User).filter(User.email == claims.email).first()
        if user is not None:
            user.logto_id = identity_id
            logger.info("Linked user id=%d (%s) to %s", user.id, claims.email, identity_id)
    if user is None:
        user = User(
            logto_id=identity_id,
            email=claims.email,
            is_active=True,
            is_superuser=True,
            is_verified=claims.email_verified,
        )
        db.add(user)
        db.flush()
        logger.info("Created user id=%d from %s", user.id, identity_id)

    user.full_name = claims.name or user.full_name
    user.username = claims.username or user.username
    user.picture = claims.picture or user.picture
    user.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(user)
    return user


def trusted_proxy_claims_from_request(
    request: Request,
    settings: Settings | None = None,
) -> Optional[ExternalIdentityClaims]:
    """Return trusted-proxy claims when explicit trusted proxy auth is enabled."""
    cfg = settings or get_settings()
    if not getattr(cfg, "trusted_proxy_configured", False):
        return None
    email = request.headers.get(cfg.AUTH_TRUSTED_PROXY_EMAIL_HEADER, "").strip().lower()
    subject = request.headers.get(cfg.AUTH_TRUSTED_PROXY_SUBJECT_HEADER, "").strip()
    if not email:
        return None
    if not email_allowed(
        email,
        allowed_emails=cfg.AUTH_TRUSTED_PROXY_ALLOWED_EMAILS,
        allowed_domains=cfg.AUTH_TRUSTED_PROXY_ALLOWED_DOMAINS,
    ):
        return None
    provider = (cfg.AUTH_TRUSTED_PROXY_PROVIDER or "trusted_proxy").strip().lower()
    return ExternalIdentityClaims(
        provider=provider,
        subject=subject or email,
        email=email,
        name=request.headers.get(cfg.AUTH_TRUSTED_PROXY_NAME_HEADER),
        username=request.headers.get(cfg.AUTH_TRUSTED_PROXY_USERNAME_HEADER),
        email_verified=True,
    )


def trusted_proxy_auth_context(
    request: Request,
    settings: Settings | None = None,
) -> Optional[dict[str, Any]]:
    """Return an auth context for a trusted proxy identity."""
    claims = trusted_proxy_claims_from_request(request, settings)
    if claims is None:
        return None
    return {
        "auth_type": "trusted_proxy",
        "provider": claims.provider,
        "sub": f"{claims.provider}:{claims.subject}",
        "email": claims.email,
        "name": claims.name,
        "username": claims.username,
    }
