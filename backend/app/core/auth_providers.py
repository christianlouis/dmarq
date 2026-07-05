"""Provider-neutral authentication helpers for external identity providers."""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Optional
from urllib.parse import urlencode

import httpx
from fastapi import HTTPException, Request, status
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.core.config import Settings, get_settings
from app.models.organization import Organization, OrganizationMembership
from app.models.user import User
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceMembership
from app.services.workspace_access import ORGANIZATION_ROLE_ALIASES, ROLE_PERMISSIONS

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
    group_workspace_role_map: Optional[str] = None
    group_organization_role_map: Optional[str] = None


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
    groups: tuple[str, ...] = ()
    workspace_roles: tuple[tuple[str, str], ...] = ()
    organization_roles: tuple[tuple[str, str], ...] = ()
    mfa_verified: bool = False
    mfa_claims: tuple[str, ...] = ()


@dataclass(frozen=True)
class AuthProviderOption:
    """Operator-facing auth provider preset metadata."""

    provider: str
    label: str
    auth_mode: str
    status: str
    deployment_model: str
    setup_hint: str
    secret_fields: tuple[str, ...] = ()
    docs_url: str | None = None
    supports_direct_oidc: bool = False
    supports_trusted_proxy: bool = False
    supports_single_user: bool = False
    supports_multi_user: bool = False
    supports_mfa_policy: bool = False

    def as_dict(self, settings: Settings | None = None) -> dict[str, Any]:
        """Return JSON/template-safe provider metadata."""
        cfg = settings or get_settings()
        return {
            "provider": self.provider,
            "label": self.label,
            "auth_mode": self.auth_mode,
            "status": self.status,
            "deployment_model": self.deployment_model,
            "setup_hint": self.setup_hint,
            "secret_fields": list(self.secret_fields),
            "docs_url": self.docs_url,
            "supports_direct_oidc": self.supports_direct_oidc,
            "supports_trusted_proxy": self.supports_trusted_proxy,
            "supports_single_user": self.supports_single_user,
            "supports_multi_user": self.supports_multi_user,
            "supports_mfa_policy": self.supports_mfa_policy,
            "active": getattr(cfg, "active_auth_provider", "unconfigured") == self.provider,
            "configured": auth_provider_configured(self.provider, cfg),
            "mfa_policy": {
                "required": self.supports_mfa_policy
                and _enabled_flag(getattr(cfg, "AUTH_REQUIRE_MFA", False)),
                "claim_names": sorted(_split_csv(getattr(cfg, "AUTH_MFA_CLAIM_NAMES", ""))),
            },
        }


AUTH_PROVIDER_OPTIONS: tuple[AuthProviderOption, ...] = (
    AuthProviderOption(
        provider="disabled",
        label="No app auth",
        auth_mode="disabled",
        status="ready",
        deployment_model="Self-hosted behind a trusted network, VPN, or access proxy",
        setup_hint=(
            "Use only when DMARQ is protected outside the app. Public unauthenticated "
            "deployments are blocked in production unless explicitly allowed."
        ),
        supports_single_user=True,
    ),
    AuthProviderOption(
        provider="local",
        label="Local admin",
        auth_mode="local",
        status="planned",
        deployment_model="Standalone self-hosted recovery and small installs",
        setup_hint=(
            "Local bootstrap users exist, but a full browser login/session flow is still "
            "tracked separately from this provider registry."
        ),
        secret_fields=("FIRST_SUPERUSER_PASSWORD",),
        supports_single_user=True,
    ),
    AuthProviderOption(
        provider="logto",
        label="Logto",
        auth_mode="logto",
        status="ready",
        deployment_model="Hosted or self-hosted OIDC identity provider",
        setup_hint="Set LOGTO_ENDPOINT, LOGTO_APP_ID, and LOGTO_APP_SECRET.",
        secret_fields=("LOGTO_APP_SECRET",),
        docs_url="https://docs.logto.io/",
        supports_direct_oidc=True,
        supports_single_user=True,
        supports_multi_user=True,
        supports_mfa_policy=True,
    ),
    AuthProviderOption(
        provider="authentik",
        label="Authentik OIDC",
        auth_mode="authentik",
        status="ready",
        deployment_model="Direct Authentik OAuth2/OpenID provider",
        setup_hint=(
            "Create an Authentik OAuth2/OpenID provider and set AUTHENTIK_ISSUER_URL, "
            "AUTHENTIK_CLIENT_ID, and AUTHENTIK_CLIENT_SECRET."
        ),
        secret_fields=("AUTHENTIK_CLIENT_SECRET",),
        docs_url="https://docs.goauthentik.io/docs/add-secure-apps/providers/oauth2/",
        supports_direct_oidc=True,
        supports_single_user=True,
        supports_multi_user=True,
        supports_mfa_policy=True,
    ),
    AuthProviderOption(
        provider="trusted_proxy",
        label="Trusted proxy / Authentik Outpost",
        auth_mode="trusted_proxy",
        status="ready",
        deployment_model="Reverse-proxy enforced SSO in front of DMARQ",
        setup_hint=(
            "Use only when the proxy is the sole public path to DMARQ and strips any "
            "incoming spoofed identity headers."
        ),
        docs_url="https://docs.goauthentik.io/docs/add-secure-apps/outposts/",
        supports_trusted_proxy=True,
        supports_single_user=True,
        supports_multi_user=True,
        supports_mfa_policy=True,
    ),
    AuthProviderOption(
        provider="oidc",
        label="Generic OIDC",
        auth_mode="oidc",
        status="ready",
        deployment_model="Provider-neutral OIDC for Keycloak, Entra ID, Google, Okta, and others",
        setup_hint=(
            "Set OIDC_ISSUER_URL, OIDC_CLIENT_ID, OIDC_CLIENT_SECRET, and optionally "
            "OIDC_PROVIDER_LABEL plus allowlists."
        ),
        secret_fields=("OIDC_CLIENT_SECRET",),
        docs_url="https://openid.net/developers/how-connect-works/",
        supports_direct_oidc=True,
        supports_single_user=True,
        supports_multi_user=True,
        supports_mfa_policy=True,
    ),
    AuthProviderOption(
        provider="keycloak",
        label="Keycloak",
        auth_mode="oidc",
        status="ready_via_generic_oidc",
        deployment_model="Self-hosted or enterprise Keycloak realm/client",
        setup_hint="Use AUTH_MODE=oidc and set OIDC_PROVIDER_LABEL=Keycloak.",
        secret_fields=("OIDC_CLIENT_SECRET",),
        docs_url="https://www.keycloak.org/docs/latest/securing_apps/",
        supports_direct_oidc=True,
        supports_single_user=True,
        supports_multi_user=True,
        supports_mfa_policy=True,
    ),
    AuthProviderOption(
        provider="entra_id",
        label="Microsoft Entra ID",
        auth_mode="oidc",
        status="ready_via_generic_oidc",
        deployment_model="Commercial enterprise IdP",
        setup_hint="Use AUTH_MODE=oidc with the Entra issuer and group/app-role claims.",
        secret_fields=("OIDC_CLIENT_SECRET",),
        docs_url="https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc",
        supports_direct_oidc=True,
        supports_single_user=True,
        supports_multi_user=True,
        supports_mfa_policy=True,
    ),
    AuthProviderOption(
        provider="google_workspace",
        label="Google Workspace",
        auth_mode="oidc",
        status="ready_via_generic_oidc",
        deployment_model="Google-managed identity for self-hosted or team deployments",
        setup_hint="Use AUTH_MODE=oidc and restrict access with OIDC_ALLOWED_EMAILS or domains.",
        secret_fields=("OIDC_CLIENT_SECRET",),
        docs_url="https://developers.google.com/identity/openid-connect/openid-connect",
        supports_direct_oidc=True,
        supports_single_user=True,
        supports_multi_user=True,
        supports_mfa_policy=True,
    ),
    AuthProviderOption(
        provider="cloudflare_access",
        label="Cloudflare Access",
        auth_mode="trusted_proxy",
        status="planned",
        deployment_model="Access proxy in front of DMARQ",
        setup_hint=(
            "Tracked as a trusted-proxy preset. DMARQ must validate the trusted proxy "
            "boundary before accepting Cloudflare identity headers."
        ),
        docs_url="https://developers.cloudflare.com/cloudflare-one/applications/",
        supports_trusted_proxy=True,
        supports_single_user=True,
        supports_multi_user=True,
        supports_mfa_policy=True,
    ),
    AuthProviderOption(
        provider="akamai_eaa",
        label="Akamai EAA",
        auth_mode="trusted_proxy",
        status="planned",
        deployment_model="Enterprise access proxy in front of DMARQ",
        setup_hint=(
            "Tracked as a trusted-proxy preset for EAA-protected deployments; DNS account "
            "linking belongs to the separate Edge DNS/FastDNS connector work."
        ),
        docs_url="https://techdocs.akamai.com/eaa/docs",
        supports_trusted_proxy=True,
        supports_single_user=True,
        supports_multi_user=True,
        supports_mfa_policy=True,
    ),
)


def auth_provider_registry(settings: Settings | None = None) -> list[dict[str, Any]]:
    """Return operator-facing auth provider presets."""
    return [option.as_dict(settings) for option in AUTH_PROVIDER_OPTIONS]


OIDC_PRESET_DISCRIMINATORS: dict[str, tuple[tuple[str, ...], tuple[str, ...]]] = {
    "keycloak": (("keycloak",), ("keycloak",)),
    "entra_id": (
        ("entra id", "microsoft entra id", "azure ad", "microsoft"),
        ("login.microsoftonline.com", "sts.windows.net", "microsoftonline.com"),
    ),
    "google_workspace": (
        ("google workspace", "google"),
        ("accounts.google.com", "google.com"),
    ),
}


def _generic_oidc_matches_preset(provider: str, settings: Settings) -> bool:
    """Return True when generic OIDC config explicitly names a known preset."""
    labels, issuer_fragments = OIDC_PRESET_DISCRIMINATORS.get(provider, ((), ()))
    provider_label = (settings.OIDC_PROVIDER_LABEL or "").strip().lower()
    issuer_url = (settings.OIDC_ISSUER_URL or "").strip().lower()
    return provider_label in labels or any(fragment in issuer_url for fragment in issuer_fragments)


def auth_provider_configured(provider: str, settings: Settings | None = None) -> bool:
    """Return True when a provider has enough config to be used."""
    cfg = settings or get_settings()
    if provider == "disabled":
        return cfg.active_auth_provider == "disabled"
    if provider == "logto":
        return cfg.logto_configured
    if provider == "authentik":
        return cfg.authentik_configured
    if provider == "trusted_proxy":
        return cfg.trusted_proxy_configured
    if provider == "oidc":
        return cfg.generic_oidc_configured
    if provider in {"keycloak", "entra_id", "google_workspace"}:
        return (
            cfg.active_auth_provider == "oidc"
            and cfg.generic_oidc_configured
            and _generic_oidc_matches_preset(provider, cfg)
        )
    if provider == "local":
        return bool(cfg.FIRST_SUPERUSER and cfg.FIRST_SUPERUSER_PASSWORD)
    return False


def _split_csv(value: Optional[str]) -> set[str]:
    if not value:
        return set()
    return {item.strip().lower() for item in value.split(",") if item.strip()}


def _split_csv_sequence(value: Optional[str]) -> tuple[str, ...]:
    if not value:
        return ()
    normalized: list[str] = []
    seen = set()
    for item in value.split(","):
        text = item.strip().lower()
        if text and text not in seen:
            normalized.append(text)
            seen.add(text)
    return tuple(normalized)


def _enabled_flag(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return False


def _claim_value(payload: Any, name: str) -> Any:
    if isinstance(payload, Mapping):
        return payload.get(name)
    value = getattr(payload, name, None)
    if isinstance(value, (str, int, float, bool, list, tuple, set)):
        return value
    return None


def _flatten_claim_values(value: Any) -> tuple[str, ...]:
    """Return claim values as lower-case tokens without exposing raw claim payloads."""
    if value is None:
        return ()
    if isinstance(value, str):
        raw_values = re.split(r"[\s,]+", value)
    elif isinstance(value, (list, tuple, set)):
        raw_values = []
        for item in value:
            raw_values.extend(_flatten_claim_values(item))
    elif isinstance(value, (int, float, bool)):
        raw_values = [str(value)]
    else:
        return ()

    normalized: list[str] = []
    seen = set()
    for item in raw_values:
        text = str(item).strip().lower()
        if text and text not in seen:
            normalized.append(text)
            seen.add(text)
    return tuple(normalized)


def _mfa_claim_names(settings: Settings | None = None) -> tuple[str, ...]:
    cfg = settings or get_settings()
    return _split_csv_sequence(getattr(cfg, "AUTH_MFA_CLAIM_NAMES", "amr,acr"))


def _mfa_claim_values(settings: Settings | None = None) -> set[str]:
    cfg = settings or get_settings()
    return _split_csv(getattr(cfg, "AUTH_MFA_CLAIM_VALUES", "mfa,otp,totp,webauthn,hwk,swk,phr"))


def mfa_claim_context(
    payload: Any, settings: Settings | None = None
) -> tuple[bool, tuple[str, ...]]:
    """Return whether IdP claims satisfy the configured MFA policy."""
    names = _mfa_claim_names(settings)
    accepted = _mfa_claim_values(settings)
    observed: list[str] = []
    seen = set()
    verified = False
    for name in names:
        for value in _flatten_claim_values(_claim_value(payload, name)):
            claim = f"{name}:{value}"
            if claim not in seen:
                observed.append(claim)
                seen.add(claim)
            if value in accepted:
                verified = True
    return verified, tuple(observed)


def enforce_mfa_claims(
    provider: str,
    payload: Any,
    settings: Settings | None = None,
) -> tuple[bool, tuple[str, ...]]:
    """Return MFA claim context and enforce the deployment policy when required."""
    mfa_verified, mfa_claims = mfa_claim_context(payload, settings)
    _enforce_mfa_policy(mfa_verified=mfa_verified, provider=provider, settings=settings)
    return mfa_verified, mfa_claims


def _enforce_mfa_policy(
    *,
    mfa_verified: bool,
    provider: str,
    settings: Settings | None = None,
) -> None:
    cfg = settings or get_settings()
    if not _enabled_flag(getattr(cfg, "AUTH_REQUIRE_MFA", False)) or mfa_verified:
        return
    logger.warning("Rejecting %s login because MFA assurance claims were not present", provider)
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail=(
            "This DMARQ deployment requires MFA at the identity provider, but the "
            "login did not include an accepted MFA assurance claim."
        ),
    )


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
            group_workspace_role_map=(
                cfg.AUTHENTIK_GROUP_WORKSPACE_ROLE_MAP or cfg.OIDC_GROUP_WORKSPACE_ROLE_MAP
            ),
            group_organization_role_map=(
                cfg.AUTHENTIK_GROUP_ORGANIZATION_ROLE_MAP or cfg.OIDC_GROUP_ORGANIZATION_ROLE_MAP
            ),
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
            group_workspace_role_map=cfg.OIDC_GROUP_WORKSPACE_ROLE_MAP,
            group_organization_role_map=cfg.OIDC_GROUP_ORGANIZATION_ROLE_MAP,
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
    settings: Settings | None = None,
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
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=(
                    "OIDC provider did not expose a userinfo endpoint; "
                    "refusing to trust unvalidated ID-token claims."
                ),
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="OIDC provider did not return usable identity claims.",
            )

    return normalize_external_claims(
        provider.provider,
        claims_payload,
        allowed_emails=provider.allowed_emails,
        allowed_domains=provider.allowed_domains,
        group_workspace_role_map=provider.group_workspace_role_map,
        group_organization_role_map=provider.group_organization_role_map,
        settings=settings,
    )


def normalize_external_claims(
    provider: str,
    payload: dict[str, Any],
    *,
    allowed_emails: Optional[str] = None,
    allowed_domains: Optional[str] = None,
    group_workspace_role_map: Optional[str] = None,
    group_organization_role_map: Optional[str] = None,
    settings: Settings | None = None,
) -> ExternalIdentityClaims:
    """Normalize provider-specific claim JSON into the DMARQ user shape."""
    cfg = settings or get_settings()
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
    groups = _normalize_string_claims(payload.get("groups") or payload.get("roles"))
    workspace_roles = _merge_role_pairs(
        _normalize_role_claims(
            payload.get("dmarq_workspace_roles") or payload.get("workspace_roles"),
            allowed_roles=set(ROLE_PERMISSIONS),
        ),
        _role_pairs_from_group_map(
            groups,
            group_workspace_role_map,
            allowed_roles=set(ROLE_PERMISSIONS),
        ),
    )
    organization_roles = _merge_role_pairs(
        _normalize_role_claims(
            payload.get("dmarq_organization_roles") or payload.get("organization_roles"),
            allowed_roles=set(ORGANIZATION_ROLE_ALIASES) | set(ROLE_PERMISSIONS),
        ),
        _role_pairs_from_group_map(
            groups,
            group_organization_role_map,
            allowed_roles=set(ORGANIZATION_ROLE_ALIASES) | set(ROLE_PERMISSIONS),
        ),
    )
    mfa_verified, mfa_claims = enforce_mfa_claims(provider, payload, cfg)
    return ExternalIdentityClaims(
        provider=provider,
        subject=subject,
        email=email,
        name=payload.get("name"),
        username=payload.get("preferred_username") or payload.get("username"),
        picture=payload.get("picture"),
        email_verified=bool(payload.get("email_verified", False)),
        groups=groups,
        workspace_roles=workspace_roles,
        organization_roles=organization_roles,
        mfa_verified=mfa_verified,
        mfa_claims=mfa_claims,
    )


def _normalize_string_claims(value: Any) -> tuple[str, ...]:
    """Return a stable tuple from common IdP string/list claim shapes."""
    if value is None:
        return ()
    if isinstance(value, str):
        values = value.split(",")
    elif isinstance(value, (list, tuple, set)):
        values = value
    else:
        return ()
    normalized = []
    seen = set()
    for item in values:
        text = str(item).strip()
        key = text.lower()
        if text and key not in seen:
            normalized.append(text)
            seen.add(key)
    return tuple(normalized)


def _normalize_role_value(role: Any, *, allowed_roles: set[str]) -> str:
    normalized = str(role or "").strip().lower()
    return normalized if normalized in allowed_roles else ""


def _merge_role_pairs(*role_sets: tuple[tuple[str, str], ...]) -> tuple[tuple[str, str], ...]:
    normalized: list[tuple[str, str]] = []
    seen = set()
    for role_set in role_sets:
        for slug, role in role_set:
            if slug in seen:
                continue
            normalized.append((slug, role))
            seen.add(slug)
    return tuple(normalized)


def _role_pairs_from_group_map(
    groups: tuple[str, ...],
    mapping: Optional[str],
    *,
    allowed_roles: set[str],
) -> tuple[tuple[str, str], ...]:
    """Return role pairs granted by configured IdP group mappings.

    Mapping syntax is a comma- or semicolon-separated list of
    ``group-name=target-slug:role`` entries. Repeating a group grants multiple
    target roles.
    """
    if not groups or not mapping:
        return ()

    group_keys = {group.strip().lower() for group in groups if group.strip()}
    mapped_pairs: list[tuple[str, str]] = []
    for index, entry in enumerate(re.split(r"[,;]", mapping), start=1):
        if "=" not in entry:
            logger.warning("Ignoring malformed group-role mapping entry at position=%d", index)
            continue
        group, assignment = entry.split("=", 1)
        if group.strip().lower() not in group_keys:
            continue
        parsed_any = False
        for slug, role in _split_role_string(assignment):
            parsed_any = True
            normalized_role = _normalize_role_value(role, allowed_roles=allowed_roles)
            normalized_slug = slug.strip().lower()
            if normalized_slug and normalized_role:
                mapped_pairs.append((normalized_slug, normalized_role))
            else:
                logger.warning(
                    "Ignoring group-role mapping entry with invalid target at position=%d",
                    index,
                )
        if not parsed_any:
            logger.warning(
                "Ignoring group-role mapping entry without a target at position=%d",
                index,
            )
    return _merge_role_pairs(tuple(mapped_pairs))


def _extend_role_pairs_from_sequence(raw_pairs: list[tuple[Any, Any]], values: Any) -> None:
    for item in values:
        if isinstance(item, dict):
            slug = item.get("workspace") or item.get("organization") or item.get("slug")
            raw_pairs.append((slug, item.get("role")))
        elif isinstance(item, str):
            raw_pairs.extend(_split_role_string(item))


def _normalize_role_claims(
    value: Any,
    *,
    allowed_roles: set[str],
) -> tuple[tuple[str, str], ...]:
    """Normalize provider role claims into ``(slug, role)`` pairs.

    Accepted shapes:
    - {"workspace-slug": "workspace_owner"}
    - ["workspace-slug:workspace_owner"]
    - [{"workspace": "workspace-slug", "role": "workspace_owner"}]
    - [{"slug": "workspace-slug", "role": "workspace_owner"}]
    """
    if value is None:
        return ()

    raw_pairs: list[tuple[Any, Any]] = []
    if isinstance(value, dict):
        raw_pairs.extend(value.items())
    elif isinstance(value, str):
        raw_pairs.extend(_split_role_string(value))
    elif isinstance(value, (list, tuple, set)):
        _extend_role_pairs_from_sequence(raw_pairs, value)

    normalized: list[tuple[str, str]] = []
    seen = set()
    for raw_slug, raw_role in raw_pairs:
        slug = str(raw_slug or "").strip().lower()
        role = _normalize_role_value(raw_role, allowed_roles=allowed_roles)
        if not slug or not role:
            continue
        key = (slug, role)
        if key in seen:
            continue
        normalized.append(key)
        seen.add(key)
    return tuple(normalized)


def _split_role_string(value: str) -> list[tuple[str, str]]:
    pairs = []
    for item in value.split(","):
        if ":" in item:
            slug, role = item.split(":", 1)
        elif "=" in item:
            slug, role = item.split("=", 1)
        else:
            continue
        pairs.append((slug, role))
    return pairs


def _upsert_workspace_membership(
    db: Session,
    *,
    user: User,
    workspace_slug: str,
    role: str,
) -> Optional[WorkspaceMembership]:
    workspace = (
        db.query(Workspace)
        .filter(
            Workspace.slug == workspace_slug,
            Workspace.active.is_(True),
        )
        .first()
    )
    if workspace is None:
        logger.info(
            "Ignoring external workspace role for unknown workspace user_id=%s",
            user.id,
        )
        return None
    membership = (
        db.query(WorkspaceMembership)
        .filter(
            WorkspaceMembership.workspace_id == workspace.id,
            WorkspaceMembership.user_id == user.id,
        )
        .first()
    )
    if membership is None:
        membership = WorkspaceMembership(workspace_id=workspace.id, user_id=user.id, role=role)
        db.add(membership)
    else:
        membership.role = role
        membership.active = True
        membership.updated_at = datetime.utcnow()
    if user.workspace_id is None:
        user.workspace_id = workspace.id
    return membership


def _upsert_organization_membership(
    db: Session,
    *,
    user: User,
    organization_slug: str,
    role: str,
) -> Optional[OrganizationMembership]:
    organization = (
        db.query(Organization)
        .filter(
            Organization.slug == organization_slug,
            Organization.active.is_(True),
        )
        .first()
    )
    if organization is None:
        logger.info(
            "Ignoring external organization role for unknown organization user_id=%s",
            user.id,
        )
        return None
    membership = (
        db.query(OrganizationMembership)
        .filter(
            OrganizationMembership.organization_id == organization.id,
            OrganizationMembership.user_id == user.id,
        )
        .first()
    )
    if membership is None:
        membership = OrganizationMembership(
            organization_id=organization.id,
            user_id=user.id,
            role=role,
        )
        db.add(membership)
    else:
        membership.role = role
        membership.active = True
        membership.updated_at = datetime.utcnow()
    return membership


def _sync_external_memberships(claims: ExternalIdentityClaims, user: User, db: Session) -> None:
    for workspace_slug, role in claims.workspace_roles:
        _upsert_workspace_membership(db, user=user, workspace_slug=workspace_slug, role=role)
    for organization_slug, role in claims.organization_roles:
        _upsert_organization_membership(
            db,
            user=user,
            organization_slug=organization_slug,
            role=role,
        )


def sync_external_user(claims: ExternalIdentityClaims, db: Session) -> User:
    """Upsert a local user for a non-Logto external identity."""
    identity_id = f"{claims.provider}:{claims.subject}"
    user: Optional[User] = db.query(User).filter(User.logto_id == identity_id).first()
    if user is None:
        user = db.query(User).filter(User.email == claims.email).first()
        if user is not None:
            user.logto_id = identity_id
            logger.info("Linked user id=%d to external provider=%s", user.id, claims.provider)
    if user is None:
        user = User(
            logto_id=identity_id,
            email=claims.email,
            is_active=True,
            is_superuser=not bool(claims.workspace_roles or claims.organization_roles),
            is_verified=claims.email_verified,
        )
        db.add(user)
        db.flush()
        logger.info("Created user id=%d from external provider=%s", user.id, claims.provider)

    user.full_name = claims.name or user.full_name
    user.username = claims.username or user.username
    user.picture = claims.picture or user.picture
    if claims.workspace_roles or claims.organization_roles:
        user.is_superuser = False
    user.updated_at = datetime.utcnow()
    _sync_external_memberships(claims, user, db)
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
    groups = _normalize_string_claims(request.headers.get(cfg.AUTH_TRUSTED_PROXY_GROUPS_HEADER))
    mfa_header = getattr(cfg, "AUTH_TRUSTED_PROXY_MFA_HEADER", "X-Authentik-Meta-Amr")
    mfa_verified, mfa_claims = enforce_mfa_claims(
        provider,
        {"amr": request.headers.get(mfa_header)},
        cfg,
    )
    return ExternalIdentityClaims(
        provider=provider,
        subject=subject or email,
        email=email,
        name=request.headers.get(cfg.AUTH_TRUSTED_PROXY_NAME_HEADER),
        username=request.headers.get(cfg.AUTH_TRUSTED_PROXY_USERNAME_HEADER),
        email_verified=True,
        groups=groups,
        workspace_roles=_role_pairs_from_group_map(
            groups,
            cfg.AUTH_TRUSTED_PROXY_GROUP_WORKSPACE_ROLE_MAP,
            allowed_roles=set(ROLE_PERMISSIONS),
        ),
        organization_roles=_role_pairs_from_group_map(
            groups,
            cfg.AUTH_TRUSTED_PROXY_GROUP_ORGANIZATION_ROLE_MAP,
            allowed_roles=set(ORGANIZATION_ROLE_ALIASES) | set(ROLE_PERMISSIONS),
        ),
        mfa_verified=mfa_verified,
        mfa_claims=mfa_claims,
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
        "mfa_verified": claims.mfa_verified,
    }
