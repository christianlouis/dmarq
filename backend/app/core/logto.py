"""
Logto OIDC integration helpers.

Provides:
- ``CookieStorage``       – Logto SDK Storage adapter backed by HTTP cookies.
- ``make_logto_client``   – Factory that builds a per-request LogtoClient.
- ``create_session_token``/``decode_session_token`` – thin JWT helpers for the
  app-level session cookie (independent of Logto after the initial callback).
- ``sync_logto_user``     – Upserts the local User shadow record from Logto claims.
"""

from __future__ import annotations

import logging
import ssl
from datetime import datetime, timedelta
from typing import Optional

import aiohttp
from fastapi import Request, Response
from jose import JWTError, jwt
from logto import IdTokenClaims, LogtoClient, LogtoConfig, PersistKey, Storage, UserInfoScope
from logto.models.oidc import OAuthScope
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.user import User

logger = logging.getLogger(__name__)
settings = get_settings()

# ── Constants ────────────────────────────────────────────────────────────────

SESSION_COOKIE = "dmarq_session"

# Short-lived: only needed while the browser is being redirected to Logto and back.
_SIGN_IN_SESSION_MAX_AGE = 600  # 10 minutes
# The app-level session lasts 24 hours by default; the Logto ID-token has its own
# expiry but we don't keep it in the browser beyond the callback request.
_SESSION_MAX_AGE = 86_400  # 24 hours


# ── SSL configuration for Logto SDK ──────────────────────────────────────────


def _apply_logto_ssl_patch() -> None:
    """
    If ``LOGTO_SKIP_SSL_VERIFY`` is ``True``, monkey-patch both
    ``aiohttp.ClientSession`` and the ``PyJWKClient`` used by the Logto SDK so
    that every connection to the Logto OIDC endpoint skips SSL certificate
    verification.

    Two patches are applied:

    1. **aiohttp.ClientSession** – The Logto SDK creates its own
       ``aiohttp.ClientSession`` objects internally (for the OIDC discovery
       document and token-endpoint requests) and provides no mechanism to
       inject an SSL context.  Replacing the class at module level is the
       only way to propagate the setting without forking the SDK.

    2. **PyJWKClient** inside ``logto.OidcCore`` – The Logto SDK uses
       ``PyJWKClient`` (from PyJWT) to fetch and verify the JWKS for
       ID-token signature validation.  ``PyJWKClient`` uses ``urllib``
       internally, *not* ``aiohttp``, so the first patch does not cover it.
       We replace the ``PyJWKClient`` reference in the ``logto.OidcCore``
       module so that every ``OidcCore`` instance gets a client that passes
       the non-verifying SSL context to ``urllib``.

    **Scope note:** ``aiohttp`` is not used anywhere else in this application
    – only the Logto SDK pulls it in.  If additional code in this repository
    starts using ``aiohttp`` directly, review whether those connections should
    also skip verification before enabling this setting.

    .. warning::
        Disabling SSL verification removes protection against man-in-the-middle
        attacks.  Only enable this when connecting to a Logto instance that uses
        a self-signed certificate that you control.
    """
    if not settings.LOGTO_SKIP_SSL_VERIFY:
        return

    logger.warning(
        "LOGTO_SKIP_SSL_VERIFY is enabled – SSL certificate verification for "
        "Logto OIDC connections is DISABLED.  Use this only when your Logto "
        "instance uses a self-signed certificate.  Never enable this in a "
        "production environment that faces the public internet."
    )

    ssl_ctx = ssl.create_default_context()
    ssl_ctx.check_hostname = False
    ssl_ctx.verify_mode = ssl.CERT_NONE

    # ── Patch 1: aiohttp.ClientSession ───────────────────────────────────────
    # Covers OIDC discovery-document and token-endpoint requests.

    _OriginalClientSession = aiohttp.ClientSession

    class _NoVerifyClientSession(_OriginalClientSession):  # type: ignore[misc]
        """``aiohttp.ClientSession`` subclass that disables SSL verification."""

        def __init__(self, *args, **kwargs) -> None:  # type: ignore[override]
            if "connector" not in kwargs:
                kwargs["connector"] = aiohttp.TCPConnector(ssl=ssl_ctx)
                kwargs.setdefault("connector_owner", True)
            super().__init__(*args, **kwargs)

    aiohttp.ClientSession = _NoVerifyClientSession  # type: ignore[assignment]

    # ── Patch 2: PyJWKClient inside logto.OidcCore ────────────────────────────
    # Covers JWKS fetching for ID-token signature verification.
    # PyJWKClient uses urllib internally, so Patch 1 does not cover it.
    try:
        import logto.OidcCore as _oidc_module  # noqa: PLC0415
        from jwt import PyJWKClient as _OrigPyJWKClient  # noqa: PLC0415

        class _NoVerifyPyJWKClient(_OrigPyJWKClient):  # type: ignore[misc]
            """``PyJWKClient`` subclass that injects a non-verifying SSL context."""

            def __init__(self, *args, **kwargs) -> None:  # type: ignore[override]
                kwargs.setdefault("ssl_context", ssl_ctx)
                super().__init__(*args, **kwargs)

        _oidc_module.PyJWKClient = _NoVerifyPyJWKClient  # type: ignore[attr-defined]
    except Exception as _exc:  # pylint: disable=broad-exception-caught
        logger.warning(
            "Failed to patch PyJWKClient for LOGTO_SKIP_SSL_VERIFY: %s. "
            "JWKS fetching will still verify SSL certificates, which may cause "
            "ID-token verification to fail when using a self-signed certificate.",
            _exc,
        )


_apply_logto_ssl_patch()


# ── Cookie-backed Logto Storage ───────────────────────────────────────────────


class CookieStorage(Storage):
    """
    Storage adapter for the Logto SDK that persists the OIDC session data
    (sign-in session, tokens) in HTTP-only cookies.

    Usage::

        storage = CookieStorage(request)
        client  = make_logto_client(storage)
        url     = await client.signIn(redirect_uri=…)
        # build a response, then:
        storage.apply_to_response(response)
        return response
    """

    _COOKIE_PREFIX = "logto_"

    def __init__(self, request: Request) -> None:
        self._request = request
        # Pending writes/deletes – applied to the Response via apply_to_response().
        self._writes: dict[str, Optional[str]] = {}
        self._deletes: set[str] = set()

    # ── Storage protocol ──────────────────────────────────────────────────────

    def get(self, key: PersistKey) -> Optional[str]:  # type: ignore[override]
        if key in self._writes:
            return self._writes[key]
        if key in self._deletes:
            return None
        return self._request.cookies.get(self._COOKIE_PREFIX + key)

    def set(self, key: PersistKey, value: Optional[str]) -> None:  # type: ignore[override]
        self._writes[key] = value
        self._deletes.discard(key)

    def delete(self, key: PersistKey) -> None:  # type: ignore[override]
        self._deletes.add(key)
        self._writes.pop(key, None)

    # ── Response helper ───────────────────────────────────────────────────────

    def apply_to_response(self, response: Response) -> None:
        """Flush pending cookie mutations onto *response*."""
        for key, value in self._writes.items():
            if value is None:
                continue
            max_age = _SIGN_IN_SESSION_MAX_AGE if key == "signInSession" else _SESSION_MAX_AGE
            response.set_cookie(
                key=self._COOKIE_PREFIX + key,
                value=value,
                httponly=True,
                samesite="lax",
                max_age=max_age,
            )
        for key in self._deletes:
            response.delete_cookie(
                key=self._COOKIE_PREFIX + key,
                httponly=True,
                samesite="lax",
            )

    def clear_all_logto_cookies(self, response: Response) -> None:
        """Remove every Logto cookie (called after we've issued our own session)."""
        for key in ("signInSession", "idToken", "accessTokenMap", "refreshToken"):
            response.delete_cookie(
                key=self._COOKIE_PREFIX + key,
                httponly=True,
                samesite="lax",
            )


# ── LogtoClient factory ───────────────────────────────────────────────────────


def make_logto_client(storage: CookieStorage) -> LogtoClient:
    """Return a per-request ``LogtoClient`` bound to *storage*."""
    return LogtoClient(
        LogtoConfig(
            endpoint=settings.LOGTO_ENDPOINT or "",
            appId=settings.LOGTO_APP_ID or "",
            appSecret=settings.LOGTO_APP_SECRET,
            scopes=[
                UserInfoScope.email,
                UserInfoScope.profile,
                OAuthScope.offlineAccess,
            ],
        ),
        storage=storage,
    )


# ── App-level session JWT (independent of Logto after first login) ────────────


def create_session_token(user_id: int) -> str:
    """Mint a signed HS256 JWT for *user_id* with a 24-hour lifetime."""
    payload = {
        "sub": str(user_id),
        "type": "dmarq_session",
        "exp": datetime.utcnow() + timedelta(seconds=_SESSION_MAX_AGE),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def decode_session_token(token: str) -> Optional[int]:
    """
    Validate *token* and return the user's local DB id.

    Returns ``None`` on any error (expired, wrong type, bad signature, …).
    """
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != "dmarq_session":
            return None
        return int(payload["sub"])
    except (JWTError, ValueError, TypeError):
        return None


# ── Local user sync ───────────────────────────────────────────────────────────


def sync_logto_user(claims: IdTokenClaims, db: Session) -> User:
    """
    Upsert the local ``User`` shadow record from Logto ID-token claims.

    Lookup order:
    1. Match on ``logto_id`` (``sub`` claim) – fastest, stable.
    2. Fall back to matching on email if the user was created before Logto
       integration and doesn't have a ``logto_id`` yet.
    3. Create a brand-new record if neither match.

    All users are treated as admins (``is_superuser=True``) until RBAC is
    added in a future milestone.
    """
    logto_id: str = claims.sub
    email: str = claims.email or f"{logto_id}@logto.local"

    # 1. Try existing Logto-linked user
    user: Optional[User] = db.query(User).filter(User.logto_id == logto_id).first()

    if user is None:
        # 2. Try to link a legacy user by email
        user = db.query(User).filter(User.email == email).first()
        if user is not None:
            user.logto_id = logto_id
            logger.info(
                "Linked existing user id=%d (%s) to Logto sub=%s",
                user.id,
                email,
                logto_id,
            )

    if user is None:
        # 3. Create new user
        user = User(
            logto_id=logto_id,
            email=email,
            is_active=True,
            is_superuser=True,
            is_verified=bool(getattr(claims, "email_verified", False)),
        )
        db.add(user)
        db.flush()  # populate user.id before commit
        logger.info("Created new user id=%d from Logto sub=%s (%s)", user.id, logto_id, email)

    # Always refresh profile from latest claims
    user.full_name = getattr(claims, "name", None) or user.full_name
    user.username = getattr(claims, "username", None) or user.username
    user.picture = getattr(claims, "picture", None) or user.picture
    user.updated_at = datetime.utcnow()

    db.commit()
    db.refresh(user)
    return user
