"""
Authentication endpoints (Logto, Authentik/OIDC, and trusted proxy).

Routes
------
GET  /sign-in          – Initiate the configured sign-in flow.
GET  /callback         – Handle the configured authorization-code callback.
GET  /sign-out         – Sign the user out.
GET  /me               – Return the currently authenticated user's profile.
GET  /forgot-password  – Redirect to Logto's forgot-password screen (unauthenticated).
GET  /change-password  – Redirect to Logto Account Center password page (authenticated).
GET  /manage-mfa       – Redirect to Logto Account Center MFA page (authenticated).
GET  /account-portal   – Redirect to the Logto Account Center root.
"""

from __future__ import annotations

import logging
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from app.core.auth_providers import (
    OIDC_STATE_COOKIE,
    OIDC_STATE_MAX_AGE,
    auth_provider_registry,
    build_oidc_authorization_url,
    configured_oidc_provider,
    decode_oidc_state,
    enforce_mfa_claims,
    exchange_oidc_callback,
    sync_external_user,
    trusted_proxy_claims_from_request,
)
from app.core.config import get_settings
from app.core.database import get_db
from app.core.logto import (
    SESSION_COOKIE,
    CookieStorage,
    create_session_token,
    decode_session_token,
    make_logto_client,
    sync_logto_user,
)
from app.models.user import User

router = APIRouter()
logger = logging.getLogger(__name__)
settings = get_settings()

# ── Helpers ───────────────────────────────────────────────────────────────────

_SAFE_NEXT_PREFIXES = ("/",)  # only allow relative redirects after login
_NEXT_COOKIE = "logto_next"
_NEXT_COOKIE_MAX_AGE = 600


def _safe_next(next_url: Optional[str]) -> str:
    """Validate and return a safe post-login redirect path."""
    if next_url and next_url.startswith("/") and not next_url.startswith("//"):
        return next_url
    return "/"


def _create_next_cookie(next_url: str) -> str:
    """Create a short-lived signed cookie for the post-login redirect path."""
    payload = {
        "type": _NEXT_COOKIE,
        "next": _safe_next(next_url),
        "exp": datetime.utcnow() + timedelta(seconds=_NEXT_COOKIE_MAX_AGE),
    }
    return jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)


def _decode_next_cookie(value: Optional[str]) -> str:
    """Validate the signed next cookie and return a safe redirect path."""
    if not value:
        return "/"
    try:
        payload = jwt.decode(value, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        if payload.get("type") != _NEXT_COOKIE:
            return "/"
        return _safe_next(payload.get("next"))
    except (JWTError, TypeError, ValueError):
        return "/"


def _logto_not_configured() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=(
            "Logto is not configured. "
            "Set LOGTO_ENDPOINT, LOGTO_APP_ID, and LOGTO_APP_SECRET "
            "in your environment."
        ),
    )


def _auth_not_configured() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=(
            "Authentication is not configured. Configure Logto, Authentik/OIDC, "
            "trusted proxy authentication, or AUTH_DISABLED=true for local use."
        ),
    )


def _active_auth_provider() -> str:
    provider = getattr(settings, "active_auth_provider", None)
    if isinstance(provider, str):
        return provider
    return "logto" if getattr(settings, "logto_configured", False) else "unconfigured"


def _get_redirect_uri(request: Request) -> str:
    """Build the callback redirect URI, preferring the configured override."""
    if settings.LOGTO_REDIRECT_URI:
        return settings.LOGTO_REDIRECT_URI
    base = str(request.base_url).rstrip("/")
    return f"{base}/api/v1/auth/callback"


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.get("/providers")
async def auth_providers() -> dict[str, Any]:
    """Return configured and available browser-auth provider options."""
    return {
        "active_provider": _active_auth_provider(),
        "active_label": settings.auth_provider_label,
        "auth_configured": settings.auth_configured,
        "providers": auth_provider_registry(settings),
    }


@router.get("/sign-in")
async def sign_in(
    request: Request,
    next: Optional[str] = None,
) -> RedirectResponse:
    """
    Initiate the configured sign-in flow.

    Logto keeps its SDK-backed PKCE storage.  Generic OIDC/AuthentiK uses a
    signed state cookie.  Trusted proxy mode does not own the upstream sign-in
    flow, so this route returns to a fixed local page.
    """
    provider_name = _active_auth_provider()
    if provider_name == "trusted_proxy":
        return RedirectResponse(url="/", status_code=302)

    if provider_name in {"oidc", "authentik"}:
        provider = configured_oidc_provider(settings)
        if provider is None:
            raise _auth_not_configured()
        safe = _safe_next(next)
        try:
            sign_in_url, state_token = await build_oidc_authorization_url(
                request,
                provider,
                next_url=safe,
            )
        except HTTPException:
            raise
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.warning("%s sign-in initialization failed: %s", provider.label, exc)
            return RedirectResponse(url="/login?error=callback_failed", status_code=302)
        response = RedirectResponse(url=sign_in_url, status_code=302)
        response.set_cookie(
            key=OIDC_STATE_COOKIE,
            value=state_token,
            httponly=True,
            samesite="lax",
            max_age=OIDC_STATE_MAX_AGE,
        )
        return response

    if _active_auth_provider() != "logto" or not settings.logto_configured:
        raise _logto_not_configured()

    storage = CookieStorage(request)
    client = make_logto_client(storage)

    sign_in_url: str = await client.signIn(redirectUri=_get_redirect_uri(request))

    response = RedirectResponse(url=sign_in_url, status_code=302)
    storage.apply_to_response(response)

    # Persist the post-login destination so the callback can redirect there.
    safe = _safe_next(next)
    if safe != "/":
        response.set_cookie(
            key=_NEXT_COOKIE,
            value=_create_next_cookie(safe),
            httponly=True,
            samesite="lax",
            max_age=_NEXT_COOKIE_MAX_AGE,
        )

    return response


async def _handle_external_oidc_callback(
    request: Request,
    db: Session,
) -> RedirectResponse:
    """Handle the generic OIDC/AuthentiK authorization-code callback."""
    provider = configured_oidc_provider(settings)
    if provider is None:
        raise _auth_not_configured()

    query_state = request.query_params.get("state")
    cookie_state = request.cookies.get(OIDC_STATE_COOKIE)
    state_payload = decode_oidc_state(query_state or "", settings)
    if not query_state or query_state != cookie_state or state_payload is None:
        return RedirectResponse(url="/login?error=callback_failed", status_code=302)

    code = request.query_params.get("code")
    if not code:
        return RedirectResponse(url="/login?error=callback_failed", status_code=302)

    try:
        claims = await exchange_oidc_callback(request, provider, code=code, settings=settings)
        user = sync_external_user(claims, db)
    except HTTPException as exc:
        logger.warning("%s callback rejected: %s", provider.label, exc.detail)
        return RedirectResponse(url="/login?error=callback_failed", status_code=302)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.warning("%s callback error: %s", provider.label, exc)
        return RedirectResponse(url="/login?error=token_error", status_code=302)

    response = RedirectResponse(url=_safe_next(state_payload.get("next")), status_code=302)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=create_session_token(user.id),
        httponly=True,
        samesite="lax",
        max_age=86_400,
    )
    response.delete_cookie(key=OIDC_STATE_COOKIE, httponly=True, samesite="lax")
    logger.info("User id=%d logged in via %s.", user.id, provider.label)
    return response


@router.get("/callback")
async def callback(
    request: Request,
    db: Session = Depends(get_db),
) -> RedirectResponse:
    """
    Handle the configured authorization-code callback.

    Exchanges the code for tokens, upserts the local user shadow record, issues
    the app-level session cookie, and clears temporary provider cookies.
    """
    provider_name = _active_auth_provider()
    if provider_name in {"oidc", "authentik"}:
        return await _handle_external_oidc_callback(request, db)

    if provider_name != "logto" or not settings.logto_configured:
        raise _logto_not_configured()

    storage = CookieStorage(request)
    client = make_logto_client(storage)

    try:
        await client.handleSignInCallback(str(request.url))
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.warning("Logto callback error: %s", exc)
        return RedirectResponse(url="/login?error=callback_failed", status_code=302)

    try:
        claims = client.getIdTokenClaims()
        enforce_mfa_claims(claims, settings)
    except HTTPException as exc:
        logger.warning("Logto callback rejected: %s", exc.detail)
        return RedirectResponse(url="/login?error=callback_failed", status_code=302)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.warning("Failed to extract ID-token claims: %s", exc)
        return RedirectResponse(url="/login?error=token_error", status_code=302)

    user = sync_logto_user(claims, db)

    # Where to go after login
    next_url = _decode_next_cookie(request.cookies.get(_NEXT_COOKIE))

    response = RedirectResponse(url=next_url, status_code=302)

    # Issue our own session cookie (independent of Logto from here on)
    session_token = create_session_token(user.id)
    response.set_cookie(
        key=SESSION_COOKIE,
        value=session_token,
        httponly=True,
        samesite="lax",
        max_age=86_400,  # 24 hours
    )

    # Clean up all temporary Logto & next cookies
    storage.clear_all_logto_cookies(response)
    response.delete_cookie(key=_NEXT_COOKIE, httponly=True, samesite="lax")

    logger.info("User id=%d logged in via Logto.", user.id)
    return response


@router.get("/sign-out")
async def sign_out(request: Request) -> RedirectResponse:
    """
    Sign the user out.

    When ``AUTH_DISABLED=true`` there is nothing to sign out of; redirects to ``/``.

    Logto deployments use Logto's end-session endpoint when available.  Generic
    OIDC/AuthentiK and trusted-proxy deployments clear DMARQ's session and
    return to the login page.
    """
    if settings.AUTH_DISABLED or _active_auth_provider() == "disabled":
        return RedirectResponse(url="/", status_code=302)

    post_logout_url = str(request.base_url).rstrip("/")

    # Best-effort: obtain Logto's end-session URL from OIDC metadata.
    end_session_url: Optional[str] = None
    if _active_auth_provider() == "logto" and settings.logto_configured:
        try:
            storage = CookieStorage(request)
            client = make_logto_client(storage)
            core = await client.getOidcCore()
            end_session_url = getattr(core.metadata, "end_session_endpoint", None)
        except Exception:  # pylint: disable=broad-exception-caught
            pass

    if end_session_url:
        redirect_to = f"{end_session_url}?post_logout_redirect_uri={post_logout_url}"
    else:
        redirect_to = "/login"

    response = RedirectResponse(url=redirect_to, status_code=302)
    response.delete_cookie(key=SESSION_COOKIE, httponly=True, samesite="lax")
    return response


@router.get("/change-password")
async def change_password(request: Request) -> RedirectResponse:
    """
    Redirect an authenticated user to the Logto Account Center password page.

    Uses Logto's prebuilt Account Center flow at ``{LOGTO_ENDPOINT}/account/password``
    so the user can change their existing password directly.  A ``redirect``
    query parameter is appended so that Logto returns the user to the Profile &
    Security page after a successful update.
    """
    if _active_auth_provider() != "logto" or not settings.logto_configured:
        raise _logto_not_configured()

    base = str(request.base_url).rstrip("/")
    password_url = f"{settings.LOGTO_ENDPOINT.rstrip('/')}/account/password?redirect={base}/profile"
    return RedirectResponse(url=password_url, status_code=302)


@router.get("/forgot-password")
async def forgot_password(request: Request) -> RedirectResponse:
    """
    Redirect the user to Logto's forgot-password screen.

    Builds a standard Logto authorization URL and appends the
    ``first_screen=forgot_password`` parameter so that Logto shows the
    password-reset form immediately instead of the normal sign-in form.
    After the user resets their password they are returned via the normal
    callback flow and land on the app dashboard.

    This endpoint is kept for unauthenticated / "I forgot my password" use
    cases.  Authenticated users should use ``/change-password`` instead.
    """
    if _active_auth_provider() != "logto" or not settings.logto_configured:
        raise _logto_not_configured()

    storage = CookieStorage(request)
    client = make_logto_client(storage)

    sign_in_url: str = await client.signIn(redirectUri=_get_redirect_uri(request))

    # Append the Logto-specific first_screen parameter so the password-reset
    # form is shown directly.  The sign-in URL normally already contains a "?"
    # but we defensively detect the right separator in case the structure varies.
    separator = "&" if "?" in sign_in_url else "?"
    forgot_url = f"{sign_in_url}{separator}first_screen=forgot_password"

    response = RedirectResponse(url=forgot_url, status_code=302)
    storage.apply_to_response(response)
    return response


@router.get("/manage-mfa")
async def manage_mfa(request: Request) -> RedirectResponse:
    """
    Redirect an authenticated user to the Logto Account Center MFA page.

    Uses Logto's prebuilt Account Center flow at
    ``{LOGTO_ENDPOINT}/account/authenticator-app`` so the user can enable,
    configure, or remove TOTP authenticator-app MFA directly.  A ``redirect``
    query parameter is appended so that Logto returns the user to the Profile &
    Security page after a successful update.
    """
    if _active_auth_provider() != "logto" or not settings.logto_configured:
        raise _logto_not_configured()

    base = str(request.base_url).rstrip("/")
    mfa_url = (
        f"{settings.LOGTO_ENDPOINT.rstrip('/')}/account/authenticator-app"
        f"?redirect={base}/profile"
    )
    return RedirectResponse(url=mfa_url, status_code=302)


@router.get("/account-portal")
async def account_portal(request: Request) -> RedirectResponse:
    """
    Redirect an authenticated user to the Logto Account Center.

    The Logto account portal (``{LOGTO_ENDPOINT}/account``) lets users manage
    their profile, linked identities, and multi-factor authentication settings
    without leaving the Logto-hosted UI.  A ``redirect`` query parameter is
    appended so that Logto returns the user to the Profile & Security page
    after a successful update.
    """
    if _active_auth_provider() != "logto" or not settings.logto_configured:
        raise _logto_not_configured()

    base = str(request.base_url).rstrip("/")
    portal_url = f"{settings.LOGTO_ENDPOINT.rstrip('/')}/account?redirect={base}/profile"
    return RedirectResponse(url=portal_url, status_code=302)


@router.get("/me", response_model=None)
async def get_current_user(
    request: Request,
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """
    Return the profile of the currently authenticated user.

    When ``AUTH_DISABLED=true`` a synthetic anonymous-admin profile is returned
    so that UI components (e.g. the navbar user menu) work without a real session.

    Otherwise reads the ``dmarq_session`` cookie (issued at callback time) and
    looks up the corresponding local ``User`` record.
    """
    provider_name = _active_auth_provider()

    # Auth-disabled: return a synthetic profile so the UI renders correctly.
    if settings.AUTH_DISABLED or provider_name == "disabled":
        return {
            "id": 0,
            "email": "admin@localhost",
            "full_name": "Local Admin",
            "username": "admin",
            "picture": None,
            "is_superuser": True,
            "logto_id": None,
            "auth_disabled": True,
            "auth_provider": "disabled",
            "auth_provider_label": "No authentication",
        }

    trusted_claims = trusted_proxy_claims_from_request(request, settings)
    if trusted_claims is not None:
        return {
            "id": 0,
            "email": trusted_claims.email,
            "full_name": trusted_claims.name,
            "username": trusted_claims.username,
            "picture": trusted_claims.picture,
            "is_superuser": True,
            "logto_id": f"{trusted_claims.provider}:{trusted_claims.subject}",
            "auth_disabled": False,
            "auth_provider": trusted_claims.provider,
            "auth_provider_label": getattr(settings, "auth_provider_label", "Trusted proxy"),
        }

    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated",
        )

    user_id = decode_session_token(token)
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired session",
        )

    user: Optional[User] = (
        db.query(User).filter(User.id == user_id, User.is_active == True).first()  # noqa: E712
    )
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )

    return {
        "id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "username": user.username,
        "picture": user.picture,
        "is_superuser": user.is_superuser,
        "logto_id": user.logto_id,
        "auth_provider": provider_name,
        "auth_provider_label": getattr(settings, "auth_provider_label", "Authentication"),
    }
