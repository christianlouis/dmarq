"""
Authentication endpoints (Logto OIDC).

Routes
------
GET  /sign-in         – Initiate the Logto sign-in flow.
GET  /callback        – Handle the Logto authorization-code callback.
GET  /sign-out        – Sign the user out (clears session + redirects to Logto).
GET  /me              – Return the currently authenticated user's profile.
GET  /forgot-password – Redirect to Logto's forgot-password screen.
GET  /account-portal  – Redirect to the Logto account portal (MFA management).
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

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


def _safe_next(next_url: Optional[str]) -> str:
    """Validate and return a safe post-login redirect path."""
    if next_url and next_url.startswith("/") and not next_url.startswith("//"):
        return next_url
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


def _get_redirect_uri(request: Request) -> str:
    """Build the callback redirect URI, preferring the configured override."""
    if settings.LOGTO_REDIRECT_URI:
        return settings.LOGTO_REDIRECT_URI
    base = str(request.base_url).rstrip("/")
    return f"{base}/api/v1/auth/callback"


# ── Endpoints ─────────────────────────────────────────────────────────────────


@router.get("/sign-in")
async def sign_in(
    request: Request,
    next: Optional[str] = None,
) -> RedirectResponse:
    """
    Initiate the Logto OIDC sign-in flow.

    Stores the PKCE sign-in session in a short-lived cookie and redirects the
    browser to Logto's authorization endpoint.  The optional ``next`` query
    parameter is persisted in a separate cookie and used to redirect the user
    to their original page after a successful login.
    """
    if not settings.logto_configured:
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
            key="logto_next",
            value=safe,
            httponly=True,
            samesite="lax",
            max_age=600,  # 10 minutes – must survive the Logto redirect round-trip
        )

    return response


@router.get("/callback")
async def callback(
    request: Request,
    db: Session = Depends(get_db),
) -> RedirectResponse:
    """
    Handle the Logto authorization-code callback.

    Exchanges the code for tokens, validates the ID token, upserts the local
    user shadow record, issues the app-level session cookie, and clears the
    temporary Logto cookies.
    """
    if not settings.logto_configured:
        raise _logto_not_configured()

    storage = CookieStorage(request)
    client = make_logto_client(storage)

    try:
        await client.handleSignInCallback(str(request.url))
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.warning("Logto callback error: %s", exc)
        return RedirectResponse(url="/login?error=callback_failed", status_code=302)

    try:
        claims = await client.getIdTokenClaims()
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.warning("Failed to extract ID-token claims: %s", exc)
        return RedirectResponse(url="/login?error=token_error", status_code=302)

    user = sync_logto_user(claims, db)

    # Where to go after login
    next_url = _safe_next(request.cookies.get("logto_next"))

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
    response.delete_cookie(key="logto_next", httponly=True, samesite="lax")

    logger.info("User id=%d logged in via Logto.", user.id)
    return response


@router.get("/sign-out")
async def sign_out(request: Request) -> RedirectResponse:
    """
    Sign the user out.

    When ``AUTH_DISABLED=true`` there is nothing to sign out of; redirects to ``/``.

    Otherwise clears the app session cookie and redirects to Logto's end-session
    endpoint (if available) so that the Logto session is terminated too.
    """
    if settings.AUTH_DISABLED:
        return RedirectResponse(url="/", status_code=302)

    post_logout_url = str(request.base_url).rstrip("/")

    # Best-effort: obtain Logto's end-session URL from OIDC metadata.
    end_session_url: Optional[str] = None
    if settings.logto_configured:
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


@router.get("/forgot-password")
async def forgot_password(request: Request) -> RedirectResponse:
    """
    Redirect the user to Logto's forgot-password screen.

    Builds a standard Logto authorization URL and appends the
    ``first_screen=forgot_password`` parameter so that Logto shows the
    password-reset form immediately instead of the normal sign-in form.
    After the user resets their password they are returned via the normal
    callback flow and land on the app dashboard.
    """
    if not settings.logto_configured:
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


@router.get("/account-portal")
async def account_portal(request: Request) -> RedirectResponse:
    """
    Redirect an authenticated user to the Logto account portal.

    The Logto account portal (``{LOGTO_ENDPOINT}/account``) lets users manage
    their profile, linked identities, and multi-factor authentication settings
    without leaving the Logto-hosted UI.  After updating their settings, users
    can simply navigate back to the app.
    """
    if not settings.logto_configured:
        raise _logto_not_configured()

    portal_url = f"{settings.LOGTO_ENDPOINT.rstrip('/')}/account"
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
    # Auth-disabled: return a synthetic profile so the UI renders correctly.
    if settings.AUTH_DISABLED:
        return {
            "id": 0,
            "email": "admin@localhost",
            "full_name": "Local Admin",
            "username": "admin",
            "picture": None,
            "is_superuser": True,
            "logto_id": None,
            "auth_disabled": True,
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
    }
