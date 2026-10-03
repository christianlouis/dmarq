"""
Authentication redirect middleware.

Intercepts browser requests for protected HTML pages and redirects
unauthenticated visitors to ``/login`` (or ``/setup`` if Logto is not yet
configured).

API routes (``/api/…``) are intentionally left to handle their own 401
responses so that programmatic clients are not broken.
"""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from starlette.types import ASGIApp

from app.core.database import SessionLocal
from app.core.logto import SESSION_COOKIE, active_session_user_id

# Paths that are always publicly accessible
_PUBLIC_PATHS: frozenset[str] = frozenset(
    {
        "/login",
        "/setup",
        "/health",
        "/healthz",
    }
)

# Request path prefixes that bypass auth checks
_PUBLIC_PREFIXES: tuple[str, ...] = (
    "/api/",
    "/static/",
    "/docs",
    "/redoc",
    "/openapi",
)

# File extensions for static assets that are always publicly accessible
_STATIC_EXTENSIONS: tuple[str, ...] = (
    ".ico",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".webp",
    ".css",
    ".js",
    ".woff",
    ".woff2",
    ".ttf",
    ".eot",
    ".map",
)


def _is_public_path(path: str) -> bool:
    """Return whether browser auth should not intercept this path."""
    return (
        path in _PUBLIC_PATHS
        or any(path.startswith(prefix) for prefix in _PUBLIC_PREFIXES)
        or any(path.endswith(extension) for extension in _STATIC_EXTENSIONS)
    )


def _has_active_session(request: Request) -> bool:
    """Return whether the request's app session belongs to an active user."""
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return False
    db = SessionLocal()
    try:
        return active_session_user_id(token, db) is not None
    finally:
        db.close()


def _auth_redirect(request: Request, configured: bool) -> RedirectResponse:
    """Return the setup or login redirect for an unauthenticated browser request."""
    if not configured:
        setup_url = "/setup"
        if request.url.query:
            setup_url = f"{setup_url}?{request.url.query}"
        return RedirectResponse(url=setup_url, status_code=302)

    next_path = request.url.path
    if request.url.query:
        next_path = f"{next_path}?{request.url.query}"
    return RedirectResponse(url=f"/login?next={next_path}", status_code=302)


class AuthRedirectMiddleware(BaseHTTPMiddleware):
    """
    Redirect unauthenticated browser requests to the appropriate page.

    Decision tree
    -------------
    1. Path is public → pass through.
    2. Trusted proxy headers or session cookie present and valid → pass through.
    3. Browser auth not configured → redirect to ``/setup``.
    4. Otherwise → redirect to ``/login?next=<original_path>``.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[override]
        path = request.url.path

        # ── 0. Auth disabled globally ─────────────────────────────────────────
        from app.core.config import get_settings  # local import avoids circular dep

        cfg = get_settings()
        if cfg.AUTH_DISABLED or getattr(cfg, "active_auth_provider", "") == "disabled":
            return await call_next(request)

        # ── 1. Public paths & prefixes ────────────────────────────────────────
        if _is_public_path(path):
            return await call_next(request)

        # ── 2. Trusted proxy / Authentik Outpost headers ─────────────────────
        from app.core.auth_providers import trusted_proxy_auth_context

        if trusted_proxy_auth_context(request, cfg) is not None:
            return await call_next(request)

        # ── 3. Valid session cookie ───────────────────────────────────────────
        if _has_active_session(request):
            return await call_next(request)

        # ── 4. Browser auth not configured ───────────────────────────────────
        return _auth_redirect(request, getattr(cfg, "auth_configured", False))
