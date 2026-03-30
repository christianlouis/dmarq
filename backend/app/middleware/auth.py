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

from app.core.logto import SESSION_COOKIE, decode_session_token

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


class AuthRedirectMiddleware(BaseHTTPMiddleware):
    """
    Redirect unauthenticated browser requests to the appropriate page.

    Decision tree
    -------------
    1. Path is public → pass through.
    2. Session cookie present and valid → pass through.
    3. Logto not configured → redirect to ``/setup``.
    4. Otherwise → redirect to ``/login?next=<original_path>``.
    """

    def __init__(self, app: ASGIApp) -> None:
        super().__init__(app)

    async def dispatch(self, request: Request, call_next) -> Response:  # type: ignore[override]
        path = request.url.path

        # ── 1. Public paths & prefixes ────────────────────────────────────────
        if path in _PUBLIC_PATHS:
            return await call_next(request)
        if any(path.startswith(p) for p in _PUBLIC_PREFIXES):
            return await call_next(request)

        # ── 2. Valid session cookie ───────────────────────────────────────────
        token = request.cookies.get(SESSION_COOKIE)
        if token and decode_session_token(token) is not None:
            return await call_next(request)

        # ── 3. Logto not configured ───────────────────────────────────────────
        from app.core.config import get_settings  # local import avoids circular dep

        if not get_settings().logto_configured:
            return RedirectResponse(url="/setup", status_code=302)

        # ── 4. Redirect to login ──────────────────────────────────────────────
        next_path = request.url.path
        if request.url.query:
            next_path = f"{next_path}?{request.url.query}"
        return RedirectResponse(url=f"/login?next={next_path}", status_code=302)
