"""Demo-mode request guard."""

from __future__ import annotations

from typing import Any, Callable

from fastapi import Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from app.core.config import get_settings

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})
DEMO_BACKFILL_SOURCE_IDS = frozenset({"9001", "9002", "9003"})


def _is_demo_backfill_simulation(request: Request) -> bool:
    if request.method.upper() != "POST":
        return False
    parts = request.url.path.strip("/").split("/")
    return (
        len(parts) >= 5
        and parts[:3] == ["api", "v1", "mail-sources"]
        and parts[3] in DEMO_BACKFILL_SOURCE_IDS
        and parts[4] == "backfills"
    )


def _is_demo_support_session_simulation(request: Request) -> bool:
    return request.url.path in {
        "/api/v1/operator/demo/support-session",
        "/api/v1/operator/support-session",
    } and request.method.upper() in {"POST", "DELETE"}


class DemoReadOnlyMiddleware(BaseHTTPMiddleware):
    """Block mutating requests when the public demo data mode is enabled."""

    def __init__(
        self,
        app,
        settings_provider: Callable[[], Any] = get_settings,
    ) -> None:
        super().__init__(app)
        self._settings_provider = settings_provider

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        settings = self._settings_provider()
        if (
            settings.DEMO_MODE
            and request.method.upper() not in SAFE_METHODS
            and not _is_demo_backfill_simulation(request)
            and not _is_demo_support_session_simulation(request)
        ):
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={
                    "detail": (
                        "This public demo is read-only. "
                        "Deploy DMARQ with DEMO_MODE=false to make changes."
                    )
                },
            )
        return await call_next(request)
