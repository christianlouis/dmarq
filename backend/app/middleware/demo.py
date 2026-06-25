"""Demo-mode request guard."""

from __future__ import annotations

from typing import Any, Callable

from fastapi import Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

from app.core.config import get_settings

SAFE_METHODS = frozenset({"GET", "HEAD", "OPTIONS"})


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
        if settings.DEMO_MODE and request.method.upper() not in SAFE_METHODS:
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
