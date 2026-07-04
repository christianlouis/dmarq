"""
Security headers middleware for DMARQ application.

Implements various security headers to protect against common web vulnerabilities:
- Content Security Policy (CSP)
- X-Frame-Options
- X-Content-Type-Options
- Strict-Transport-Security (HSTS)
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy
"""

import logging
import os
from typing import Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

logger = logging.getLogger(__name__)


def _strict_csp_directives() -> list[str]:
    """Return the target CSP once templates and Alpine runtime are fully migrated."""
    return [
        "default-src 'self'",
        "script-src 'self'",
        "style-src 'self' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com",
        "img-src 'self' data: https:",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
    ]


def _relaxed_csp_directives() -> list[str]:
    """Return the compatibility CSP required by current Alpine expressions."""
    return [
        "default-src 'self'",
        "script-src 'self' 'unsafe-eval'",
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
        "font-src 'self' https://fonts.gstatic.com",
        "img-src 'self' data: https:",
        "connect-src 'self'",
        "frame-ancestors 'none'",
        "base-uri 'self'",
        "form-action 'self'",
    ]


def _truthy_env(name: str) -> bool:
    """Return whether a boolean environment flag is enabled."""
    return os.environ.get(name, "false").strip().lower() in {"1", "true", "yes", "on"}


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add security headers to all HTTP responses.
    """

    def __init__(self, app, environment: str = "development"):
        """
        Initialize security headers middleware.

        Args:
            app: FastAPI application instance
            environment: Application environment (development/production)
        """
        super().__init__(app)
        self.environment = environment

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Process the request and add security headers to the response.

        Args:
            request: Incoming HTTP request
            call_next: Next middleware/handler in the chain

        Returns:
            HTTP response with security headers added
        """
        response = await call_next(request)

        # Content Security Policy (CSP). Default remains compatibility mode for the
        # current CDN Alpine runtime; operators can enable the strict target policy
        # after validating their deployment with CSP_REPORT_ONLY=true.
        csp_directives = (
            _strict_csp_directives()
            if _truthy_env("CSP_ENFORCE_STRICT")
            else _relaxed_csp_directives()
        )
        response.headers["Content-Security-Policy"] = "; ".join(csp_directives)

        if _truthy_env("CSP_REPORT_ONLY"):
            report_only_directives = _strict_csp_directives()
            response.headers["Content-Security-Policy-Report-Only"] = "; ".join(
                report_only_directives
            )

        # X-Frame-Options: Prevent clickjacking attacks
        # 'DENY' prevents the page from being displayed in a frame
        response.headers["X-Frame-Options"] = "DENY"

        # X-Content-Type-Options: Prevent MIME type sniffing
        # Forces browsers to respect the declared Content-Type
        response.headers["X-Content-Type-Options"] = "nosniff"

        # X-XSS-Protection: Enable browser XSS protection
        # Note: Modern browsers rely more on CSP, but this provides defense-in-depth
        response.headers["X-XSS-Protection"] = "1; mode=block"

        # Referrer-Policy: Control referrer information
        # 'strict-origin-when-cross-origin' provides good balance of privacy and functionality
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Permissions-Policy: Control browser features
        # Disable features that aren't needed
        permissions_policies = [
            "accelerometer=()",
            "camera=()",
            "geolocation=()",
            "gyroscope=()",
            "magnetometer=()",
            "microphone=()",
            "payment=()",
            "usb=()",
        ]
        response.headers["Permissions-Policy"] = ", ".join(permissions_policies)

        # Strict-Transport-Security (HSTS): Force HTTPS
        # Only enable in production with HTTPS
        if self.environment == "production":
            # max-age=31536000 = 1 year
            # includeSubDomains applies to all subdomains
            # preload allows inclusion in browser HSTS preload lists
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )

        # Cache-Control for sensitive pages
        # Prevent caching of potentially sensitive data
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, private"
            response.headers["Pragma"] = "no-cache"
            response.headers["Expires"] = "0"

        return response
