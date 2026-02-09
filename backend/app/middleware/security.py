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

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from typing import Callable
import logging

logger = logging.getLogger(__name__)


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
        
        # Content Security Policy (CSP)
        # Restricts sources of content that can be loaded
        csp_directives = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval'",  # Allow inline scripts for now
            "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
            "font-src 'self' https://fonts.gstatic.com",
            "img-src 'self' data: https:",
            "connect-src 'self'",
            "frame-ancestors 'none'",  # Prevent framing
            "base-uri 'self'",
            "form-action 'self'"
        ]
        response.headers["Content-Security-Policy"] = "; ".join(csp_directives)
        
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
            "usb=()"
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


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Simple rate limiting middleware to prevent abuse.
    For production, consider using a more robust solution like slowapi or Redis-based rate limiting.
    """
    
    def __init__(self, app, requests_per_minute: int = 60):
        """
        Initialize rate limiting middleware.
        
        Args:
            app: FastAPI application instance
            requests_per_minute: Maximum requests allowed per minute per IP
        """
        super().__init__(app)
        self.requests_per_minute = requests_per_minute
        self.request_counts = {}  # Simple in-memory store (not production-ready)
        logger.warning(
            "Using in-memory rate limiting. "
            "For production, use Redis or similar distributed storage."
        )
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """
        Check rate limit and process request.
        
        Args:
            request: Incoming HTTP request
            call_next: Next middleware/handler in the chain
            
        Returns:
            HTTP response or 429 Too Many Requests if rate limit exceeded
        """
        # Get client IP
        client_ip = request.client.host if request.client else "unknown"
        
        # For now, just log and pass through
        # TODO: Implement actual rate limiting logic with time windows
        # This is a placeholder for the actual implementation
        
        response = await call_next(request)
        
        # Add rate limit headers for transparency
        response.headers["X-RateLimit-Limit"] = str(self.requests_per_minute)
        
        return response
