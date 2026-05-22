"""
Startup configuration checks for production deployments.
"""

import logging
from dataclasses import dataclass

from sqlalchemy.engine import make_url

from app.core.config import Settings

logger = logging.getLogger(__name__)


class StartupConfigurationError(RuntimeError):
    """Raised when production configuration is unsafe enough to block startup."""


@dataclass(frozen=True)
class StartupCheckResult:
    """Result of validating startup configuration."""

    errors: tuple[str, ...]
    warnings: tuple[str, ...]

    @property
    def ok(self) -> bool:
        return not self.errors


def _uses_sqlite(database_url: str) -> bool:
    try:
        return make_url(database_url).drivername.startswith("sqlite")
    except Exception:  # pylint: disable=broad-exception-caught
        return False


def validate_startup_configuration(settings: Settings) -> StartupCheckResult:
    """Return production startup errors and warnings for the provided settings."""
    errors: list[str] = []
    warnings: list[str] = []

    if not settings.is_production:
        return StartupCheckResult(errors=(), warnings=())

    if settings.AUTH_DISABLED and not settings.ALLOW_AUTH_DISABLED_IN_PRODUCTION:
        errors.append(
            "AUTH_DISABLED=true is not allowed in production unless "
            "ALLOW_AUTH_DISABLED_IN_PRODUCTION=true is also set."
        )

    if (
        settings.LOGTO_SKIP_SSL_VERIFY
        and not settings.ALLOW_LOGTO_SKIP_SSL_VERIFY_IN_PRODUCTION
    ):
        errors.append(
            "LOGTO_SKIP_SSL_VERIFY=true is not allowed in production unless "
            "ALLOW_LOGTO_SKIP_SSL_VERIFY_IN_PRODUCTION=true is also set."
        )

    if not settings.AUTH_DISABLED and not settings.ADMIN_API_KEY and not settings.logto_configured:
        errors.append(
            "Production startup requires Logto settings or ADMIN_API_KEY. "
            "Set LOGTO_ENDPOINT, LOGTO_APP_ID, and LOGTO_APP_SECRET, or set ADMIN_API_KEY."
        )

    if settings.ADMIN_API_KEY and len(settings.ADMIN_API_KEY) < 32:
        errors.append("ADMIN_API_KEY must be at least 32 characters in production.")

    if settings.SECRET_KEY is None or len(settings.SECRET_KEY) < 32:
        errors.append("SECRET_KEY must be at least 32 characters in production.")

    if _uses_sqlite(settings.DATABASE_URL):
        warnings.append(
            "DATABASE_URL uses SQLite in production. This is supported for small "
            "single-node deployments, but PostgreSQL is recommended for durable production use."
        )

    return StartupCheckResult(errors=tuple(errors), warnings=tuple(warnings))


def run_startup_checks(settings: Settings) -> StartupCheckResult:
    """Log startup validation results and raise when production config is unsafe."""
    result = validate_startup_configuration(settings)
    for warning in result.warnings:
        logger.warning("Startup configuration warning: %s", warning)

    if result.errors:
        for error in result.errors:
            logger.error("Startup configuration error: %s", error)
        raise StartupConfigurationError(
            "Unsafe production configuration: " + " ".join(result.errors)
        )

    return result
