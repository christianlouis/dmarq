"""Application timezone helpers for presentation (storage remains UTC)."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Optional
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

logger = logging.getLogger(__name__)

DEFAULT_APP_TIMEZONE = "UTC"


def resolve_app_timezone_name(value: Optional[str]) -> str:
    """Return a valid IANA timezone name, falling back to UTC when invalid."""
    raw = (value or "").strip() or DEFAULT_APP_TIMEZONE
    try:
        ZoneInfo(raw)
    except (ZoneInfoNotFoundError, ValueError, TypeError, KeyError):
        logger.warning(
            "Invalid APP_TIMEZONE %r; falling back to %s",
            raw,
            DEFAULT_APP_TIMEZONE,
        )
        return DEFAULT_APP_TIMEZONE
    return raw


def app_zoneinfo(name: Optional[str] = None) -> ZoneInfo:
    """Resolve ZoneInfo for an explicit presentation timezone, defaulting to UTC."""
    return ZoneInfo(resolve_app_timezone_name(name or DEFAULT_APP_TIMEZONE))


def ensure_utc(value: datetime) -> datetime:
    """Treat naive datetimes as UTC storage and normalize to aware UTC."""
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def present_datetime(
    value: Optional[datetime],
    *,
    tz_name: Optional[str] = None,
) -> Optional[datetime]:
    """Convert a stored UTC datetime into the application presentation zone."""
    if value is None:
        return None
    return ensure_utc(value).astimezone(app_zoneinfo(tz_name))


def format_datetime_for_display(
    value: Optional[datetime],
    *,
    tz_name: Optional[str] = None,
) -> Optional[str]:
    """Format a stored UTC datetime for UI/API presentation strings."""
    presented = present_datetime(value, tz_name=tz_name)
    if presented is None:
        return None
    return presented.isoformat()
