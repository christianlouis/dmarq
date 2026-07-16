from datetime import date, datetime, time, timedelta, timezone
from math import ceil
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Path, Query, status
from sqlalchemy.orm import Session

from app.core.config import get_settings, uses_legacy_demo_fixtures
from app.core.database import get_db
from app.core.security import require_admin_auth
from app.services.demo_data import build_demo_dashboard_statistics
from app.services.workspace_access import (
    PERMISSION_REPORTS_READ,
    parse_selected_workspace_id,
    resolve_authorized_workspace,
)
from app.utils.stats_summarizer import StatsSummarizer

router = APIRouter()


DATE_INTERVALS = {
    "last_24_hours": "Last 24 hours",
    "last_48_hours": "Last 48 hours",
    "last_7_days": "Last 7 days",
    "last_30_days": "Last 30 days",
    "last_90_days": "Last 90 days",
    "week_to_date": "Week to date",
    "month_to_date": "Month to date",
    "custom": "Custom",
}


def _parse_date(value: str, field_name: str) -> date:
    try:
        return date.fromisoformat(value)
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{field_name} must use YYYY-MM-DD format",
        ) from exc


def _date_range_response(
    *,
    interval: str,
    label: str,
    start_at: datetime,
    end_at: datetime,
    is_filtered: bool = True,
) -> Dict[str, Any]:
    seconds = max(1, int((end_at - start_at).total_seconds()))
    return {
        "interval": interval,
        "label": label,
        "is_filtered": is_filtered,
        "start_at": start_at.isoformat(),
        "end_at": end_at.isoformat(),
        "start_date": start_at.date().isoformat(),
        "end_date": (end_at - timedelta(seconds=1)).date().isoformat(),
        "period_days": max(1, ceil(seconds / 86400)),
    }


def _custom_date_range(start_date: Optional[str], end_date: Optional[str]) -> Dict[str, Any]:
    if not start_date or not end_date:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="custom interval requires start_date and end_date",
        )
    start_day = _parse_date(start_date, "start_date")
    end_day = _parse_date(end_date, "end_date")
    if end_day < start_day:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="end_date must be on or after start_date",
        )
    start_at = datetime.combine(start_day, time.min, tzinfo=timezone.utc)
    end_at = datetime.combine(end_day + timedelta(days=1), time.min, tzinfo=timezone.utc)
    return _date_range_response(
        interval="custom",
        label=f"{start_day.isoformat()} to {end_day.isoformat()}",
        start_at=start_at,
        end_at=end_at,
    )


def _rolling_date_range(now: datetime, interval: str, days: int) -> Dict[str, Any]:
    interval_name = interval if interval in DATE_INTERVALS else f"last_{days}_days"
    # Rolling day presets are calendar-day windows in UTC. Starting at midnight
    # keeps Dashboard and Reports on the same set of included dates.
    start_day = now.date() - timedelta(days=days - 1)
    return _date_range_response(
        interval=interval_name,
        label=DATE_INTERVALS.get(interval_name, f"Last {days} days"),
        start_at=datetime.combine(start_day, time.min, tzinfo=timezone.utc),
        end_at=now,
    )


def _to_date_range(now: datetime, interval: str) -> Dict[str, Any]:
    today = now.date()
    if interval == "week_to_date":
        start_day = today - timedelta(days=today.weekday())
    else:
        start_day = today.replace(day=1)
    return _date_range_response(
        interval=interval,
        label=DATE_INTERVALS[interval],
        start_at=datetime.combine(start_day, time.min, tzinfo=timezone.utc),
        end_at=now,
    )


def _days_from_interval(interval: str, fallback_days: Optional[int]) -> int:
    if interval.startswith("last_") and interval.endswith("_days"):
        try:
            return int(interval.removeprefix("last_").removesuffix("_days"))
        except ValueError:
            pass
    return int(fallback_days or 30)


def _summary_cache_key(date_range: Dict[str, Any]) -> str:
    """Build a stable cache key for resolved dashboard windows."""
    interval = str(date_range["interval"])
    if interval == "custom":
        return f"custom_{date_range['start_date']}_{date_range['end_date']}"
    if interval in {"week_to_date", "month_to_date"}:
        return f"{interval}_{date_range['start_date']}"
    return interval


def resolve_dashboard_date_range(
    *,
    interval: Optional[str] = None,
    period_days: Optional[int] = None,
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
) -> Dict[str, Any]:
    """Resolve dashboard interval presets and custom dates into UTC boundaries."""
    now = datetime.now(timezone.utc)
    requested_interval = (interval or "").strip().lower()
    selected = requested_interval
    if selected not in DATE_INTERVALS:
        if period_days is not None:
            selected = f"last_{period_days}_days"
        else:
            selected = "last_30_days"

    if selected == "custom":
        return _custom_date_range(start_date, end_date)

    if selected == "last_24_hours":
        return _date_range_response(
            interval=selected,
            label=DATE_INTERVALS[selected],
            start_at=now - timedelta(hours=24),
            end_at=now,
        )
    if selected == "last_48_hours":
        return _date_range_response(
            interval=selected,
            label=DATE_INTERVALS[selected],
            start_at=now - timedelta(hours=48),
            end_at=now,
        )
    if selected in {"week_to_date", "month_to_date"}:
        return _to_date_range(now, selected)

    days = max(1, min(365, _days_from_interval(selected, period_days)))
    date_range = _rolling_date_range(now, selected, days)
    date_range["is_filtered"] = bool(requested_interval)
    return date_range


@router.get("/dashboard")
async def get_dashboard_statistics(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
    force_refresh: bool = Query(False, title="Force refresh of statistics"),
    period_days: int = Query(30, ge=1, le=365, title="Period in days for time-based statistics"),
    interval: Optional[str] = Query(None, title="Named date interval"),
    start_date: Optional[str] = Query(None, title="Custom start date in YYYY-MM-DD format"),
    end_date: Optional[str] = Query(None, title="Custom end date in YYYY-MM-DD format"),
) -> Dict[str, Any]:
    """
    Get optimized statistics for the dashboard using cached data when possible.
    This endpoint provides efficient access to statistics for large datasets.

    Args:
        force_refresh: If True, invalidate cache and recalculate statistics
        period_days: Period in days for time-based statistics (default: 30)

    Returns:
        Dictionary with dashboard statistics
    """
    date_range = resolve_dashboard_date_range(
        interval=interval,
        period_days=period_days,
        start_date=start_date,
        end_date=end_date,
    )
    resolved_days = date_range["period_days"]
    start_ts = int(datetime.fromisoformat(date_range["start_at"]).timestamp())
    end_ts = int(datetime.fromisoformat(date_range["end_at"]).timestamp())

    selected_workspace_id = parse_selected_workspace_id(selected_workspace)
    workspace = resolve_authorized_workspace(
        db,
        _auth,
        PERMISSION_REPORTS_READ,
        selected_workspace_id=selected_workspace_id,
    )

    if uses_legacy_demo_fixtures(get_settings()):
        stats = build_demo_dashboard_statistics(period_days=resolved_days)
        stats["api_version"] = "1.0"
        stats["period_days"] = resolved_days
        stats["date_range"] = date_range
        return stats

    # Initialize statistics summarizer
    stats_summarizer = StatsSummarizer()

    # If force refresh, invalidate cache
    if force_refresh:
        stats_summarizer.invalidate_cache(workspace_id=workspace.id)

    # Get statistics (from cache or calculate if needed)
    stats = stats_summarizer.calculate_summary_statistics(
        db,
        period_days=resolved_days,
        start_ts=start_ts,
        end_ts=end_ts,
        cache_key=_summary_cache_key(date_range),
        workspace_id=workspace.id,
    )

    # Add version and timestamp
    stats["api_version"] = "1.0"
    stats["period_days"] = resolved_days
    stats["date_range"] = date_range

    return stats


@router.get("/domain/{domain_id}")
async def get_domain_statistics(
    domain_id: str = Path(..., title="The domain ID or name"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
    force_refresh: bool = Query(False, title="Force refresh of statistics"),
    period_days: int = Query(30, ge=1, le=365, title="Period in days for time-based statistics"),
    interval: Optional[str] = Query(None, title="Named date interval"),
    start_date: Optional[str] = Query(None, title="Custom start date in YYYY-MM-DD format"),
    end_date: Optional[str] = Query(None, title="Custom end date in YYYY-MM-DD format"),
) -> Dict[str, Any]:
    """
    Get optimized statistics for a specific domain using cached data when possible.

    Args:
        domain_id: The domain ID or name
        force_refresh: If True, invalidate cache and recalculate statistics
        period_days: Period in days for time-based statistics (default: 30)

    Returns:
        Dictionary with domain statistics
    """
    date_range = resolve_dashboard_date_range(
        interval=interval,
        period_days=period_days,
        start_date=start_date,
        end_date=end_date,
    )
    resolved_days = date_range["period_days"]
    start_ts = int(datetime.fromisoformat(date_range["start_at"]).timestamp())
    end_ts = int(datetime.fromisoformat(date_range["end_at"]).timestamp())

    selected_workspace_id = parse_selected_workspace_id(selected_workspace)
    workspace = resolve_authorized_workspace(
        db,
        _auth,
        PERMISSION_REPORTS_READ,
        selected_workspace_id=selected_workspace_id,
    )

    if uses_legacy_demo_fixtures(get_settings()):
        stats = build_demo_dashboard_statistics(period_days=resolved_days, domain=domain_id)
        stats["api_version"] = "1.0"
        stats["period_days"] = resolved_days
        stats["date_range"] = date_range
        return stats

    # Initialize statistics summarizer
    stats_summarizer = StatsSummarizer()

    # If force refresh, invalidate domain cache
    if force_refresh:
        stats_summarizer.invalidate_cache(domain_id, workspace_id=workspace.id)

    # Get domain statistics (from cache or calculate if needed)
    stats = stats_summarizer.calculate_summary_statistics(
        db,
        domain_id,
        period_days=resolved_days,
        start_ts=start_ts,
        end_ts=end_ts,
        cache_key=_summary_cache_key(date_range),
        workspace_id=workspace.id,
    )

    # Add version and timestamp
    stats["api_version"] = "1.0"
    stats["period_days"] = resolved_days
    stats["date_range"] = date_range

    return stats
