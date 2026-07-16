from datetime import datetime, timezone

import pytest
from fastapi import HTTPException

from app.api.api_v1.endpoints.stats import _rolling_date_range, resolve_dashboard_date_range


def test_rolling_date_range_uses_inclusive_utc_calendar_days():
    date_range = _rolling_date_range(
        datetime(2026, 7, 16, 14, 30, tzinfo=timezone.utc),
        "last_30_days",
        30,
    )

    assert date_range["start_date"] == "2026-06-17"
    assert date_range["end_date"] == "2026-07-16"
    assert date_range["period_days"] == 30


def test_resolve_dashboard_date_range_accepts_custom_dates():
    date_range = resolve_dashboard_date_range(
        interval="custom",
        start_date="2026-06-01",
        end_date="2026-06-10",
    )

    assert date_range["interval"] == "custom"
    assert date_range["start_date"] == "2026-06-01"
    assert date_range["end_date"] == "2026-06-10"
    assert date_range["period_days"] == 10


def test_resolve_dashboard_date_range_rejects_reversed_custom_dates():
    with pytest.raises(HTTPException) as exc_info:
        resolve_dashboard_date_range(
            interval="custom",
            start_date="2026-06-10",
            end_date="2026-06-01",
        )

    assert exc_info.value.status_code == 400
    assert "end_date" in exc_info.value.detail
