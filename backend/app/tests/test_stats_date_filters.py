import pytest
from fastapi import HTTPException

from app.api.api_v1.endpoints.stats import resolve_dashboard_date_range


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
