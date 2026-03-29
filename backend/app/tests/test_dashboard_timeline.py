"""Tests for the domain compliance timeline with real data."""

from fastapi.testclient import TestClient

from app.services.report_store import ReportStore


def _add_report_to_store(
    domain, report_id, begin_ts, end_ts, total, passed, failed, org_name="test.org"
):
    """Helper to add a report to the ReportStore with integer timestamps."""
    store = ReportStore.get_instance()
    store.add_report(
        {
            "domain": domain,
            "report_id": report_id,
            "org_name": org_name,
            "begin_date": begin_ts,
            "end_date": end_ts,
            "begin_timestamp": begin_ts,
            "end_timestamp": end_ts,
            "policy": "none",
            "records": [],
            "summary": {
                "total_count": total,
                "passed_count": passed,
                "failed_count": failed,
            },
        }
    )


class TestComplianceTimeline:
    """Tests that the compliance timeline returns real data instead of mock."""

    def test_timeline_has_entries_after_upload(self, client: TestClient):
        """When a domain has reports, the timeline should have entries."""
        _add_report_to_store("example.com", "rpt-001", 1597449600, 1597535999, 10, 8, 2)

        response = client.get("/api/v1/domains/example.com/reports?limit=10")
        assert response.status_code == 200
        data = response.json()
        timeline = data["compliance_timeline"]
        assert len(timeline) >= 1

    def test_timeline_uses_real_dates(self, client: TestClient):
        """Timeline dates should come from actual report begin_dates."""
        _add_report_to_store("example.com", "rpt-001", 1597449600, 1597535999, 10, 8, 2)

        response = client.get("/api/v1/domains/example.com/reports?limit=10")
        data = response.json()
        timeline = data["compliance_timeline"]

        # The begin_date=1597449600 is 2020-08-15
        dates = [point["date"] for point in timeline]
        assert "2020-08-15" in dates

    def test_timeline_compliance_rate_is_deterministic(self, client: TestClient):
        """Compliance rate should be deterministic, not random."""
        _add_report_to_store("example.com", "rpt-001", 1597449600, 1597535999, 10, 8, 2)

        resp1 = client.get("/api/v1/domains/example.com/reports?limit=10")
        resp2 = client.get("/api/v1/domains/example.com/reports?limit=10")

        timeline1 = resp1.json()["compliance_timeline"]
        timeline2 = resp2.json()["compliance_timeline"]
        assert timeline1 == timeline2

    def test_timeline_empty_for_domain_with_no_valid_dates(self, client: TestClient):
        """A domain with begin_date=0 should have an empty timeline."""
        store = ReportStore.get_instance()
        store.add_report(
            {
                "domain": "empty-timeline.com",
                "report_id": "rpt-empty",
                "org_name": "test",
                "begin_date": 0,
                "end_date": 0,
                "policy": "none",
                "records": [],
                "summary": {"total_count": 0, "passed_count": 0, "failed_count": 0},
            }
        )

        response = client.get("/api/v1/domains/empty-timeline.com/reports?limit=10")
        assert response.status_code == 200
        data = response.json()
        assert data["compliance_timeline"] == []

    def test_timeline_handles_iso_string_dates(self, client: TestClient):
        """Timeline should handle reports with ISO-format string dates."""
        from app.api.api_v1.endpoints.domains import _build_compliance_timeline

        store = ReportStore.get_instance()
        store.add_report(
            {
                "domain": "isodate.com",
                "report_id": "rpt-iso",
                "org_name": "test",
                "begin_date": "2020-08-15T00:00:00",
                "end_date": "2020-08-15T23:59:59",
                "policy": "none",
                "records": [],
                "summary": {"total_count": 10, "passed_count": 9, "failed_count": 1},
            }
        )

        timeline = _build_compliance_timeline(store, "isodate.com")
        assert len(timeline) == 1
        assert timeline[0].date == "2020-08-15"
        assert timeline[0].compliance_rate == 90.0


class TestBuildComplianceTimelineMultipleReports:
    """Test timeline aggregation with multiple reports."""

    def test_multiple_reports_same_day(self, client: TestClient):
        """Multiple reports on the same day should be aggregated."""
        _add_report_to_store("multi.com", "rpt-1", 1597449600, 1597535999, 10, 8, 2)
        _add_report_to_store("multi.com", "rpt-2", 1597449600, 1597535999, 10, 6, 4)

        response = client.get("/api/v1/domains/multi.com/reports?limit=10")
        assert response.status_code == 200
        data = response.json()
        timeline = data["compliance_timeline"]

        assert len(timeline) == 1
        assert timeline[0]["date"] == "2020-08-15"
        # Aggregated: 14 passed out of 20 total = 70%
        assert timeline[0]["compliance_rate"] == 70.0

    def test_reports_on_different_days(self, client: TestClient):
        """Reports on different days should produce separate timeline points."""
        _add_report_to_store("days.com", "rpt-d1", 1597449600, 1597535999, 10, 10, 0)
        _add_report_to_store("days.com", "rpt-d2", 1597536000, 1597622399, 10, 5, 5)

        response = client.get("/api/v1/domains/days.com/reports?limit=10")
        assert response.status_code == 200
        data = response.json()
        timeline = data["compliance_timeline"]

        assert len(timeline) == 2
        # Sorted by date
        assert timeline[0]["date"] == "2020-08-15"
        assert timeline[0]["compliance_rate"] == 100.0
        assert timeline[1]["date"] == "2020-08-16"
        assert timeline[1]["compliance_rate"] == 50.0
