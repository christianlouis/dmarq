from app.services.report_store import ReportStore


def _sample_report(domain: str = "example.com") -> dict:
    """Return a minimal parsed report dict for testing."""
    return {
        "domain": domain,
        "report_id": "rpt-001",
        "org_name": "google.com",
        "begin_date": "2020-08-15T00:00:00",
        "end_date": "2020-08-15T23:59:59",
        "begin_timestamp": 1597449600,
        "end_timestamp": 1597535999,
        "policy": {"p": "none", "sp": "none", "pct": "100"},
        "records": [
            {
                "source_ip": "203.0.113.1",
                "count": 5,
                "disposition": "none",
                "dkim_result": "pass",
                "spf_result": "fail",
                "header_from": domain,
            }
        ],
        "summary": {
            "total_count": 5,
            "passed_count": 5,
            "failed_count": 0,
            "pass_rate": 100.0,
        },
    }


class TestReportStore:
    """Tests for the in-memory ReportStore."""

    def test_add_report_creates_domain(self):
        store = ReportStore.get_instance()
        store.add_report(_sample_report("test.com"))

        domains = store.get_domains()
        assert "test.com" in domains

    def test_domain_summary_after_add(self):
        store = ReportStore.get_instance()
        store.add_report(_sample_report("test.com"))

        summary = store.get_domain_summary("test.com")
        assert summary["total_count"] == 5
        assert summary["passed_count"] == 5
        assert summary["reports_processed"] == 1

    def test_get_domain_reports(self):
        store = ReportStore.get_instance()
        store.add_report(_sample_report("test.com"))

        reports = store.get_domain_reports("test.com")
        assert len(reports) == 1
        assert reports[0]["report_id"] == "rpt-001"

    def test_clear(self):
        store = ReportStore.get_instance()
        store.add_report(_sample_report("test.com"))
        store.clear()

        assert store.get_domains() == []

    def test_delete_domain(self):
        store = ReportStore.get_instance()
        store.add_report(_sample_report("test.com"))
        store.add_report(_sample_report("other.com"))

        assert store.delete_domain_with_cleanup("test.com") is True
        assert "test.com" not in store.get_domains()
        assert "other.com" in store.get_domains()

    def test_delete_nonexistent_domain(self):
        store = ReportStore.get_instance()
        assert store.delete_domain_with_cleanup("nope.com") is False
