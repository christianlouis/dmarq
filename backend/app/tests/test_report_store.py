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
        assert any(d == "test.com" for d in domains)

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
        assert any(d == "other.com" for d in store.get_domains())

    def test_delete_nonexistent_domain(self):
        store = ReportStore.get_instance()
        assert store.delete_domain_with_cleanup("nope.com") is False

    def test_has_report_returns_true_for_existing(self):
        store = ReportStore.get_instance()
        store.add_report(_sample_report("test.com"))
        assert store.has_report("test.com", "rpt-001") is True

    def test_has_report_returns_false_for_missing_report_id(self):
        store = ReportStore.get_instance()
        store.add_report(_sample_report("test.com"))
        assert store.has_report("test.com", "rpt-999") is False

    def test_has_report_returns_false_for_unknown_domain(self):
        store = ReportStore.get_instance()
        assert store.has_report("nobody.com", "rpt-001") is False

    def test_delete_report_removes_report_and_updates_stats(self):
        store = ReportStore.get_instance()
        store.add_report(_sample_report("test.com"))

        result = store.delete_report("test.com", "rpt-001")
        assert result is True
        # Domain should be gone entirely when no reports remain
        assert "test.com" not in store.get_domains()

    def test_delete_report_with_remaining_reports_recomputes_stats(self):
        store = ReportStore.get_instance()
        report_a = _sample_report("test.com")
        report_a["report_id"] = "rpt-001"

        report_b = _sample_report("test.com")
        report_b["report_id"] = "rpt-002"
        report_b["summary"] = {"total_count": 3, "passed_count": 1, "failed_count": 2}

        store.add_report(report_a)
        store.add_report(report_b)

        assert store.get_domain_summary("test.com")["reports_processed"] == 2

        result = store.delete_report("test.com", "rpt-001")
        assert result is True

        summary = store.get_domain_summary("test.com")
        assert summary["reports_processed"] == 1
        # Stats should now reflect only report_b
        assert summary["total_count"] == 3
        assert summary["passed_count"] == 1

    def test_delete_report_nonexistent_returns_false(self):
        store = ReportStore.get_instance()
        assert store.delete_report("test.com", "rpt-999") is False

    def test_delete_report_unknown_domain_returns_false(self):
        store = ReportStore.get_instance()
        assert store.delete_report("nobody.com", "rpt-001") is False

    def test_recompute_stats_after_add(self):
        """_recompute_domain_stats is called on add; compliance_rate must be correct."""
        store = ReportStore.get_instance()
        report = _sample_report("test.com")
        report["summary"] = {"total_count": 10, "passed_count": 8, "failed_count": 2}
        store.add_report(report)

        summary = store.get_domain_summary("test.com")
        assert summary["compliance_rate"] == 80.0
