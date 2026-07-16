from app.services import report_store as report_store_module
from app.services.report_store import ReportStore, _auth_status_from_counts, _dominant_result


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

    def test_get_report_by_id_returns_matching_report(self):
        store = ReportStore.get_instance()
        report = _sample_report("test.com")
        store.add_report(report)

        assert store.get_report_by_id("rpt-001") is report

    def test_get_report_by_id_returns_none_for_missing_report(self):
        store = ReportStore.get_instance()
        store.add_report(_sample_report("test.com"))

        assert store.get_report_by_id("rpt-missing") is None

    def test_get_domain_sources_returns_sources_sorted_by_count(self):
        store = ReportStore.get_instance()
        report = _sample_report("test.com")
        report["records"].append(
            {
                "source_ip": "203.0.113.2",
                "count": 12,
                "disposition": "none",
                "dkim_result": "fail",
                "spf_result": "pass",
                "header_from": "test.com",
            }
        )
        store.add_report(report)

        sources = store.get_domain_sources("test.com")

        assert [source["source_ip"] for source in sources] == ["203.0.113.2", "203.0.113.1"]
        assert [source["count"] for source in sources] == [12, 5]

    def test_get_domain_sources_rolls_up_pass_fail_counts_per_ip(self):
        store = ReportStore.get_instance()
        report = _sample_report("test.com")
        report["records"] = [
            {
                "source_ip": "203.0.113.9",
                "count": 7,
                "disposition": "none",
                "dkim_result": "pass",
                "spf_result": "fail",
                "header_from": "test.com",
            },
            {
                "source_ip": "203.0.113.9",
                "count": 3,
                "disposition": "quarantine",
                "dkim_result": "fail",
                "spf_result": "pass",
                "header_from": "test.com",
            },
            {
                "source_ip": "203.0.113.9",
                "count": 2,
                "disposition": "reject",
                "dkim_result": "fail",
                "spf_result": "fail",
                "header_from": "test.com",
            },
        ]

        store.add_report(report)

        source = store.get_domain_sources("test.com")[0]
        assert source["source_ip"] == "203.0.113.9"
        assert source["count"] == 12
        assert source["spf_result"] == "mixed"
        assert source["dkim_result"] == "mixed"
        assert source["dmarc_result"] == "mixed"
        assert source["spf_pass_count"] == 3
        assert source["spf_fail_count"] == 9
        assert source["dkim_pass_count"] == 7
        assert source["dkim_fail_count"] == 5
        assert source["dmarc_pass_count"] == 10
        assert source["dmarc_fail_count"] == 2
        assert source["disposition_counts"] == {"none": 7, "quarantine": 3, "reject": 2}

    def test_get_domain_sources_tracks_first_last_seen_and_daily_volume(self):
        store = ReportStore.get_instance()
        older = _sample_report("test.com")
        older.update(
            {
                "report_id": "older",
                "begin_timestamp": 1704067200,
                "end_timestamp": 1704153599,
                "records": [
                    {
                        "source_ip": "203.0.113.9",
                        "count": 2,
                        "disposition": "none",
                        "dkim_result": "pass",
                        "spf_result": "pass",
                        "header_from": "test.com",
                    }
                ],
            }
        )
        newer = _sample_report("test.com")
        newer.update(
            {
                "report_id": "newer",
                "begin_timestamp": 1706745600,
                "end_timestamp": 1706831999,
                "records": [
                    {
                        "source_ip": "203.0.113.9",
                        "count": 5,
                        "disposition": "reject",
                        "dkim_result": "fail",
                        "spf_result": "fail",
                        "header_from": "test.com",
                    }
                ],
            }
        )

        store.add_report(newer)
        store.add_report(older)

        source = store.get_domain_sources("test.com")[0]
        assert source["first_seen"] == 1704067200
        assert source["last_seen"] == 1706831999
        assert source["active_days"] == 2
        assert source["report_count"] == 2
        assert source["volume_history"] == [
            {"date": "2024-01-01", "count": 2, "passed": 2, "failed": 0},
            {"date": "2024-02-01", "count": 5, "passed": 0, "failed": 5},
        ]
        assert "_volume_by_date" not in source

    def test_get_domain_sources_clamps_future_report_end_to_current_time(self, monkeypatch):
        store = ReportStore.get_instance()
        now = 1706788800
        report = _sample_report("test.com")
        report.update(
            {
                "report_id": "future-period-end",
                "begin_timestamp": 1706745600,
                "end_timestamp": 1706831999,
                "records": [
                    {
                        "source_ip": "203.0.113.9",
                        "count": 4,
                        "disposition": "none",
                        "dkim_result": "pass",
                        "spf_result": "pass",
                        "header_from": "test.com",
                    }
                ],
            }
        )
        monkeypatch.setattr(report_store_module, "_now_timestamp", lambda: now)

        store.add_report(report)

        source = store.get_domain_sources("test.com")[0]
        assert source["first_seen"] == 1706745600
        assert source["last_seen"] == now
        assert source["volume_history"] == [
            {"date": "2024-02-01", "count": 4, "passed": 4, "failed": 0},
        ]

    def test_get_domain_sources_clamps_future_report_begin_to_current_time(self, monkeypatch):
        store = ReportStore.get_instance()
        now = 1706788800
        report = _sample_report("test.com")
        report.update(
            {
                "report_id": "future-period-start",
                "begin_timestamp": 1706831999,
                "end_timestamp": 1706745600,
                "records": [
                    {
                        "source_ip": "203.0.113.9",
                        "count": 4,
                        "disposition": "none",
                        "dkim_result": "pass",
                        "spf_result": "pass",
                        "header_from": "test.com",
                    }
                ],
            }
        )
        monkeypatch.setattr(report_store_module, "_now_timestamp", lambda: now)

        store.add_report(report)

        source = store.get_domain_sources("test.com")[0]
        assert source["first_seen"] == 1706745600
        assert source["last_seen"] == 1706745600
        assert source["volume_history"] == [
            {"date": "2024-02-01", "count": 4, "passed": 4, "failed": 0},
        ]

    def test_get_domain_sources_ignores_missing_date_sentinel_timestamps(self):
        store = ReportStore.get_instance()
        report = _sample_report("test.com")
        report.update(
            {
                "begin_timestamp": 0,
                "end_timestamp": 0,
                "begin_date": "",
                "end_date": "",
            }
        )

        store.add_report(report)

        source = store.get_domain_sources("test.com")[0]
        assert source["first_seen"] is None
        assert source["last_seen"] is None
        assert source["active_days"] == 0
        assert source["report_count"] == 1
        assert source["volume_history"] == []

    def test_get_domain_sources_rolls_up_unknown_auth_results(self):
        store = ReportStore.get_instance()
        report = _sample_report("test.com")
        report["records"] = [
            {
                "source_ip": "203.0.113.10",
                "count": 4,
                "disposition": "none",
                "dkim_result": "temperror",
                "spf_result": "neutral",
                "header_from": "test.com",
            }
        ]

        store.add_report(report)

        source = store.get_domain_sources("test.com")[0]
        assert source["spf_result"] == "unknown"
        assert source["dkim_result"] == "unknown"
        assert source["spf_unknown_count"] == 4
        assert source["dkim_unknown_count"] == 4
        assert source["dmarc_result"] == "fail"

    def test_dominant_result_returns_default_for_empty_counts(self):
        assert _dominant_result({}) == "none"

    def test_auth_status_returns_none_without_counts(self):
        assert _auth_status_from_counts(0, 0) == "none"

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

    def test_selector_evidence_separates_active_rotation_from_history(self):
        store = ReportStore.get_instance()
        now = 1_800_000_000

        def add_selector_report(report_id, age_days, selector, result, count, signing_domain):
            report = _sample_report("test.com")
            report.update(
                {
                    "report_id": report_id,
                    "begin_timestamp": now - age_days * 86_400 - 3600,
                    "end_timestamp": now - age_days * 86_400,
                    "records": [
                        {
                            "source_ip": "203.0.113.8",
                            "count": count,
                            "disposition": "none",
                            "dkim_result": result,
                            "spf_result": "fail",
                            "header_from": "test.com",
                            "dkim": [
                                {
                                    "domain": signing_domain,
                                    "selector": selector,
                                    "result": result,
                                }
                            ],
                        }
                    ],
                }
            )
            store.add_report(report)

        add_selector_report("current-fail", 1, "rotated-2026", "fail", 9, "test.com")
        add_selector_report("current-pass", 2, "current-pass", "pass", 7, "test.com")
        add_selector_report("recent", 14, "recent-provider", "pass", 4, "test.com")
        add_selector_report("historical", 70, "retired-2024", "fail", 3, "test.com")
        add_selector_report("unaligned", 1, "provider-internal", "fail", 20, "vendor.test")

        rows = store.get_domain_selector_evidence(
            "test.com",
            manual_selectors=["manual-only"],
            now=now,
        )
        by_selector = {row["selector"]: row for row in rows}

        assert by_selector["rotated-2026"]["classification"] == "active_failing"
        assert by_selector["rotated-2026"]["current_failure_count"] == 9
        assert by_selector["rotated-2026"]["report_count"] == 1
        assert by_selector["current-pass"]["classification"] == "active_passing"
        assert by_selector["recent-provider"]["classification"] == "recently_observed"
        assert by_selector["retired-2024"]["classification"] == "historical"
        assert by_selector["manual-only"]["classification"] == "manually_configured"
        assert by_selector["manual-only"]["manual_configured"] is True
        assert "provider-internal" not in by_selector
