from copy import deepcopy

from app.models.workspace import Workspace
from app.services import report_persistence
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

    def test_add_reports_matches_incremental_append_for_mixed_domains(self):
        reports = []
        for index, domain in enumerate(("a.example", "b.example", "a.example"), 1):
            report = _sample_report(domain)
            report["report_id"] = f"rpt-{index}"
            report["records"][0]["source_ip"] = f"203.0.113.{index}"
            reports.append(report)

        incremental = ReportStore()
        for report in reports:
            incremental.add_report(deepcopy(report))

        bulk = ReportStore()
        assert bulk.add_reports(deepcopy(reports)) == len(reports)

        assert bulk.domain_reports == incremental.domain_reports
        assert bulk.domain_summary == incremental.domain_summary
        assert bulk.domain_sources == incremental.domain_sources

    def test_add_reports_recomputes_once_per_touched_domain_and_preserves_append(self):
        store = ReportStore()
        calls = []
        original = store._recompute_domain_stats

        def counted(domain):
            calls.append(domain)
            return original(domain)

        store._recompute_domain_stats = counted
        reports = []
        for index, domain in enumerate(("a.example", "a.example", "b.example"), 1):
            report = _sample_report(domain)
            report["report_id"] = f"rpt-{index}"
            reports.append(report)

        assert store.add_reports(reports) == 3
        assert calls == ["a.example", "b.example"]
        assert [report["report_id"] for report in store.domain_reports["a.example"]] == [
            "rpt-1",
            "rpt-2",
        ]

        store.add_report(_sample_report("a.example"))
        assert calls[-1] == "a.example"

    def test_add_reports_empty_is_a_noop(self):
        store = ReportStore()
        assert store.add_reports([]) == 0
        assert store.get_domains() == []

    def test_hydration_functions_preserve_workspace_isolation(self, db_session):
        first = Workspace(slug="first", name="First")
        second = Workspace(slug="second", name="Second")
        db_session.add_all([first, second])
        db_session.commit()

        first_report = _sample_report("first.example")
        first_report["report_id"] = "first-report"
        second_report = _sample_report("second.example")
        second_report["report_id"] = "second-report"
        report_persistence.save_parsed_report(db_session, first_report, workspace_id=first.id)
        report_persistence.save_parsed_report(db_session, second_report, workspace_id=second.id)
        db_session.commit()

        global_store = ReportStore()
        global_calls = []
        global_recompute = global_store._recompute_domain_stats
        global_store._recompute_domain_stats = lambda domain: (
            global_calls.append(domain), global_recompute(domain)
        )[1]
        assert (
            report_persistence.hydrate_report_store_from_db(
                db_session, global_store, workspace_id=first.id
            )
            == 1
        )
        assert [r["report_id"] for r in global_store.domain_reports["first.example"]] == [
            "first-report"
        ]
        assert global_calls == ["first.example"]

        domain_store = ReportStore()
        domain_calls = []
        domain_recompute = domain_store._recompute_domain_stats
        domain_store._recompute_domain_stats = lambda domain: (
            domain_calls.append(domain), domain_recompute(domain)
        )[1]
        assert (
            report_persistence.hydrate_domain_report_store_from_db(
                db_session,
                domain_store,
                "second.example",
                workspace_id=second.id,
            )
            == 1
        )
        assert [r["report_id"] for r in domain_store.domain_reports["second.example"]] == [
            "second-report"
        ]
        assert domain_calls == ["second.example"]

    def test_hydration_clears_empty_store_and_preserves_limit_order(self, db_session):
        workspace = Workspace(slug="hydration", name="Hydration")
        db_session.add(workspace)
        db_session.commit()

        for index, end_timestamp in enumerate((300, 200, 100), 1):
            report = _sample_report("ordered.example")
            report.update(
                report_id=f"ordered-{index}",
                begin_timestamp=end_timestamp - 10,
                end_timestamp=end_timestamp,
            )
            report_persistence.save_parsed_report(
                db_session, report, workspace_id=workspace.id
            )
        db_session.commit()

        store = ReportStore()
        store.add_report(_sample_report("stale.example"))
        assert (
            report_persistence.hydrate_report_store_from_db(
                db_session, store, workspace_id=99999
            )
            == 0
        )
        assert store.get_domains() == []

        assert (
            report_persistence.hydrate_domain_report_store_from_db(
                db_session,
                store,
                "ordered.example",
                workspace_id=workspace.id,
                limit=2,
            )
            == 2
        )
        assert [report["report_id"] for report in store.get_domain_reports("ordered.example")] == [
            "ordered-1",
            "ordered-2",
        ]

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

    def test_get_domain_sources_honors_the_requested_observation_window(self, monkeypatch):
        store = ReportStore.get_instance()
        now = 1709251200  # 2024-03-01T00:00:00Z
        older = _sample_report("test.com")
        older.update(
            {
                "report_id": "outside-window",
                "begin_timestamp": 1701388800,
                "end_timestamp": 1701475199,
                "records": [
                    {
                        "source_ip": "203.0.113.10",
                        "count": 99,
                        "disposition": "reject",
                        "dkim_result": "fail",
                        "spf_result": "fail",
                    }
                ],
            }
        )
        recent = _sample_report("test.com")
        recent.update(
            {
                "report_id": "inside-window",
                "begin_timestamp": 1709164800,
                "end_timestamp": 1709251199,
                "records": [
                    {
                        "source_ip": "203.0.113.20",
                        "count": 7,
                        "disposition": "none",
                        "dkim_result": "pass",
                        "spf_result": "pass",
                    }
                ],
            }
        )
        store.add_report(older)
        store.add_report(recent)
        monkeypatch.setattr(report_store_module, "_now_timestamp", lambda: now)

        sources = store.get_domain_sources("test.com", days=30)
        reports = store.get_domain_reports("test.com", days=30)

        assert [source["source_ip"] for source in sources] == ["203.0.113.20"]
        assert sources[0]["count"] == 7
        assert [report["report_id"] for report in reports] == ["inside-window"]

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
