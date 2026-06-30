import time
from datetime import date, datetime, timezone

import pytest

from app.services.demo_data import (
    DEMO_DOMAINS,
    analyze_demo_forensic_reports,
    build_demo_dashboard_statistics,
    build_demo_forensic_reports,
    build_demo_health_score_history,
    build_demo_mail_source_backfills,
    build_demo_mail_sources,
    build_demo_reports,
    list_demo_forensic_reports,
    list_demo_tls_reports,
    seed_demo_report_store,
    summarize_demo_tls_reports,
)
from app.services.dns_resolver import DemoDNSProvider
from app.services.report_store import ReportStore


def _date_from_timestamp(value: int) -> date:
    return datetime.fromtimestamp(value, tz=timezone.utc).date()


def test_build_demo_reports_rolls_with_current_date():
    reports = build_demo_reports(today=date(2026, 6, 25), days=90)

    assert len(reports) == 180
    assert {report["domain"] for report in reports} == set(DEMO_DOMAINS)
    assert min(_date_from_timestamp(report["begin_timestamp"]) for report in reports) == date(
        2026, 3, 28
    )
    assert max(_date_from_timestamp(report["begin_timestamp"]) for report in reports) == date(
        2026, 6, 25
    )
    assert any(
        record["disposition"] == "quarantine"
        for report in reports
        if report["domain"] == "dmarq.org"
        for record in report["records"]
    )
    assert any(
        record["spf_result"] == "fail" and record["dkim_result"] == "pass"
        for report in reports
        if report["domain"] == "dmarq.com"
        for record in report["records"]
    )


def test_build_demo_reports_uses_utc_iso_dates(monkeypatch):
    monkeypatch.setenv("TZ", "America/Los_Angeles")
    time.tzset()
    try:
        reports = build_demo_reports(today=date(2026, 6, 25), days=1)
        report = next(report for report in reports if report["domain"] == "dmarq.org")

        assert report["begin_timestamp"] == 1782345600
        assert report["end_timestamp"] == 1782431999
        assert report["begin_date"] == "2026-06-25T00:00:00"
        assert report["end_date"] == "2026-06-25T23:59:59"
    finally:
        monkeypatch.undo()
        time.tzset()


def test_seed_demo_report_store_replaces_store_with_demo_domains():
    store = ReportStore()
    store.add_report(
        {
            "domain": "real.example",
            "report_id": "real",
            "records": [],
            "summary": {"total_count": 0, "passed_count": 0, "failed_count": 0},
        }
    )

    count = seed_demo_report_store(store)

    assert count == 180
    assert set(store.get_domains()) == set(DEMO_DOMAINS)
    assert store.get_domain_summary("dmarq.org")["reports_processed"] == 90
    assert store.get_domain_sources("dmarq.com")


def test_build_demo_dashboard_statistics_fills_chart_sources_and_changes():
    stats = build_demo_dashboard_statistics(today=date(2026, 6, 25), period_days=30)

    assert stats["total_domains"] == 2
    assert stats["total_emails"] > 0
    assert stats["compliance_trend"]
    assert stats["top_sources"]
    assert stats["change_summary"]
    assert stats["source_regions"]
    assert stats["source_anomalies"]
    assert any(source["dmarc"] in {"mixed", "fail"} for source in stats["top_sources"])
    assert all("geo" in source for source in stats["top_sources"])


def test_build_demo_domain_statistics_includes_sources():
    stats = build_demo_dashboard_statistics(
        today=date(2026, 6, 25), period_days=30, domain="dmarq.com"
    )

    assert stats["domain"] == "dmarq.com"
    assert "sources" in stats
    assert stats["sources"]
    assert "top_sources" not in stats


def test_demo_tls_reports_fill_summary_and_list_views():
    listed = list_demo_tls_reports(today=date(2026, 6, 25), page_size=10)
    summary = summarize_demo_tls_reports(today=date(2026, 6, 25), days=30)

    assert listed["total"] > 10
    assert listed["reports"][0]["failures"] is not None
    assert summary["totals"]["reports"] > 0
    assert summary["totals"]["failed_sessions"] > 0
    assert summary["trends"]
    assert summary["top_failures"]
    assert summary["affected_domains"]


def test_demo_forensic_reports_fill_list_and_analysis_views():
    reports = build_demo_forensic_reports(today=date(2026, 6, 25), days=30)
    listed = list_demo_forensic_reports(today=date(2026, 6, 25), auth_failure="dkim")
    analysis = analyze_demo_forensic_reports(today=date(2026, 6, 25), domain="dmarq.org")

    assert reports
    assert listed["total"] > 0
    assert all(report["auth_failure"] == "dkim" for report in listed["reports"])
    assert analysis["total"] > 0
    assert analysis["groups"]
    assert analysis["samples"]
    assert "redacted headers and metadata only" in analysis["samples"][0]["privacy_note"]


def test_demo_mail_sources_include_backfill_lifecycle_examples():
    sources = build_demo_mail_sources(today=date(2026, 6, 25))
    source_ids = {source["id"] for source in sources}

    assert {9001, 9002, 9003}.issubset(source_ids)
    assert all(source["password"] is None for source in sources)
    assert any(source["method"] == "GMAIL_API" and source["gmail_connected"] for source in sources)
    assert any(source["method"] == "M365_GRAPH" and source["m365_connected"] for source in sources)

    statuses = {
        job["status"]
        for source_id in source_ids
        for job in build_demo_mail_source_backfills(source_id, today=date(2026, 6, 25))
    }
    assert {"completed", "running", "backoff", "queued"}.issubset(statuses)


def test_demo_health_score_history_covers_core_personas():
    org = build_demo_health_score_history("dmarq.org", today=date(2026, 6, 25), days=90)
    com = build_demo_health_score_history("dmarq.com", today=date(2026, 6, 25), days=90)
    tenant = build_demo_health_score_history("lawfirm.example", today=date(2026, 6, 25), days=10)

    assert org[0]["date"] == "2026-03-28"
    assert org[-1]["policy"] == "reject"
    assert org[-1]["score"] > org[0]["score"]
    assert com[-1]["policy"] == "none"
    assert com[-1]["grade"] in {"C", "D"}
    assert tenant[-1]["policy"] == "quarantine"
    assert tenant[-1]["top_actions"][0]["title"] == "Review managed customer sender alignment"


@pytest.mark.asyncio
async def test_demo_dns_provider_returns_corner_case_records():
    provider = DemoDNSProvider()

    dmarq_org = await provider.check_domain("dmarq.org", selectors=["selector1", "news"])
    dmarq_com = await provider.check_domain("dmarq.com", selectors=["google", "mailchimp"])

    assert dmarq_org.dmarc is True
    assert dmarq_org.spf_record.endswith("-all")
    assert "selector1" in dmarq_org.dkim_selectors
    assert dmarq_org.dmarc_warnings == []

    assert dmarq_com.dmarc is True
    assert dmarq_com.spf_record.endswith("+all")
    assert "google" in dmarq_com.dkim_selectors
    assert any("External rua destination" in warning for warning in dmarq_com.dmarc_warnings)
