from datetime import date, datetime, timezone

import pytest

from app.services.demo_data import DEMO_DOMAINS, build_demo_reports, seed_demo_report_store
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
