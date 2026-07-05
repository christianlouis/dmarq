from unittest.mock import AsyncMock

import pytest

from app.models.domain import Domain
from app.models.report import DMARCReport, ReportRecord
from app.services import dns_prewarm


@pytest.mark.asyncio
async def test_prewarm_dns_cache_refreshes_active_domains(db_session, monkeypatch):
    db_session.add(
        Domain(
            name=" Example.COM. ",
            active=True,
            dkim_selectors="google, mailgun",
        )
    )
    db_session.add(Domain(name="inactive.example", active=False))
    db_session.commit()
    resolver = AsyncMock()

    monkeypatch.setattr(
        dns_prewarm,
        "get_default_provider",
        lambda _db: resolver,
    )
    monkeypatch.setattr(dns_prewarm, "SessionLocal", lambda: db_session)
    resolve = AsyncMock()
    monkeypatch.setattr(dns_prewarm, "resolve_domain_dns_cached", resolve)
    settings = dns_prewarm.get_settings()
    monkeypatch.setattr(settings, "DNS_STARTUP_PREWARM_ENABLED", True)
    monkeypatch.setattr(settings, "DNS_STARTUP_PREWARM_LIMIT", 10)
    monkeypatch.setattr(settings, "DNS_STARTUP_PREWARM_CONCURRENCY", 2)

    await dns_prewarm.prewarm_dns_cache()

    resolve.assert_awaited_once()
    _, provider, domain, *args = resolve.await_args.args
    assert provider is resolver
    assert domain == "example.com"
    assert resolve.await_args.kwargs["selectors"] == ["google", "mailgun"]
    assert resolve.await_args.kwargs["refresh"] is True


def test_domain_selectors_strip_empty_entries():
    domain = Domain(name="example.com", dkim_selectors=" google, , mailgun ,")

    assert dns_prewarm._domain_selectors(domain) == [  # pylint: disable=protected-access
        "google",
        "mailgun",
    ]


def test_canonical_domain_name_normalizes_imported_values():
    assert (
        dns_prewarm._canonical_domain_name(  # pylint: disable=protected-access
            " Example.COM. "
        )
        == "example.com"
    )


@pytest.mark.asyncio
async def test_prewarm_dns_cache_prioritizes_domains_with_report_activity(db_session, monkeypatch):
    active_empty = Domain(name="empty.example", active=True)
    active_reported = Domain(
        name="reported.example",
        active=True,
        dkim_selectors="selector1",
    )
    db_session.add_all([active_empty, active_reported])
    db_session.flush()
    report = DMARCReport(
        domain_id=active_reported.id,
        report_id="report-1",
        org_name="google.com",
        begin_date=1783000000,
        end_date=1783086400,
    )
    db_session.add(report)
    db_session.flush()
    db_session.add(
        ReportRecord(
            report_id=report.id,
            source_ip="203.0.113.10",
            count=25,
            disposition="none",
            dkim="pass",
            spf="pass",
            header_from="reported.example",
        )
    )
    db_session.commit()
    resolver = AsyncMock()

    monkeypatch.setattr(
        dns_prewarm,
        "get_default_provider",
        lambda _db: resolver,
    )
    monkeypatch.setattr(dns_prewarm, "SessionLocal", lambda: db_session)
    resolve = AsyncMock()
    monkeypatch.setattr(dns_prewarm, "resolve_domain_dns_cached", resolve)
    settings = dns_prewarm.get_settings()
    monkeypatch.setattr(settings, "DNS_STARTUP_PREWARM_ENABLED", True)
    monkeypatch.setattr(settings, "DNS_STARTUP_PREWARM_LIMIT", 1)
    monkeypatch.setattr(settings, "DNS_STARTUP_PREWARM_CONCURRENCY", 1)

    await dns_prewarm.prewarm_dns_cache()

    resolve.assert_awaited_once()
    _, _, domain, *args = resolve.await_args.args
    assert domain == "reported.example"
    assert resolve.await_args.kwargs["selectors"] == ["selector1"]
