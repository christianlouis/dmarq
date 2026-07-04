from unittest.mock import AsyncMock

import pytest

from app.models.domain import Domain
from app.services import dns_prewarm


@pytest.mark.asyncio
async def test_prewarm_dns_cache_refreshes_active_domains(db_session, monkeypatch):
    db_session.add(
        Domain(
            name="example.com",
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
