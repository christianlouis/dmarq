import asyncio
from datetime import datetime

import pytest

from app.models.dns_posture_snapshot import DomainDNSPostureCurrent, DomainDNSPostureSnapshot
from app.models.domain import Domain
from app.services import dns_posture_refresh
from app.services.dns_posture_snapshots import (
    accepted_dns_posture_result,
    capture_dns_posture_snapshot,
    request_dns_posture_refresh,
)
from app.services.dns_resolver import DomainDNSResult


def _result(*, dmarc=True, status="ok"):
    return DomainDNSResult(
        dmarc=dmarc,
        dmarc_record="v=DMARC1; p=reject" if dmarc else None,
        spf=dmarc,
        spf_record="v=spf1 -all" if dmarc else None,
        lookup_status=status,
        resolver_route="configured_recursive",
        resolver_identity="127.0.0.1",
    )


def test_failed_lookup_preserves_last_known_good_dns_posture(db_session):
    domain = Domain(name="example.com", active=True)
    db_session.add(domain)
    db_session.commit()

    accepted = capture_dns_posture_snapshot(
        db_session, domain=domain, result=_result(), selectors=["mail"], trigger="report_ingest"
    )
    db_session.commit()
    failed = capture_dns_posture_snapshot(
        db_session,
        domain=domain,
        result=_result(dmarc=False, status="failed"),
        selectors=["mail"],
        trigger="scheduled",
    )
    db_session.commit()

    result, checked_at, provenance = accepted_dns_posture_result(
        db_session, domain_name=domain.name
    )
    current = db_session.query(DomainDNSPostureCurrent).filter_by(domain_id=domain.id).one()

    assert accepted.accepted is True
    assert failed.accepted is False
    assert result is not None and result.dmarc is True
    assert checked_at is not None
    assert provenance["snapshot_id"] == accepted.id
    assert current.accepted_snapshot_id == accepted.id
    assert current.latest_snapshot_id == failed.id
    assert db_session.query(DomainDNSPostureSnapshot).count() == 2


def test_absence_requires_two_observations_before_replacing_last_known_good(db_session):
    domain = Domain(name="absent.example", active=True)
    db_session.add(domain)
    db_session.commit()
    initial = capture_dns_posture_snapshot(
        db_session, domain=domain, result=_result(), selectors=[], trigger="scheduled"
    )
    db_session.commit()
    first_empty = capture_dns_posture_snapshot(
        db_session, domain=domain, result=_result(dmarc=False), selectors=[], trigger="scheduled"
    )
    db_session.commit()
    second_empty = capture_dns_posture_snapshot(
        db_session, domain=domain, result=_result(dmarc=False), selectors=[], trigger="scheduled"
    )
    db_session.commit()

    current = db_session.query(DomainDNSPostureCurrent).filter_by(domain_id=domain.id).one()
    assert initial.accepted is True
    assert first_empty.accepted is False
    assert second_empty.accepted is True
    assert current.accepted_snapshot_id == second_empty.id


def test_ingest_refresh_requests_are_coalesced(db_session):
    domain = Domain(name="coalesce.example", active=True)
    db_session.add(domain)
    db_session.commit()
    first = request_dns_posture_refresh(
        db_session, domain=domain, selectors=["first"], trigger="report_ingest"
    )
    first_requested_at = first.requested_at
    db_session.commit()
    second = request_dns_posture_refresh(
        db_session, domain=domain, selectors=["first"], trigger="report_ingest"
    )
    db_session.commit()

    assert second.id == first.id
    assert second.requested_at == first_requested_at


class _ScalarResult:
    def __init__(self, value):
        self.value = value

    def scalar(self):
        return self.value


class _LockDatabase:
    def __init__(self, dialect_name="sqlite", value=True):
        self.value = value
        self.executed = []
        self._bind = type("Bind", (), {"dialect": type("Dialect", (), {"name": dialect_name})()})()

    def get_bind(self):
        return self._bind

    def execute(self, statement, parameters):
        self.executed.append((statement, parameters))
        return _ScalarResult(self.value)


def test_dns_posture_worker_lock_is_sqlite_noop_and_postgres_advisory_lock():
    sqlite = _LockDatabase()
    postgres = _LockDatabase("postgresql", value=False)

    assert dns_posture_refresh._try_acquire_refresh_lock(sqlite) is True
    assert sqlite.executed == []
    assert dns_posture_refresh._try_acquire_refresh_lock(postgres) is False
    assert postgres.executed[0][1] == {
        "lock_key": dns_posture_refresh._DNS_POSTURE_REFRESH_LOCK_KEY
    }


@pytest.mark.asyncio
async def test_requested_worker_honors_enabled_setting_and_counts_refreshes(monkeypatch):
    class Settings:
        DNS_POSTURE_REFRESH_ENABLED = True
        DNS_POSTURE_REFRESH_LIMIT = 2

    refreshed = []

    async def refresh(domain_id):
        refreshed.append(domain_id)
        return domain_id == 1

    monkeypatch.setattr(dns_posture_refresh, "get_settings", lambda: Settings())
    monkeypatch.setattr(
        dns_posture_refresh,
        "_candidates",
        lambda limit: [(1, "one.example"), (2, "two.example")][:limit],
    )
    monkeypatch.setattr(dns_posture_refresh, "refresh_domain_dns_posture", refresh)

    assert await dns_posture_refresh.refresh_requested_dns_posture() == 1
    assert refreshed == [1, 2]


@pytest.mark.asyncio
async def test_requested_worker_does_not_enumerate_when_disabled(monkeypatch):
    class Settings:
        DNS_POSTURE_REFRESH_ENABLED = False
        DNS_POSTURE_REFRESH_LIMIT = 50

    monkeypatch.setattr(dns_posture_refresh, "get_settings", lambda: Settings())
    monkeypatch.setattr(
        dns_posture_refresh,
        "_candidates",
        lambda *_args: pytest.fail("disabled worker must not enumerate domains"),
    )
    assert await dns_posture_refresh.refresh_requested_dns_posture() == 0


@pytest.mark.asyncio
async def test_scheduled_dns_posture_worker_honors_startup_and_cancellation(monkeypatch):
    class Settings:
        DNS_POSTURE_REFRESH_STARTUP_DELAY_SECONDS = 1
        DNS_POSTURE_REFRESH_INTERVAL_SECONDS = 1

    sleeps = []

    async def sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) > 1:
            raise asyncio.CancelledError()

    async def refresh():
        return 1

    monkeypatch.setattr(dns_posture_refresh, "get_settings", lambda: Settings())
    monkeypatch.setattr(dns_posture_refresh.asyncio, "sleep", sleep)
    monkeypatch.setattr(dns_posture_refresh, "refresh_requested_dns_posture", refresh)

    with pytest.raises(asyncio.CancelledError):
        await dns_posture_refresh.scheduled_dns_posture_refresh()
    assert sleeps == [5, 60]


@pytest.mark.asyncio
async def test_refresh_domain_materializes_requested_dns_evidence(db_session, monkeypatch):
    domain = Domain(name="worker.example", active=True)
    db_session.add(domain)
    db_session.flush()
    request_dns_posture_refresh(
        db_session, domain=domain, selectors=["mail"], trigger="report_ingest"
    )
    db_session.commit()

    async def resolve(*_args, **_kwargs):
        return _result(), False, datetime.utcnow()

    monkeypatch.setattr(dns_posture_refresh, "SessionLocal", lambda: db_session)
    monkeypatch.setattr(dns_posture_refresh, "get_default_provider", lambda _db: object())
    monkeypatch.setattr(dns_posture_refresh, "resolve_domain_dns_cached", resolve)

    assert await dns_posture_refresh.refresh_domain_dns_posture(domain.id) is True
    current = db_session.query(DomainDNSPostureCurrent).filter_by(domain_id=domain.id).one()
    assert current.accepted_snapshot_id is not None
    assert current.requested_at is None


@pytest.mark.asyncio
async def test_refresh_domain_keeps_worker_alive_when_resolution_fails(db_session, monkeypatch):
    domain = Domain(name="worker-failure.example", active=True)
    db_session.add(domain)
    db_session.commit()

    async def fail(*_args, **_kwargs):
        raise RuntimeError("resolver unavailable")

    monkeypatch.setattr(dns_posture_refresh, "SessionLocal", lambda: db_session)
    monkeypatch.setattr(dns_posture_refresh, "get_default_provider", lambda _db: object())
    monkeypatch.setattr(dns_posture_refresh, "resolve_domain_dns_cached", fail)

    assert await dns_posture_refresh.refresh_domain_dns_posture(domain.id) is False
