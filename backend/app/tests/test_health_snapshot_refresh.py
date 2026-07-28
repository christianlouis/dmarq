"""Tests for the background health-assessment materialization worker."""

import asyncio

import pytest

from app.services import health_snapshot_refresh


class _ScalarResult:
    def __init__(self, value):
        self.value = value

    def scalar(self):
        return self.value


class _Bind:
    def __init__(self, dialect_name):
        self.dialect = type("Dialect", (), {"name": dialect_name})()


class _LockDatabase:
    def __init__(self, dialect_name="sqlite", lock_value=True):
        self._bind = _Bind(dialect_name)
        self.lock_value = lock_value
        self.executed = []

    def get_bind(self):
        return self._bind

    def execute(self, statement, params):
        self.executed.append((statement, params))
        return _ScalarResult(self.lock_value)


class _Query:
    def __init__(self, value):
        self.value = value

    def filter(self, *_args):
        return self

    def order_by(self, *_args):
        return self

    def limit(self, *_args):
        return self

    def all(self):
        return self.value

    def one_or_none(self):
        return self.value


@pytest.mark.asyncio
async def test_health_snapshot_refresh_materializes_active_domains(monkeypatch):
    """The worker refreshes domains outside a browser request and counts writes."""

    class Settings:
        HEALTH_SNAPSHOT_REFRESH_ENABLED = True
        HEALTH_SNAPSHOT_REFRESH_LIMIT = 3

    refreshed = []

    async def fake_refresh(domain_name, workspace_id):
        refreshed.append((domain_name, workspace_id))
        return domain_name != "unchanged.example"

    monkeypatch.setattr(health_snapshot_refresh, "get_settings", lambda: Settings())
    monkeypatch.setattr(
        health_snapshot_refresh,
        "_active_domains",
        lambda limit: [
            (1, "fresh.example", 10),
            (2, "unchanged.example", 10),
            (3, "other.example", 20),
        ][:limit],
    )
    monkeypatch.setattr(health_snapshot_refresh, "_refresh_domain_snapshot", fake_refresh)

    assert await health_snapshot_refresh.refresh_health_score_snapshots() == 2
    assert refreshed == [
        ("fresh.example", 10),
        ("unchanged.example", 10),
        ("other.example", 20),
    ]


@pytest.mark.asyncio
async def test_health_snapshot_refresh_is_disabled_without_side_effects(monkeypatch):
    class Settings:
        HEALTH_SNAPSHOT_REFRESH_ENABLED = False
        HEALTH_SNAPSHOT_REFRESH_LIMIT = 100

    monkeypatch.setattr(health_snapshot_refresh, "get_settings", lambda: Settings())
    monkeypatch.setattr(
        health_snapshot_refresh,
        "_active_domains",
        lambda _limit: pytest.fail("disabled refresh must not enumerate domains"),
    )

    assert await health_snapshot_refresh.refresh_health_score_snapshots() == 0


@pytest.mark.asyncio
async def test_health_snapshot_refresh_skips_when_limit_is_zero(monkeypatch):
    class Settings:
        HEALTH_SNAPSHOT_REFRESH_ENABLED = True
        HEALTH_SNAPSHOT_REFRESH_LIMIT = 0

    monkeypatch.setattr(health_snapshot_refresh, "get_settings", lambda: Settings())
    monkeypatch.setattr(
        health_snapshot_refresh,
        "_active_domains",
        lambda _limit: pytest.fail("zero limit must not enumerate domains"),
    )

    assert await health_snapshot_refresh.refresh_health_score_snapshots() == 0


def test_health_snapshot_refresh_lock_is_noop_for_sqlite():
    db = _LockDatabase("sqlite")

    assert health_snapshot_refresh._try_acquire_refresh_lock(db) is True
    assert db.executed == []


def test_health_snapshot_refresh_lock_uses_postgres_advisory_lock():
    db = _LockDatabase("postgresql", lock_value=False)

    assert health_snapshot_refresh._try_acquire_refresh_lock(db) is False
    assert len(db.executed) == 1
    assert db.executed[0][1] == {
        "lock_key": health_snapshot_refresh._HEALTH_SNAPSHOT_REFRESH_LOCK_KEY
    }


def test_active_domains_returns_only_named_active_domains(monkeypatch):
    rows = [
        type("DomainRow", (), {"id": 1, "name": "active.example", "workspace_id": 2})(),
        type("DomainRow", (), {"id": 2, "name": "", "workspace_id": 3})(),
    ]

    class Database:
        def __init__(self):
            self.closed = False

        def query(self, *_args):
            return _Query(rows)

        def close(self):
            self.closed = True

    db = Database()
    monkeypatch.setattr(health_snapshot_refresh, "SessionLocal", lambda: db)

    assert health_snapshot_refresh._active_domains(5) == [(1, "active.example", 2)]
    assert db.closed is True


@pytest.mark.asyncio
async def test_refresh_domain_snapshot_persists_cached_assessment(monkeypatch):
    workspace = type("Workspace", (), {"id": 7})()
    captured = {}

    class Database(_LockDatabase):
        def __init__(self):
            super().__init__("sqlite")
            self.closed = False

        def query(self, *_args):
            return _Query(workspace)

        def rollback(self):
            pytest.fail("successful refresh must not roll back")

        def close(self):
            self.closed = True

    class Store:
        def get_domain_summary(self, _domain_name):
            return {"reports_processed": 12}

    async def dns_health(*_args, **kwargs):
        assert kwargs["cached_only"] is True
        return {"status": "pass"}

    async def domain_health(*_args, **kwargs):
        assert kwargs["cached_only"] is True
        return {"score": 96}

    db = Database()
    monkeypatch.setattr(health_snapshot_refresh, "SessionLocal", lambda: db)
    monkeypatch.setattr(health_snapshot_refresh, "ReportStore", Store)
    monkeypatch.setattr(
        health_snapshot_refresh,
        "hydrate_domain_report_store_from_db",
        lambda *args, **kwargs: captured.setdefault("hydrated", (args, kwargs)),
    )
    from app.api.api_v1.endpoints import domains as domain_endpoints

    monkeypatch.setattr(domain_endpoints, "_build_domain_dns_health", dns_health)
    monkeypatch.setattr(domain_endpoints, "_build_domain_health_grade", domain_health)
    monkeypatch.setattr(
        domain_endpoints,
        "_record_health_snapshot_from_posture",
        lambda *_args, **kwargs: captured.setdefault("snapshot", kwargs),
    )

    assert await health_snapshot_refresh._refresh_domain_snapshot("example.test", 7) is True
    assert captured["hydrated"][1]["workspace_id"] == 7
    assert captured["snapshot"] == {
        "workspace_id": 7,
        "domain_id": "example.test",
        "dns_health": {"status": "pass"},
        "domain_health": {"score": 96},
        "report_count": 12,
    }
    assert db.closed is True


@pytest.mark.asyncio
async def test_refresh_domain_snapshot_retains_existing_evidence_on_failure(monkeypatch):
    class Database(_LockDatabase):
        def __init__(self):
            super().__init__("sqlite")
            self.rolled_back = False
            self.closed = False

        def query(self, *_args):
            return _Query(type("Workspace", (), {"id": 7})())

        def rollback(self):
            self.rolled_back = True

        def close(self):
            self.closed = True

    db = Database()
    monkeypatch.setattr(health_snapshot_refresh, "SessionLocal", lambda: db)
    monkeypatch.setattr(health_snapshot_refresh, "ReportStore", lambda: (_ for _ in ()).throw(RuntimeError("bad cache")))

    assert await health_snapshot_refresh._refresh_domain_snapshot("example.test", 7) is False
    assert db.rolled_back is True
    assert db.closed is True


@pytest.mark.asyncio
async def test_scheduled_refresh_honors_startup_and_cancellation(monkeypatch):
    class Settings:
        HEALTH_SNAPSHOT_REFRESH_STARTUP_DELAY_SECONDS = 1
        HEALTH_SNAPSHOT_REFRESH_INTERVAL_SECONDS = 1

    sleeps = []

    async def fake_sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) > 1:
            raise asyncio.CancelledError()

    monkeypatch.setattr(health_snapshot_refresh, "get_settings", lambda: Settings())
    monkeypatch.setattr(health_snapshot_refresh.asyncio, "sleep", fake_sleep)
    monkeypatch.setattr(health_snapshot_refresh, "refresh_health_score_snapshots", lambda: _async_value(1))

    with pytest.raises(asyncio.CancelledError):
        await health_snapshot_refresh.scheduled_health_snapshot_refresh()
    assert sleeps == [5, 60]


async def _async_value(value):
    return value
