import asyncio
import json
from datetime import datetime

import pytest

from app.models.dns_posture_snapshot import DomainDNSPostureCurrent, DomainDNSPostureSnapshot
from app.models.domain import Domain
from app.models.workspace import Workspace
from app.services import dns_posture_refresh
from app.services.dns_posture_snapshots import (
    accepted_dns_posture_result,
    capture_dns_posture_snapshot,
    request_dns_posture_refresh,
    selector_fingerprint,
)
from app.services.dns_resolver import DomainDNSResult
from app.services.report_persistence import save_parsed_report
from app.services.report_store import ReportStore


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


def _report(domain, report_id, *, selector, dkim_domain=None, end_timestamp=None):
    return {
        "domain": domain,
        "report_id": report_id,
        "org_name": "reporter.example",
        "begin_timestamp": end_timestamp or 1_700_000_000,
        "end_timestamp": end_timestamp or 1_700_003_600,
        "policy": {"p": "reject"},
        "records": [
            {
                "source_ip": "192.0.2.1",
                "count": 1,
                "disposition": "none",
                "dkim_result": "pass",
                "spf_result": "pass",
                "dkim": [{"domain": dkim_domain or domain, "selector": selector, "result": "pass"}],
                "spf": [],
                "header_from": domain,
            }
        ],
    }


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
async def test_refresh_domain_uses_persisted_report_selector_and_scopes_evidence(
    db_session, monkeypatch
):
    workspace = Workspace(slug="selector-refresh", name="Selector Refresh")
    other_workspace = Workspace(slug="other-selector-refresh", name="Other Selector Refresh")
    domain = Domain(name="worker-report.example", workspace=workspace, active=True)
    other_domain = Domain(name="other-report.example", workspace=other_workspace, active=True)
    db_session.add_all([workspace, other_workspace, domain, other_domain])
    db_session.flush()
    save_parsed_report(
        db_session,
        _report(domain.name, "target-report", selector="20i"),
        workspace_id=workspace.id,
    )
    save_parsed_report(
        db_session,
        _report(other_domain.name, "other-report", selector="wrong-workspace"),
        workspace_id=other_workspace.id,
    )
    db_session.commit()
    singleton = ReportStore.get_instance()
    singleton.add_report(_report(domain.name, "singleton-report", selector="singleton-only"))
    seen = {}

    async def resolve(*_args, **kwargs):
        seen["selectors"] = kwargs["selectors"]
        result = _result()
        result.dkim = True
        result.dkim_selectors = ["20i"]
        result.selectors_checked = list(kwargs["selectors"])
        return result, False, datetime.utcnow()

    monkeypatch.setattr(dns_posture_refresh, "SessionLocal", lambda: db_session)
    monkeypatch.setattr(dns_posture_refresh, "get_default_provider", lambda _db: object())
    monkeypatch.setattr(dns_posture_refresh, "resolve_domain_dns_cached", resolve)

    assert await dns_posture_refresh.refresh_domain_dns_posture(domain.id) is True
    current = db_session.query(DomainDNSPostureCurrent).filter_by(domain_id=domain.id).one()
    snapshot = db_session.get(DomainDNSPostureSnapshot, current.accepted_snapshot_id)
    result, _checked_at, _provenance = accepted_dns_posture_result(
        db_session, domain_name=domain.name
    )
    assert seen["selectors"] == ["20i"]
    assert snapshot.accepted is True
    assert current.selector_hash == selector_fingerprint(["20i"])
    assert snapshot.selector_hash == selector_fingerprint(["20i"])
    assert json.loads(snapshot.result_json)["dkim_selectors"] == ["20i"]
    assert result is not None and result.dkim is True
    assert [item["selector"] for item in singleton.get_domain_selector_evidence(domain.name)] == [
        "singleton-only"
    ]


def test_selectors_merge_manual_and_report_evidence_without_unaligned_or_other_workspace_rows(
    db_session,
):
    workspace = Workspace(slug="selector-merge", name="Selector Merge")
    other_workspace = Workspace(slug="selector-merge-other", name="Selector Merge Other")
    domain = Domain(
        name="merge-report.example",
        workspace=workspace,
        dkim_selectors="manual,20i",
        active=True,
    )
    other_domain = Domain(name="unrelated.example", workspace=other_workspace, active=True)
    db_session.add_all([workspace, other_workspace, domain, other_domain])
    db_session.flush()
    save_parsed_report(
        db_session,
        _report(domain.name, "merge-target", selector="20i"),
        workspace_id=workspace.id,
    )
    save_parsed_report(
        db_session,
        _report(
            domain.name,
            "unaligned-target",
            selector="unaligned",
            dkim_domain="other.example",
        ),
        workspace_id=workspace.id,
    )
    save_parsed_report(
        db_session,
        _report(other_domain.name, "other-workspace", selector="leak"),
        workspace_id=other_workspace.id,
    )
    db_session.commit()

    assert dns_posture_refresh._selectors(db_session, domain) == ["manual", "20i"]


def test_selectors_fall_back_to_manual_configuration_without_reports(db_session):
    domain = Domain(name="manual-only.example", dkim_selectors="manual,", active=True)
    db_session.add(domain)
    db_session.commit()
    assert dns_posture_refresh._selectors(db_session, domain) == ["manual"]


def test_selectors_bound_manual_report_input_before_dns_refresh(db_session):
    selectors = ",".join(f"attacker-{index}" for index in range(150))
    domain = Domain(name="bounded-selectors.example", dkim_selectors=selectors, active=True)
    db_session.add(domain)
    db_session.commit()

    selected = dns_posture_refresh._selectors(db_session, domain)

    assert len(selected) == dns_posture_refresh.MAX_DNS_POSTURE_SELECTORS
    assert selected[0] == "attacker-0"
    assert selected[-1] == "attacker-99"

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
