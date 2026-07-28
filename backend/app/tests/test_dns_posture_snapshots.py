from app.models.dns_posture_snapshot import DomainDNSPostureCurrent, DomainDNSPostureSnapshot
from app.models.domain import Domain
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

    result, checked_at, provenance = accepted_dns_posture_result(db_session, domain_name=domain.name)
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
