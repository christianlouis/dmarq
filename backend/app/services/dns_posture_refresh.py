"""Coalesced background refresh for immutable DNS posture evidence."""

from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timedelta
from typing import List, Tuple

from sqlalchemy import case, func, or_, text

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.models.dns_posture_snapshot import DomainDNSPostureCurrent
from app.models.domain import Domain
from app.services.bimi import check_bimi_cached
from app.services.dane import check_dane_cached
from app.services.dns_cache import resolve_domain_dns_cached
from app.services.dns_posture_snapshots import capture_dns_posture_snapshot
from app.services.dns_resolver import get_default_provider
from app.services.mta_sts import check_mta_sts_cached
from app.services.report_persistence import hydrate_domain_report_store_from_db
from app.services.report_store import ReportStore

logger = logging.getLogger(__name__)

_DNS_POSTURE_REFRESH_LOCK_KEY = 1_144_591_957
MAX_DNS_POSTURE_SELECTORS = 100


def _try_acquire_refresh_lock(db) -> bool:
    if db.get_bind().dialect.name != "postgresql":
        return True
    return bool(
        db.execute(
            text("SELECT pg_try_advisory_xact_lock(:lock_key)"),
            {"lock_key": _DNS_POSTURE_REFRESH_LOCK_KEY},
        ).scalar()
    )


def _baseline_expired(current: DomainDNSPostureCurrent) -> bool:
    max_age = int(getattr(get_settings(), "DNS_POSTURE_MAX_AGE_SECONDS", 0) or 0)
    if max_age <= 0 or current.completed_at is None:
        return max_age > 0
    return current.completed_at <= datetime.utcnow() - timedelta(seconds=max_age)


def _selectors(db, domain: Domain) -> list[str]:
    """Return manual and persisted report-observed selectors for one domain."""
    manual = [item.strip() for item in (domain.dkim_selectors or "").split(",") if item.strip()]
    store = ReportStore()
    hydrate_domain_report_store_from_db(
        db,
        store,
        domain.name,
        workspace_id=domain.workspace_id,
        limit=500,
    )
    observed = [
        str(item["selector"])
        for item in store.get_domain_selector_evidence(domain.name)
        if item.get("selector")
    ]
    # Report selectors are attacker-controlled input. Keep refresh work bounded
    # even when a tenant has accumulated a large historical report archive.
    return list(dict.fromkeys(manual + observed))[:MAX_DNS_POSTURE_SELECTORS]


def _candidates(limit: int) -> List[Tuple[int, str]]:
    db = SessionLocal()
    try:
        # A bounded batch must be fair to both requested work and completed
        # evidence that has aged out.  A failed attempt records completed_at,
        # so it is retried after the normal age window instead of occupying
        # every batch until the resolver recovers.
        max_age = int(getattr(get_settings(), "DNS_POSTURE_MAX_AGE_SECONDS", 0) or 0)
        eligibility = [
            DomainDNSPostureCurrent.id.is_(None),
            DomainDNSPostureCurrent.requested_at.isnot(None),
            DomainDNSPostureCurrent.completed_at.is_(None),
        ]
        if max_age > 0:
            eligibility.append(
                DomainDNSPostureCurrent.completed_at
                <= datetime.utcnow() - timedelta(seconds=max_age)
            )
        # Pending requests are due when requested; completed work is due when
        # it was last attempted.  Ordering both classes on that timestamp
        # prevents a stream of fresh ingest requests from starving stale
        # low-volume domains.
        due_at = case(
            (
                DomainDNSPostureCurrent.requested_at.isnot(None),
                DomainDNSPostureCurrent.requested_at,
            ),
            else_=func.coalesce(DomainDNSPostureCurrent.completed_at, Domain.created_at),
        )
        rows = (
            db.query(Domain.id, Domain.name)
            .outerjoin(DomainDNSPostureCurrent, DomainDNSPostureCurrent.domain_id == Domain.id)
            .filter(Domain.active.is_(True))
            .filter(or_(*eligibility))
            .order_by(
                due_at.asc(),
                Domain.id.asc(),
            )
            .limit(limit)
            .all()
        )
        return [(int(row.id), str(row.name)) for row in rows if row.name]
    finally:
        db.close()


async def _refresh_side_checks(db, provider, domain: Domain) -> None:
    """Best-effort refresh of optional posture caches, isolated per check."""
    checks = (
        ("MTA-STS", check_mta_sts_cached, {}),
        ("BIMI", check_bimi_cached, {}),
        ("DANE", check_dane_cached, {"derive_suggestions": True}),
    )
    for label, check, kwargs in checks:
        try:
            timeout = max(
                0.1,
                float(
                    getattr(get_settings(), "DNS_POSTURE_SIDE_CHECK_TIMEOUT_SECONDS", 5.0) or 5.0
                ),
            )
            await asyncio.wait_for(
                check(db, provider, domain.name, refresh=True, **kwargs), timeout=timeout
            )
            db.commit()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pylint: disable=broad-exception-caught
            db.rollback()
            logger.warning(
                "DNS %s side-check refresh failed for domain id=%s with %s",
                label,
                domain.id,
                type(exc).__name__,
            )


def _record_refresh_failure(db, domain_id: int, exc: Exception) -> None:
    """Record a failed attempt without retaining provider error details."""
    try:
        domain = db.get(Domain, domain_id)
        if domain is not None and domain.active:
            current = db.query(DomainDNSPostureCurrent).filter_by(domain_id=domain_id).one_or_none()
            if current is None:
                current = DomainDNSPostureCurrent(
                    domain_id=domain_id,
                    workspace_id=domain.workspace_id,
                )
                db.add(current)
            current.completed_at = datetime.utcnow()
            current.requested_at = None
            current.next_trigger = None
            current.last_error = type(exc).__name__
            db.commit()
    except Exception:  # pylint: disable=broad-exception-caught
        db.rollback()


async def refresh_domain_dns_posture(domain_id: int) -> bool:
    """Resolve one domain and atomically publish a safe evidence snapshot."""
    db = SessionLocal()
    try:
        if not _try_acquire_refresh_lock(db):
            return False
        domain = db.get(Domain, domain_id)
        if domain is None or not domain.active:
            return False
        current = db.query(DomainDNSPostureCurrent).filter_by(domain_id=domain.id).one_or_none()
        # Refresh requested work, new baselines, and completed baselines that
        # have aged out. This keeps low-volume domains from staying stale.
        if (
            current is not None
            and current.requested_at is None
            and current.accepted_snapshot_id
            and not _baseline_expired(current)
        ):
            return False
        provider = get_default_provider(db)
        selectors = _selectors(db, domain)
        result, cached, checked_at = await resolve_domain_dns_cached(
            db,
            provider,
            domain.name,
            selectors=selectors,
            refresh=True,
        )
        trigger = str((current.next_trigger if current else None) or "scheduled")
        snapshot = capture_dns_posture_snapshot(
            db,
            domain=domain,
            result=result,
            selectors=selectors,
            trigger=trigger,
            provenance={
                "cache_hit": bool(cached),
                "resolver_route": result.resolver_route,
                "resolver_identity": result.resolver_identity,
                "fallback_attempts": list(result.fallback_attempts or []),
                "source_checked_at": checked_at.isoformat() if checked_at else None,
            },
            absence_confirmations_required=max(
                2, int(get_settings().DNS_POSTURE_ABSENCE_CONFIRMATIONS or 2)
            ),
        )
        db.commit()
        await _refresh_side_checks(db, provider, domain)
        logger.info(
            "Materialized DNS posture snapshot id=%s for domain id=%s accepted=%s",
            snapshot.id,
            domain.id,
            snapshot.accepted,
        )
        return True
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # pylint: disable=broad-exception-caught
        db.rollback()
        # A transport or resolver exception has no immutable observation to
        # capture, but it is still a completed attempt.  Record only the
        # exception type to avoid retaining provider details while preventing
        # this domain from consuming every scheduled batch.
        _record_refresh_failure(db, domain_id, exc)
        logger.warning(
            "DNS posture refresh failed for domain id=%s with %s", domain_id, type(exc).__name__
        )
        return False
    finally:
        db.close()


async def refresh_requested_dns_posture() -> int:
    settings = get_settings()
    if not settings.DNS_POSTURE_REFRESH_ENABLED:
        return 0
    count = 0
    for domain_id, _domain_name in _candidates(
        max(0, int(settings.DNS_POSTURE_REFRESH_LIMIT or 0))
    ):
        if await refresh_domain_dns_posture(domain_id):
            count += 1
    return count


async def scheduled_dns_posture_refresh() -> None:
    """Materialize requested DNS evidence after startup without blocking UI."""
    settings = get_settings()
    await asyncio.sleep(max(5, int(settings.DNS_POSTURE_REFRESH_STARTUP_DELAY_SECONDS or 5)))
    while True:
        try:
            count = await refresh_requested_dns_posture()
            if count:
                logger.info("Materialized DNS posture evidence for %s domain(s)", count)
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.warning("DNS posture refresh worker failed with %s", type(exc).__name__)
        await asyncio.sleep(max(60, int(settings.DNS_POSTURE_REFRESH_INTERVAL_SECONDS or 300)))
