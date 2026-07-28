"""Coalesced background refresh for immutable DNS posture evidence."""

from __future__ import annotations

import asyncio
import logging
from typing import List, Tuple

from sqlalchemy import text

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.models.dns_posture_snapshot import DomainDNSPostureCurrent
from app.models.domain import Domain
from app.services.dns_cache import resolve_domain_dns_cached
from app.services.dns_posture_snapshots import capture_dns_posture_snapshot
from app.services.dns_resolver import get_default_provider

logger = logging.getLogger(__name__)

_DNS_POSTURE_REFRESH_LOCK_KEY = 1_144_591_957


def _try_acquire_refresh_lock(db) -> bool:
    if db.get_bind().dialect.name != "postgresql":
        return True
    return bool(
        db.execute(
            text("SELECT pg_try_advisory_xact_lock(:lock_key)"),
            {"lock_key": _DNS_POSTURE_REFRESH_LOCK_KEY},
        ).scalar()
    )


def _selectors(domain: Domain) -> list[str]:
    return [item.strip() for item in (domain.dkim_selectors or "").split(",") if item.strip()]


def _candidates(limit: int) -> List[Tuple[int, str]]:
    db = SessionLocal()
    try:
        # Work explicitly requested by ingestion first, then establish a
        # baseline for active domains that have never been materialized.
        rows = (
            db.query(Domain.id, Domain.name)
            .outerjoin(DomainDNSPostureCurrent, DomainDNSPostureCurrent.domain_id == Domain.id)
            .filter(Domain.active.is_(True))
            .order_by(
                DomainDNSPostureCurrent.requested_at.desc().nullslast(),
                DomainDNSPostureCurrent.completed_at.asc().nullsfirst(),
                Domain.id.asc(),
            )
            .limit(limit)
            .all()
        )
        return [(int(row.id), str(row.name)) for row in rows if row.name]
    finally:
        db.close()


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
        # A completed baseline is refreshed only after an ingest/operator
        # request. This avoids periodic network work unrelated to new data.
        if current is not None and current.requested_at is None and current.accepted_snapshot_id:
            return False
        provider = get_default_provider(db)
        selectors = _selectors(domain)
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
