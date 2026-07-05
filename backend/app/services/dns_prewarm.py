"""Background DNS cache prewarming for monitored domains."""

from __future__ import annotations

import asyncio
import logging
from typing import List

from sqlalchemy import func

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.models.domain import Domain
from app.models.report import DMARCReport, ReportRecord
from app.services.dns_cache import resolve_domain_dns_cached
from app.services.dns_resolver import get_default_provider

logger = logging.getLogger(__name__)


def _selectors_from_raw(raw_selectors: str | None) -> List[str]:
    raw = raw_selectors or ""
    return [selector.strip() for selector in raw.split(",") if selector.strip()]


def _domain_selectors(domain: Domain) -> List[str]:
    return _selectors_from_raw(domain.dkim_selectors)


def _canonical_domain_name(name: str) -> str:
    return name.strip().rstrip(".").lower()


async def _prewarm_domain(domain_id: int, domain_name: str, selectors: List[str]) -> None:
    db = SessionLocal()
    try:
        provider = get_default_provider(db)
        await resolve_domain_dns_cached(
            db,
            provider,
            domain_name,
            selectors=selectors,
            refresh=True,
        )
        logger.info("Prewarmed DNS cache for domain id=%s", domain_id)
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.warning(
            "DNS cache prewarm failed for domain id=%s with %s",
            domain_id,
            exc.__class__.__name__,
        )
    finally:
        db.close()


async def prewarm_dns_cache() -> None:
    """Refresh DNS cache rows shortly after startup without blocking startup."""
    settings = get_settings()
    if not settings.DNS_STARTUP_PREWARM_ENABLED:
        return

    limit = max(0, int(settings.DNS_STARTUP_PREWARM_LIMIT or 0))
    if limit == 0:
        return

    db = SessionLocal()
    try:
        report_count = func.count(func.distinct(DMARCReport.id))
        message_count = func.coalesce(func.sum(ReportRecord.count), 0)
        activity_score = message_count + (report_count * 1000)
        last_report_end = func.max(DMARCReport.end_date)
        rows = (
            db.query(
                Domain.id,
                Domain.name,
                Domain.dkim_selectors,
                activity_score.label("activity_score"),
                last_report_end.label("last_report_end"),
            )
            .outerjoin(DMARCReport, DMARCReport.domain_id == Domain.id)
            .outerjoin(ReportRecord, ReportRecord.report_id == DMARCReport.id)
            .filter(Domain.active.is_(True))
            .group_by(Domain.id, Domain.name, Domain.dkim_selectors, Domain.updated_at)
            .order_by(
                activity_score.desc(),
                last_report_end.desc(),
                Domain.updated_at.desc(),
                Domain.id.asc(),
            )
            .limit(limit)
            .all()
        )
        candidates = [
            (row.id, canonical_name, _selectors_from_raw(row.dkim_selectors))
            for row in rows
            if row.name and (canonical_name := _canonical_domain_name(row.name))
        ]
    finally:
        db.close()

    if not candidates:
        return

    concurrency = max(1, int(settings.DNS_STARTUP_PREWARM_CONCURRENCY or 1))
    semaphore = asyncio.Semaphore(concurrency)

    async def _bounded(domain_id: int, domain_name: str, selectors: List[str]) -> None:
        async with semaphore:
            await _prewarm_domain(domain_id, domain_name, selectors)

    logger.info("Starting DNS cache prewarm for %d domain(s)", len(candidates))
    await asyncio.gather(*(_bounded(*candidate) for candidate in candidates))
    logger.info("Finished DNS cache prewarm for %d domain(s)", len(candidates))
