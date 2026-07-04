"""Background DNS cache prewarming for monitored domains."""

from __future__ import annotations

import asyncio
import logging
from typing import List

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.models.domain import Domain
from app.services.dns_cache import resolve_domain_dns_cached
from app.services.dns_resolver import get_default_provider

logger = logging.getLogger(__name__)


def _domain_selectors(domain: Domain) -> List[str]:
    raw = domain.dkim_selectors or ""
    return [selector.strip() for selector in raw.split(",") if selector.strip()]


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
        domains = (
            db.query(Domain)
            .filter(Domain.active.is_(True))
            .order_by(Domain.updated_at.desc(), Domain.id.asc())
            .limit(limit)
            .all()
        )
        candidates = [
            (domain.id, domain.name, _domain_selectors(domain)) for domain in domains if domain.name
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
