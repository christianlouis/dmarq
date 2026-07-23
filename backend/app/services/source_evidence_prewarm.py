"""Background prewarming for sender PTR and network evidence."""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import asdict
from datetime import datetime, timezone
from typing import List

from sqlalchemy import func

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.models.report import DMARCReport, ReportRecord
from app.services.dns_resolver import get_default_provider
from app.services.ptr_lookup import PtrLookupResult, lookup_ptr_with_fallbacks
from app.services.source_network import SourceNetworkIntelligence, lookup_sources_network_cached
from app.services.source_reputation_feeds import (
    lookup_sources_reputation_cached,
    providers_from_settings,
)

logger = logging.getLogger(__name__)


def ptr_from_source_evidence(evidence: object):
    """Restore a structured PTR result from a report-row evidence snapshot."""
    if not isinstance(evidence, dict) or not isinstance(evidence.get("ptr"), dict):
        return None
    allowed = {field.name for field in PtrLookupResult.__dataclass_fields__.values()}
    payload = evidence["ptr"]
    return PtrLookupResult(**{key: payload[key] for key in payload if key in allowed})


def network_from_source_evidence(evidence: object):
    """Restore network context from a report-row evidence snapshot."""
    if not isinstance(evidence, dict) or not isinstance(evidence.get("network"), dict):
        return None
    allowed = {field.name for field in SourceNetworkIntelligence.__dataclass_fields__.values()}
    payload = evidence["network"]
    if not payload:
        return None
    return SourceNetworkIntelligence(**{key: payload[key] for key in payload if key in allowed})


def _recent_source_ips(limit: int) -> List[str]:
    db = SessionLocal()
    try:
        rows = (
            db.query(
                ReportRecord.source_ip,
                func.max(DMARCReport.end_date).label("last_seen"),
                func.sum(ReportRecord.count).label("message_count"),
            )
            .join(DMARCReport, DMARCReport.id == ReportRecord.report_id)
            .filter(ReportRecord.source_ip.isnot(None), ReportRecord.source_ip != "unknown")
            .group_by(ReportRecord.source_ip)
            .order_by(
                func.max(DMARCReport.end_date).desc(),
                func.sum(ReportRecord.count).desc(),
            )
            .limit(limit)
            .all()
        )
        return [str(row.source_ip) for row in rows if row.source_ip]
    finally:
        db.close()


async def prewarm_source_evidence() -> int:
    """Capture point-in-time PTR, network, and reputation evidence for report rows."""
    settings = get_settings()
    if not settings.SOURCE_EVIDENCE_PREWARM_ENABLED:
        return 0

    limit = max(0, int(settings.SOURCE_EVIDENCE_PREWARM_LIMIT or 0))
    if limit == 0:
        return 0
    source_ips = _recent_source_ips(limit)
    if not source_ips:
        return 0

    db = SessionLocal()
    try:
        provider = get_default_provider(db)
        network_task = asyncio.create_task(
            lookup_sources_network_cached(
                db,
                provider,
                source_ips,
                ttl_seconds=settings.SOURCE_NETWORK_ENRICHMENT_CACHE_SECONDS,
                max_ips=limit,
                concurrency=settings.SOURCE_EVIDENCE_PREWARM_CONCURRENCY,
                timeout_seconds=settings.SOURCE_EVIDENCE_PREWARM_TIMEOUT_SECONDS,
            )
        )
        semaphore = asyncio.Semaphore(max(1, settings.SOURCE_EVIDENCE_PREWARM_CONCURRENCY))

        ptr_results = {}

        async def _prewarm_ptr(ip: str) -> None:
            async with semaphore:
                ptr_results[ip] = await lookup_ptr_with_fallbacks(
                    provider, ip, timeout=2.0, use_cache=True
                )

        ptr_task = asyncio.gather(*(_prewarm_ptr(ip) for ip in source_ips))
        networks, _ = await asyncio.gather(network_task, ptr_task)
        feed_providers = providers_from_settings(settings)
        reputation = await lookup_sources_reputation_cached(
            db,
            source_ips,
            feed_providers,
            ttl_seconds=settings.SOURCE_REPUTATION_FEED_CACHE_SECONDS,
            max_ips=limit,
        )

        captured_at = (
            datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        )
        rows = (
            db.query(ReportRecord)
            .filter(
                ReportRecord.source_evidence.is_(None),
                ReportRecord.source_ip.in_(source_ips),
            )
            .all()
        )
        completed_ips = {ip for ip, ptr_result in ptr_results.items() if not ptr_result.transient}
        rows = [row for row in rows if str(row.source_ip) in completed_ips]
        for row in rows:
            ip = str(row.source_ip)
            feed_result = reputation.get(ip)
            row.source_evidence = json.dumps(
                {
                    "captured_at": captured_at,
                    "ptr": ptr_results[ip].as_public_dict(),
                    "network": asdict(networks[ip]) if ip in networks else {},
                    "reputation": (
                        {
                            **asdict(feed_result),
                            "status": "listed" if feed_result.listed else "clear",
                        }
                        if feed_result and feed_providers
                        else {
                            "ip": ip,
                            "status": "not_configured",
                            "listed": False,
                            "evidence": [],
                        }
                    ),
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        if rows:
            db.commit()
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.warning("Sender evidence prewarm failed with %s", type(exc).__name__)
        return 0
    finally:
        db.close()

    logger.info(
        "Captured sender evidence for %d report row(s) across %d source IP(s)",
        len(rows),
        len(source_ips),
    )
    return len(rows)


async def scheduled_source_evidence_prewarm() -> None:
    """Continuously warm new sender IPs after report ingestion."""
    settings = get_settings()
    # Let startup migrations and domain DNS prewarming take the first write turn,
    # especially on the default single-file SQLite deployment.
    await asyncio.sleep(2)
    while True:
        try:
            await prewarm_source_evidence()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.warning("Scheduled sender evidence prewarm failed with %s", type(exc).__name__)
        await asyncio.sleep(max(30, int(settings.SOURCE_EVIDENCE_PREWARM_INTERVAL_SECONDS)))
