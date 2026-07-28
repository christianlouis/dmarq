"""Materialize authoritative domain health assessments outside browser reads."""

from __future__ import annotations

import asyncio
import logging
from typing import List, Tuple

from sqlalchemy import text

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.models.domain import Domain
from app.models.workspace import Workspace
from app.services.report_persistence import hydrate_domain_report_store_from_db
from app.services.report_store import ReportStore
from app.services.workspaces import get_or_create_default_workspace

logger = logging.getLogger(__name__)

_HEALTH_SNAPSHOT_REFRESH_LOCK_KEY = 1_144_591_956


def _try_acquire_refresh_lock(db) -> bool:
    """Allow only one replica to materialize health snapshots at a time."""
    if db.get_bind().dialect.name != "postgresql":
        return True
    return bool(
        db.execute(
            text("SELECT pg_try_advisory_xact_lock(:lock_key)"),
            {"lock_key": _HEALTH_SNAPSHOT_REFRESH_LOCK_KEY},
        ).scalar()
    )


def _active_domains(limit: int) -> List[Tuple[int, str, int | None]]:
    db = SessionLocal()
    try:
        rows = (
            db.query(Domain.id, Domain.name, Domain.workspace_id)
            .filter(Domain.active.is_(True))
            .order_by(Domain.updated_at.desc(), Domain.id.asc())
            .limit(limit)
            .all()
        )
        return [(int(row.id), str(row.name), row.workspace_id) for row in rows if row.name]
    finally:
        db.close()


async def _refresh_domain_snapshot(domain_name: str, workspace_id: int | None) -> bool:
    """Score one domain from prewarmed evidence and persist it atomically."""
    # The endpoint module owns the existing assessment and DNS-health builders.
    # Import lazily so application startup stays free from an API/service cycle.
    from app.api.api_v1.endpoints import domains as domain_endpoints

    db = SessionLocal()
    try:
        if not _try_acquire_refresh_lock(db):
            return False
        workspace = (
            db.query(Workspace).filter(Workspace.id == workspace_id).one_or_none()
            if workspace_id is not None
            else get_or_create_default_workspace(db)
        )
        if workspace is None:
            return False
        store = ReportStore()
        hydrate_domain_report_store_from_db(
            db,
            store,
            domain_name,
            workspace_id=workspace.id,
            days=30,
        )
        dns_health = await domain_endpoints._build_domain_dns_health(
            db,
            store,
            domain_name,
            cached_only=True,
        )
        domain_health = await domain_endpoints._build_domain_health_grade(
            db,
            domain_name,
            store,
            cached_only=True,
        )
        summary = store.get_domain_summary(domain_name)
        domain_endpoints._record_health_snapshot_from_posture(
            db,
            workspace_id=workspace.id,
            domain_id=domain_name,
            dns_health=dns_health,
            domain_health=domain_health,
            report_count=int(summary.get("reports_processed", 0) or 0),
        )
        return True
    except asyncio.CancelledError:
        raise
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.warning(
            "Health snapshot refresh failed for domain=%s with %s",
            domain_name,
            type(exc).__name__,
        )
        db.rollback()
        return False
    finally:
        db.close()


async def refresh_health_score_snapshots() -> int:
    """Persist current health once DNS/source cache evidence is ready."""
    settings = get_settings()
    if not settings.HEALTH_SNAPSHOT_REFRESH_ENABLED:
        return 0
    limit = max(0, int(settings.HEALTH_SNAPSHOT_REFRESH_LIMIT or 0))
    if limit == 0:
        return 0
    refreshed = 0
    for _domain_id, domain_name, workspace_id in _active_domains(limit):
        if await _refresh_domain_snapshot(domain_name, workspace_id):
            refreshed += 1
    if refreshed:
        logger.info("Refreshed persisted health snapshots for %d domain(s)", refreshed)
    return refreshed


async def scheduled_health_snapshot_refresh() -> None:
    """Continuously materialize health after ingestion and DNS evidence refresh."""
    settings = get_settings()
    # DNS and source evidence workers receive the first pass after startup.
    await asyncio.sleep(max(5, int(settings.HEALTH_SNAPSHOT_REFRESH_STARTUP_DELAY_SECONDS)))
    while True:
        try:
            await refresh_health_score_snapshots()
        except asyncio.CancelledError:
            raise
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.warning("Scheduled health snapshot refresh failed with %s", type(exc).__name__)
        await asyncio.sleep(max(60, int(settings.HEALTH_SNAPSHOT_REFRESH_INTERVAL_SECONDS)))
