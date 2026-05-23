"""Cross-workspace operator summaries for MSP mode."""

# pylint: disable=not-callable

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.alert import AlertHistory
from app.models.domain import Domain
from app.models.mail_source import MailSource
from app.models.mail_source_import import MailSourceImport
from app.models.report import DMARCReport
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceAuditLog


def retention_to_dict(workspace: Workspace) -> Dict[str, int]:
    """Return workspace retention controls."""
    return {
        "aggregate_reports_days": workspace.report_retention_days,
        "forensic_reports_days": workspace.forensic_retention_days,
        "tls_reports_days": workspace.tls_report_retention_days,
    }


def _last_import(db: Session, workspace: Workspace) -> Optional[MailSourceImport]:
    return (
        db.query(MailSourceImport)
        .join(MailSource, MailSourceImport.mail_source_id == MailSource.id)
        .filter(MailSource.workspace_id == workspace.id)
        .order_by(MailSourceImport.finished_at.desc(), MailSourceImport.id.desc())
        .first()
    )


def _recent_audit_rows(
    db: Session,
    workspace: Workspace,
    *,
    since: datetime,
    limit: int = 5,
) -> List[WorkspaceAuditLog]:
    return (
        db.query(WorkspaceAuditLog)
        .filter(
            WorkspaceAuditLog.workspace_id == workspace.id,
            WorkspaceAuditLog.created_at >= since,
        )
        .order_by(WorkspaceAuditLog.created_at.desc(), WorkspaceAuditLog.id.desc())
        .limit(limit)
        .all()
    )


def _active_alert_count(db: Session, domain_names: List[str]) -> int:
    if not domain_names:
        return 0
    return (
        db.query(func.count(AlertHistory.id))
        .filter(AlertHistory.domain.in_(domain_names), AlertHistory.is_active.is_(True))
        .scalar()
        or 0
    )


def _failed_import_count(db: Session, workspace: Workspace, since: datetime) -> int:
    return (
        db.query(func.count(MailSourceImport.id))
        .join(MailSource, MailSourceImport.mail_source_id == MailSource.id)
        .filter(
            MailSource.workspace_id == workspace.id,
            MailSourceImport.finished_at >= since,
            MailSourceImport.status != "success",
        )
        .scalar()
        or 0
    )


def _health_status(
    *,
    domain_count: int,
    enabled_sources: int,
    verified_domains: int,
    active_alerts: int,
    failed_imports: int,
    last_import: Optional[MailSourceImport],
) -> str:
    if domain_count == 0 or enabled_sources == 0 or active_alerts > 0 or failed_imports > 0:
        return "critical"
    if verified_domains < domain_count or last_import is None:
        return "warning"
    return "healthy"


def workspace_operator_summary(  # pylint: disable=too-many-locals
    db: Session,
    workspace: Workspace,
    *,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Return one safe cross-workspace operator summary."""
    now = now or datetime.utcnow()
    since = now - timedelta(days=7)
    domains = (
        db.query(Domain).filter(Domain.workspace_id == workspace.id).order_by(Domain.name).all()
    )
    domain_names = [domain.name for domain in domains]
    domain_count = len(domains)
    active_domains = sum(1 for domain in domains if domain.active)
    verified_domains = sum(1 for domain in domains if domain.verified)
    source_count = (
        db.query(func.count(MailSource.id)).filter(MailSource.workspace_id == workspace.id).scalar()
        or 0
    )
    enabled_sources = (
        db.query(func.count(MailSource.id))
        .filter(MailSource.workspace_id == workspace.id, MailSource.enabled.is_(True))
        .scalar()
        or 0
    )
    report_count = (
        db.query(func.count(DMARCReport.id))
        .join(Domain, DMARCReport.domain_id == Domain.id)
        .filter(Domain.workspace_id == workspace.id)
        .scalar()
        or 0
    )
    last_import = _last_import(db, workspace)
    active_alerts = _active_alert_count(db, domain_names)
    failed_imports = _failed_import_count(db, workspace, since)
    drift_rows = _recent_audit_rows(db, workspace, since=since)
    return {
        "workspace": {
            "id": workspace.id,
            "slug": workspace.slug,
            "name": workspace.name,
            "active": workspace.active,
        },
        "health": {
            "status": _health_status(
                domain_count=domain_count,
                enabled_sources=int(enabled_sources),
                verified_domains=verified_domains,
                active_alerts=active_alerts,
                failed_imports=failed_imports,
                last_import=last_import,
            ),
            "active_alerts": active_alerts,
            "failed_imports_7d": failed_imports,
            "drift_events_7d": len(drift_rows),
        },
        "domains": {
            "total": domain_count,
            "active": active_domains,
            "verified": verified_domains,
            "names": domain_names,
        },
        "mail_sources": {
            "total": source_count,
            "enabled": int(enabled_sources),
            "last_import_at": last_import.finished_at.isoformat() if last_import else None,
            "last_import_status": last_import.status if last_import else None,
        },
        "reports": {"aggregate_total": int(report_count)},
        "retention": retention_to_dict(workspace),
        "recent_drift": [
            {
                "action": row.action,
                "entity_type": row.entity_type,
                "entity_name": row.entity_name,
                "created_at": row.created_at.isoformat() if row.created_at else None,
            }
            for row in drift_rows
        ],
    }


def list_workspace_operator_summaries(db: Session) -> List[Dict[str, Any]]:
    """Return safe summaries for every active workspace."""
    workspaces = (
        db.query(Workspace).filter(Workspace.active.is_(True)).order_by(Workspace.slug).all()
    )
    return [workspace_operator_summary(db, workspace) for workspace in workspaces]
