"""Read-only workspace usage summaries for public API and MCP clients."""

from __future__ import annotations

from collections import Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import case, func
from sqlalchemy.orm import Session

from app.models.alert import AlertHistory
from app.models.domain import Domain
from app.models.mail_source import MailSource
from app.models.mail_source_import import MailSourceImport
from app.models.report import DMARCReport, ForensicReport, ReportRecord, TLSReport
from app.models.workspace import Workspace


def _timestamp() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _unix_timestamp(value: Optional[int]) -> Optional[str]:
    if value is None:
        return None
    return datetime.fromtimestamp(int(value), tz=timezone.utc).replace(microsecond=0).isoformat()


def _rate(numerator: int, denominator: int) -> float:
    if denominator <= 0:
        return 0.0
    return round((numerator / denominator) * 100, 1)


def _workspace_domains(db: Session, workspace: Workspace) -> List[Domain]:
    return (
        db.query(Domain)
        .filter(Domain.workspace_id == workspace.id)
        .order_by(Domain.name.asc())
        .all()
    )


def _message_totals(db: Session, domain_ids: List[int]) -> Dict[str, Any]:
    if not domain_ids:
        return {
            "total_messages": 0,
            "compliant_messages": 0,
            "failed_messages": 0,
            "distinct_source_count": 0,
        }
    row = (
        db.query(
            func.coalesce(func.sum(ReportRecord.count), 0).label("total_messages"),
            func.coalesce(
                func.sum(
                    case(
                        (
                            (ReportRecord.dkim == "pass") | (ReportRecord.spf == "pass"),
                            ReportRecord.count,
                        ),
                        else_=0,
                    )
                ),
                0,
            ).label("compliant_messages"),
            func.coalesce(
                func.sum(
                    case(
                        (
                            (func.coalesce(ReportRecord.dkim, "fail") != "pass")
                            & (func.coalesce(ReportRecord.spf, "fail") != "pass"),
                            ReportRecord.count,
                        ),
                        else_=0,
                    )
                ),
                0,
            ).label("failed_messages"),
            func.count(func.distinct(ReportRecord.source_ip)).label("distinct_source_count"),
        )
        .join(DMARCReport, DMARCReport.id == ReportRecord.report_id)
        .filter(DMARCReport.domain_id.in_(domain_ids))
        .first()
    )
    if row is None:
        return {
            "total_messages": 0,
            "compliant_messages": 0,
            "failed_messages": 0,
            "distinct_source_count": 0,
        }
    return {
        "total_messages": int(row.total_messages or 0),
        "compliant_messages": int(row.compliant_messages or 0),
        "failed_messages": int(row.failed_messages or 0),
        "distinct_source_count": int(row.distinct_source_count or 0),
    }


def _domain_usage_rows(db: Session, domains: List[Domain]) -> List[Dict[str, Any]]:
    if not domains:
        return []
    domain_ids = [domain.id for domain in domains]
    rows = (
        db.query(
            Domain.id.label("domain_id"),
            func.count(func.distinct(DMARCReport.id)).label("report_count"),
            func.coalesce(func.sum(ReportRecord.count), 0).label("total_messages"),
            func.coalesce(
                func.sum(
                    case(
                        (
                            (func.coalesce(ReportRecord.dkim, "fail") != "pass")
                            & (func.coalesce(ReportRecord.spf, "fail") != "pass"),
                            ReportRecord.count,
                        ),
                        else_=0,
                    )
                ),
                0,
            ).label("failed_messages"),
            func.count(func.distinct(ReportRecord.source_ip)).label("source_count"),
            func.max(DMARCReport.end_date).label("last_report_end"),
        )
        .outerjoin(DMARCReport, DMARCReport.domain_id == Domain.id)
        .outerjoin(ReportRecord, ReportRecord.report_id == DMARCReport.id)
        .filter(Domain.id.in_(domain_ids))
        .group_by(Domain.id)
        .all()
    )
    by_domain_id = {int(row.domain_id): row for row in rows}
    usage_rows = []
    for domain in domains:
        row = by_domain_id.get(domain.id)
        total_messages = int(row.total_messages or 0) if row is not None else 0
        failed_messages = int(row.failed_messages or 0) if row is not None else 0
        compliant_messages = max(total_messages - failed_messages, 0)
        usage_rows.append(
            {
                "domain": domain.name,
                "active": bool(domain.active),
                "verified": bool(domain.verified),
                "dmarc_policy": domain.dmarc_policy,
                "report_count": int(row.report_count or 0) if row is not None else 0,
                "total_messages": total_messages,
                "failed_messages": failed_messages,
                "compliant_messages": compliant_messages,
                "compliance_rate": _rate(compliant_messages, total_messages),
                "source_count": int(row.source_count or 0) if row is not None else 0,
                "last_report_end_at": (
                    _unix_timestamp(row.last_report_end)
                    if row is not None and row.last_report_end is not None
                    else None
                ),
            }
        )
    return usage_rows


def _mail_source_summary(db: Session, workspace: Workspace) -> Dict[str, Any]:
    sources = db.query(MailSource).filter(MailSource.workspace_id == workspace.id).all()
    source_ids = [source.id for source in sources]
    by_method = Counter((source.method or "UNKNOWN").upper() for source in sources)
    import_rows = (
        db.query(MailSourceImport.status, func.count(MailSourceImport.id))
        .filter(MailSourceImport.mail_source_id.in_(source_ids))
        .group_by(MailSourceImport.status)
        .all()
        if source_ids
        else []
    )
    imports_by_status = {str(status): int(count or 0) for status, count in import_rows}
    return {
        "total": len(sources),
        "enabled": sum(1 for source in sources if source.enabled),
        "disabled": sum(1 for source in sources if not source.enabled),
        "by_method": dict(sorted(by_method.items())),
        "imports": {
            "total": sum(imports_by_status.values()),
            "by_status": dict(sorted(imports_by_status.items())),
        },
    }


def _alert_summary(db: Session, domain_names: List[str]) -> Dict[str, Any]:
    if not domain_names:
        return {"total": 0, "active": 0, "resolved": 0, "by_rule": {}}
    rows = (
        db.query(
            AlertHistory.rule.label("rule"),
            AlertHistory.is_active.label("is_active"),
            func.count(AlertHistory.id).label("count"),
        )
        .filter(AlertHistory.domain.in_(domain_names))
        .group_by(AlertHistory.rule, AlertHistory.is_active)
        .all()
    )
    total = 0
    active = 0
    by_rule: Counter[str] = Counter()
    for row in rows:
        count = int(row.count or 0)
        total += count
        by_rule[str(row.rule)] += count
        if row.is_active:
            active += count
    return {
        "total": total,
        "active": active,
        "resolved": max(total - active, 0),
        "by_rule": dict(sorted(by_rule.items())),
    }


def build_workspace_usage_summary(db: Session, workspace: Workspace) -> Dict[str, Any]:
    """Return tenant-safe, read-only usage evidence for one workspace."""
    domains = _workspace_domains(db, workspace)
    domain_ids = [domain.id for domain in domains]
    domain_names = [domain.name for domain in domains]
    message_totals = _message_totals(db, domain_ids)
    total_messages = message_totals["total_messages"]
    compliant_messages = message_totals["compliant_messages"]
    report_count = (
        db.query(func.count(DMARCReport.id)).filter(DMARCReport.domain_id.in_(domain_ids)).scalar()
        if domain_ids
        else 0
    )
    forensic_count = (
        db.query(func.count(ForensicReport.id))
        .filter(ForensicReport.domain_id.in_(domain_ids))
        .scalar()
        if domain_ids
        else 0
    )
    tls_report_count = (
        db.query(func.count(TLSReport.id)).filter(TLSReport.domain_id.in_(domain_ids)).scalar()
        if domain_ids
        else 0
    )
    last_report_end = (
        db.query(func.max(DMARCReport.end_date))
        .filter(DMARCReport.domain_id.in_(domain_ids))
        .scalar()
        if domain_ids
        else None
    )
    return {
        "generated_at": _timestamp(),
        "workspace": {
            "id": workspace.id,
            "slug": workspace.slug,
            "name": workspace.name,
        },
        "summary": {
            "domain_count": len(domains),
            "active_domain_count": sum(1 for domain in domains if domain.active),
            "verified_domain_count": sum(1 for domain in domains if domain.verified),
            "aggregate_report_count": int(report_count or 0),
            "forensic_report_count": int(forensic_count or 0),
            "tls_report_count": int(tls_report_count or 0),
            "total_messages": total_messages,
            "compliant_messages": compliant_messages,
            "failed_messages": message_totals["failed_messages"],
            "compliance_rate": _rate(compliant_messages, total_messages),
            "distinct_source_count": message_totals["distinct_source_count"],
            "last_report_end_at": _unix_timestamp(last_report_end),
        },
        "mail_sources": _mail_source_summary(db, workspace),
        "alerts": _alert_summary(db, domain_names),
        "domains": _domain_usage_rows(db, domains),
    }
