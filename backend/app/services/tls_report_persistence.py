"""Persistence and summarization helpers for SMTP TLS reports."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.models.domain import Domain
from app.models.report import TLSReport, TLSReportFailure
from app.services.workspaces import assign_default_workspace_to_unscoped_rows
from app.utils.domain_validator import DomainValidationError, validate_domain

TLS_REPORT_PRIVACY_CONTROLS = {
    "retention": (
        "TLS reports store aggregate session counts, reporting organization metadata, "
        "policy domains, and grouped TLS failure details."
    ),
    "stored_fields": [
        "report id",
        "reporting organization",
        "contact info",
        "policy domain",
        "policy type",
        "report date range",
        "successful and failed session counts",
        "grouped result type and failed-session count",
        "sending MTA IP when supplied by the reporter",
        "receiving MX host/HELO/IP when supplied by the reporter",
        "failure reason code and additional grouped diagnostic text",
    ],
    "not_stored": [
        "message bodies",
        "message subjects",
        "sender or recipient addresses",
        "recipient local-parts",
        "raw uploaded attachments",
        "mailbox credentials or source message identifiers",
    ],
}


def tls_report_exists(
    db: Session,
    report_id: str,
    policy_domain: str,
    *,
    workspace_id: Optional[int] = None,
) -> bool:
    """Return True when a TLS report policy entry already exists."""
    normalized_report_id = str(report_id or "").strip()
    normalized_domain = str(policy_domain or "").strip().lower().strip(".")
    if not normalized_report_id or not normalized_domain:
        return False
    query = db.query(TLSReport.id).filter(
        TLSReport.report_id == normalized_report_id,
        TLSReport.policy_domain == normalized_domain,
    )
    if workspace_id is not None:
        query = query.join(Domain, TLSReport.domain_id == Domain.id).filter(
            Domain.workspace_id == workspace_id
        )
    return query.first() is not None


def _domain_for_report(
    db: Session,
    domain_name: Optional[str],
    *,
    workspace_id: Optional[int] = None,
) -> Optional[Domain]:
    if not domain_name:
        return None
    normalized = domain_name.lower().strip(".")
    is_valid, _, error_code = validate_domain(normalized, check_dns=False)
    if not is_valid and error_code != DomainValidationError.DNS_RESOLUTION_FAILED:
        return None

    if workspace_id is None:
        workspace = assign_default_workspace_to_unscoped_rows(db, commit=False)
        workspace_id = workspace.id
    domain = (
        db.query(Domain)
        .filter(Domain.name == normalized, Domain.workspace_id == workspace_id)
        .first()
    )
    if domain is None:
        domain = Domain(name=normalized, workspace_id=workspace_id)
        db.add(domain)
        db.flush()
    return domain


def _save_policy_report(
    db: Session,
    parsed_report: Dict[str, Any],
    policy: Dict[str, Any],
    *,
    workspace_id: Optional[int] = None,
) -> tuple[Optional[TLSReport], bool]:
    report_id = str(parsed_report.get("report_id") or "").strip()
    policy_domain = str(policy.get("policy_domain") or "").strip().lower().strip(".")
    if not report_id or not policy_domain:
        return None, False

    existing_query = db.query(TLSReport).filter(
        TLSReport.report_id == report_id,
        TLSReport.policy_domain == policy_domain,
    )
    if workspace_id is not None:
        existing_query = existing_query.join(Domain, TLSReport.domain_id == Domain.id).filter(
            Domain.workspace_id == workspace_id
        )
    existing = existing_query.first()
    if existing is not None:
        return existing, False

    domain = _domain_for_report(db, policy_domain, workspace_id=workspace_id)
    if domain is None:
        return None, False
    row = TLSReport(
        domain_id=domain.id,
        report_id=report_id,
        org_name=parsed_report.get("org_name"),
        contact_info=parsed_report.get("contact_info"),
        policy_domain=policy_domain,
        policy_type=policy.get("policy_type"),
        begin_date=parsed_report.get("begin_date"),
        end_date=parsed_report.get("end_date"),
        total_successful_sessions=policy.get("total_successful_sessions") or 0,
        total_failure_sessions=policy.get("total_failure_sessions") or 0,
        raw_policy=json.dumps(policy.get("policy") or {}, sort_keys=True),
    )
    for failure in policy.get("failures") or []:
        row.failures.append(
            TLSReportFailure(
                result_type=failure.get("result_type") or "unknown",
                failed_session_count=failure.get("failed_session_count") or 0,
                sending_mta_ip=failure.get("sending_mta_ip") or None,
                receiving_mx_hostname=failure.get("receiving_mx_hostname") or None,
                receiving_mx_helo=failure.get("receiving_mx_helo") or None,
                receiving_ip=failure.get("receiving_ip") or None,
                failure_reason_code=failure.get("failure_reason_code") or None,
                additional_information=failure.get("additional_information") or None,
            )
        )

    db.add(row)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        existing_query = db.query(TLSReport).filter(
            TLSReport.report_id == report_id,
            TLSReport.policy_domain == policy_domain,
        )
        if workspace_id is not None:
            existing_query = existing_query.join(Domain, TLSReport.domain_id == Domain.id).filter(
                Domain.workspace_id == workspace_id
            )
        existing = existing_query.first()
        if existing is not None:
            return existing, False
        raise
    return row, True


def save_tls_report(
    db: Session,
    parsed_report: Dict[str, Any],
    *,
    workspace_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Persist parsed TLS report policy entries.

    One TLS-RPT JSON can carry multiple policy domains. Each policy is stored
    independently so partial duplicate imports can still add newly seen domains.
    The caller owns the transaction.
    """
    rows: List[TLSReport] = []
    created = 0
    skipped = 0
    for policy in parsed_report.get("policies") or []:
        row, was_created = _save_policy_report(
            db,
            parsed_report,
            policy,
            workspace_id=workspace_id,
        )
        if row is None:
            skipped += 1
            continue
        rows.append(row)
        if was_created:
            created += 1
        else:
            skipped += 1
    return {"rows": rows, "created": created, "skipped": skipped}


def tls_report_to_dict(row: TLSReport) -> Dict[str, Any]:
    """Convert a TLS report row to an API-safe dictionary."""
    return {
        "id": row.id,
        "report_id": row.report_id,
        "domain": row.domain.name if row.domain else row.policy_domain,
        "org_name": row.org_name,
        "contact_info": row.contact_info,
        "policy_domain": row.policy_domain,
        "policy_type": row.policy_type,
        "begin_date": row.begin_date.isoformat() if row.begin_date else None,
        "end_date": row.end_date.isoformat() if row.end_date else None,
        "total_successful_sessions": row.total_successful_sessions,
        "total_failure_sessions": row.total_failure_sessions,
        "processed_at": row.processed_at.isoformat() if row.processed_at else None,
        "failures": [
            {
                "result_type": failure.result_type,
                "failed_session_count": failure.failed_session_count,
                "sending_mta_ip": failure.sending_mta_ip,
                "receiving_mx_hostname": failure.receiving_mx_hostname,
                "receiving_mx_helo": failure.receiving_mx_helo,
                "receiving_ip": failure.receiving_ip,
                "failure_reason_code": failure.failure_reason_code,
                "additional_information": failure.additional_information,
            }
            for failure in row.failures
        ],
    }


def _row_day(row: TLSReport) -> str:
    basis = row.begin_date or row.end_date or row.processed_at or datetime.utcnow()
    return basis.date().isoformat()


def _report_rows(
    db: Session,
    *,
    domain: Optional[str] = None,
    days: int = 30,
    workspace_id: Optional[int] = None,
) -> Iterable[TLSReport]:
    cutoff = datetime.utcnow() - timedelta(days=days)
    query = db.query(TLSReport).options(
        selectinload(TLSReport.domain), selectinload(TLSReport.failures)
    )
    if workspace_id is not None or domain:
        query = query.outerjoin(Domain)
    if workspace_id is not None:
        query = query.filter(Domain.workspace_id == workspace_id)
    query = query.filter(
        (TLSReport.begin_date >= cutoff)
        | (TLSReport.end_date >= cutoff)
        | (TLSReport.processed_at >= cutoff)
    )
    if domain:
        normalized = domain.lower().strip(".")
        query = query.filter((Domain.name == normalized) | (TLSReport.policy_domain == normalized))
    return query.order_by(TLSReport.begin_date.desc().nullslast(), TLSReport.id.desc()).all()


def summarize_tls_reports(
    db: Session,
    *,
    domain: Optional[str] = None,
    days: int = 30,
    limit: int = 10,
    workspace_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Summarize TLS reports into trends and actionable failure groupings."""
    rows = list(_report_rows(db, domain=domain, days=days, workspace_id=workspace_id))

    totals = {
        "reports": len(rows),
        "successful_sessions": sum(row.total_successful_sessions or 0 for row in rows),
        "failed_sessions": sum(row.total_failure_sessions or 0 for row in rows),
    }
    session_total = totals["successful_sessions"] + totals["failed_sessions"]
    totals["failure_rate"] = (totals["failed_sessions"] / session_total) if session_total else 0.0

    trend_map: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {"date": "", "reports": 0, "successful_sessions": 0, "failed_sessions": 0}
    )
    domain_map: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {
            "domain": "",
            "reports": 0,
            "successful_sessions": 0,
            "failed_sessions": 0,
            "top_failure": None,
        }
    )
    failure_map: Dict[str, Dict[str, Any]] = defaultdict(
        lambda: {
            "result_type": "",
            "failed_sessions": 0,
            "reports": set(),
            "affected_domains": set(),
            "receiving_mx_hostnames": set(),
            "reason_codes": set(),
        }
    )

    for row in rows:
        day = _row_day(row)
        trend = trend_map[day]
        trend["date"] = day
        trend["reports"] += 1
        trend["successful_sessions"] += row.total_successful_sessions or 0
        trend["failed_sessions"] += row.total_failure_sessions or 0

        domain_summary = domain_map[row.policy_domain]
        domain_summary["domain"] = row.policy_domain
        domain_summary["reports"] += 1
        domain_summary["successful_sessions"] += row.total_successful_sessions or 0
        domain_summary["failed_sessions"] += row.total_failure_sessions or 0

        top_for_row = None
        for failure in row.failures:
            result_type = failure.result_type or "unknown"
            item = failure_map[result_type]
            item["result_type"] = result_type
            item["failed_sessions"] += failure.failed_session_count or 0
            item["reports"].add(row.report_id)
            item["affected_domains"].add(row.policy_domain)
            if failure.receiving_mx_hostname:
                item["receiving_mx_hostnames"].add(failure.receiving_mx_hostname)
            if failure.failure_reason_code:
                item["reason_codes"].add(failure.failure_reason_code)
            if (
                top_for_row is None
                or (failure.failed_session_count or 0) > top_for_row.failed_session_count
            ):
                top_for_row = failure
        if top_for_row is not None:
            domain_summary["top_failure"] = top_for_row.result_type

    trends = [trend_map[key] for key in sorted(trend_map)]
    affected_domains = []
    for item in domain_map.values():
        domain_sessions = item["successful_sessions"] + item["failed_sessions"]
        item["failure_rate"] = item["failed_sessions"] / domain_sessions if domain_sessions else 0.0
        affected_domains.append(item)

    top_failures = []
    for item in failure_map.values():
        top_failures.append(
            {
                "result_type": item["result_type"],
                "failed_sessions": item["failed_sessions"],
                "report_count": len(item["reports"]),
                "affected_domains": sorted(item["affected_domains"]),
                "receiving_mx_hostnames": sorted(item["receiving_mx_hostnames"])[:5],
                "reason_codes": sorted(item["reason_codes"])[:5],
            }
        )

    top_failures.sort(key=lambda item: item["failed_sessions"], reverse=True)
    affected_domains.sort(key=lambda item: item["failed_sessions"], reverse=True)

    return {
        "domain": domain,
        "days": days,
        "totals": totals,
        "trends": trends,
        "top_failures": top_failures[:limit],
        "affected_domains": affected_domains[:limit],
        "privacy": TLS_REPORT_PRIVACY_CONTROLS,
    }
