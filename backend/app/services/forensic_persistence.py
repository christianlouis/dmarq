import json
from typing import Any, Dict, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.domain import Domain
from app.models.report import ForensicReport
from app.utils.domain_validator import DomainValidationError, validate_domain


def forensic_report_exists(db: Session, report_id: str) -> bool:
    """Return True when a forensic report ID is already persisted."""
    if not str(report_id or "").strip():
        return False
    return (
        db.query(ForensicReport.id).filter(ForensicReport.report_id == report_id).first()
        is not None
    )


def _domain_for_report(db: Session, domain_name: Optional[str]) -> Optional[Domain]:
    if not domain_name:
        return None
    normalized = domain_name.lower().strip(".")
    is_valid, _, error_code = validate_domain(normalized, check_dns=False)
    if not is_valid and error_code != DomainValidationError.DNS_RESOLUTION_FAILED:
        return None

    domain = db.query(Domain).filter(Domain.name == normalized).first()
    if domain is None:
        domain = Domain(name=normalized)
        db.add(domain)
        db.flush()
    return domain


def save_forensic_report(db: Session, report: Dict[str, Any]) -> tuple[ForensicReport, bool]:
    """Persist a parsed forensic report.

    Returns ``(row, created)``. The caller owns the transaction and should
    commit after related work has completed.
    """
    report_id = str(report.get("report_id") or "").strip()
    if not report_id:
        raise ValueError("Forensic report_id is required")

    existing = db.query(ForensicReport).filter(ForensicReport.report_id == report_id).first()
    if existing is not None:
        return existing, False

    domain = _domain_for_report(db, report.get("reported_domain"))
    feedback_headers = report.get("feedback_headers")
    if isinstance(feedback_headers, dict):
        feedback_headers = json.dumps(feedback_headers, sort_keys=True)

    row = ForensicReport(
        domain_id=domain.id if domain else None,
        report_id=report_id,
        source_email=report.get("source_email"),
        feedback_type=report.get("feedback_type"),
        user_agent=report.get("user_agent"),
        version=report.get("version"),
        reported_domain=report.get("reported_domain"),
        source_ip=report.get("source_ip"),
        auth_failure=report.get("auth_failure"),
        delivery_result=report.get("delivery_result"),
        arrival_date=report.get("arrival_date"),
        authentication_results=report.get("authentication_results"),
        original_mail_from=report.get("original_mail_from"),
        original_from=report.get("original_from"),
        original_to=report.get("original_to"),
        original_subject=report.get("original_subject"),
        original_message_id=report.get("original_message_id"),
        original_date=report.get("original_date"),
        feedback_headers=feedback_headers,
    )
    db.add(row)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        existing = db.query(ForensicReport).filter(ForensicReport.report_id == report_id).first()
        if existing is not None:
            return existing, False
        raise
    return row, True


def forensic_report_to_dict(row: ForensicReport) -> Dict[str, Any]:
    """Convert a forensic report row to an API-safe dictionary."""
    feedback_headers = {}
    if row.feedback_headers:
        try:
            feedback_headers = json.loads(row.feedback_headers)
        except (json.JSONDecodeError, TypeError):
            feedback_headers = {}

    return {
        "id": row.id,
        "report_id": row.report_id,
        "domain": row.domain.name if row.domain else row.reported_domain,
        "reported_domain": row.reported_domain,
        "source_email": row.source_email,
        "feedback_type": row.feedback_type,
        "user_agent": row.user_agent,
        "version": row.version,
        "source_ip": row.source_ip,
        "auth_failure": row.auth_failure,
        "delivery_result": row.delivery_result,
        "arrival_date": row.arrival_date.isoformat() if row.arrival_date else None,
        "authentication_results": row.authentication_results,
        "original_mail_from": row.original_mail_from,
        "original_from": row.original_from,
        "original_to": row.original_to,
        "original_subject": row.original_subject,
        "original_message_id": row.original_message_id,
        "original_date": row.original_date,
        "feedback_headers": feedback_headers,
        "processed_at": row.processed_at.isoformat() if row.processed_at else None,
    }
