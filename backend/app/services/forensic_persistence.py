import json
from typing import Any, Dict, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.domain import Domain
from app.models.report import ForensicReport
from app.services.forensic_redaction import ForensicRedactionPolicy, redact_forensic_value
from app.services.workspaces import assign_default_workspace_to_unscoped_rows
from app.utils.domain_validator import DomainValidationError, validate_domain


def forensic_report_exists(
    db: Session,
    report_id: str,
    *,
    workspace_id: Optional[int] = None,
) -> bool:
    """Return True when a forensic report ID is already persisted."""
    if not str(report_id or "").strip():
        return False
    query = db.query(ForensicReport.id).filter(ForensicReport.report_id == report_id)
    if workspace_id is not None:
        query = query.join(Domain, ForensicReport.domain_id == Domain.id).filter(
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


def save_forensic_report(
    db: Session,
    report: Dict[str, Any],
    *,
    workspace_id: Optional[int] = None,
) -> tuple[ForensicReport, bool]:
    """Persist a parsed forensic report.

    Returns ``(row, created)``. The caller owns the transaction and should
    commit after related work has completed.
    """
    report_id = str(report.get("report_id") or "").strip()
    if not report_id:
        raise ValueError("Forensic report_id is required")

    existing_query = db.query(ForensicReport).filter(ForensicReport.report_id == report_id)
    if workspace_id is not None:
        existing_query = existing_query.join(Domain, ForensicReport.domain_id == Domain.id).filter(
            Domain.workspace_id == workspace_id
        )
    existing = existing_query.first()
    if existing is not None:
        return existing, False

    domain = _domain_for_report(db, report.get("reported_domain"), workspace_id=workspace_id)
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
        existing_query = db.query(ForensicReport).filter(ForensicReport.report_id == report_id)
        if workspace_id is not None:
            existing_query = existing_query.join(
                Domain, ForensicReport.domain_id == Domain.id
            ).filter(Domain.workspace_id == workspace_id)
        existing = existing_query.first()
        if existing is not None:
            return existing, False
        raise
    return row, True


_REDACTABLE_RESPONSE_FIELDS = {
    "source_email",
    "user_agent",
    "authentication_results",
    "original_mail_from",
    "original_from",
    "original_to",
    "original_subject",
    "feedback_headers",
}


def forensic_report_to_dict(
    row: ForensicReport,
    *,
    redaction_policy: Optional[ForensicRedactionPolicy] = None,
) -> Dict[str, Any]:
    """Convert a forensic report row to an API-safe dictionary."""
    feedback_headers = {}
    if row.feedback_headers:
        try:
            feedback_headers = json.loads(row.feedback_headers)
        except (json.JSONDecodeError, TypeError):
            feedback_headers = {}

    result = {
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
    if redaction_policy is not None:
        for field in _REDACTABLE_RESPONSE_FIELDS:
            result[field] = redact_forensic_value(result.get(field), redaction_policy)
    return result
