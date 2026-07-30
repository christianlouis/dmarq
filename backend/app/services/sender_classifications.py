"""Auditable operator classifications for report-backed sending sources."""

from __future__ import annotations

import hashlib
import json
from ipaddress import ip_address
from typing import Any, Dict, Optional

from sqlalchemy.orm import Session

from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceAuditLog
from app.services.workspace_audit import record_workspace_audit_log
from app.utils.domain_validator import normalize_domain_name, validate_domain

SENDER_CLASSIFICATIONS = {
    "legitimate",
    "unknown",
    "unauthorized",
    "expected_forwarding",
    "stale",
}
SENDER_CLASSIFICATION_ACTION = "mail_health.sender_classified"
SENDER_CLASSIFICATION_ENTITY = "mail_sender_classification"


def _scope_id(domain: str, source_ip: str) -> str:
    value = f"{domain}|{source_ip}"
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def normalize_sender_scope(domain: str, source_ip: str) -> tuple[str, str]:
    """Validate one exact domain/source scope without performing network I/O."""
    normalized_domain = normalize_domain_name(domain)
    if not validate_domain(normalized_domain, check_dns=False)[0]:
        raise ValueError("A valid domain is required")
    try:
        normalized_ip = str(ip_address(str(source_ip).strip()))
    except ValueError as exc:
        raise ValueError("A valid source IP address is required") from exc
    return normalized_domain, normalized_ip


def _details(row: WorkspaceAuditLog) -> Dict[str, Any]:
    try:
        value = json.loads(row.details or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _classification_projection(
    row: WorkspaceAuditLog, *, details: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Return the decision fields needed by report readers, without audit internals."""
    values = details if details is not None else _details(row)
    return {
        "domain": str(values.get("domain") or ""),
        "source_ip": str(values.get("source_ip") or ""),
        "classification": str(values.get("classification") or ""),
        "reason": str(values.get("reason") or "") or None,
        "scope": "exact_domain_source",
        "classified_at": row.created_at.isoformat() if row.created_at else None,
    }


def latest_sender_classifications(
    db: Session,
    *,
    workspace: Workspace,
    domain: Optional[str] = None,
) -> Dict[tuple[str, str], Dict[str, Any]]:
    """Return the latest decision per exact domain/IP scope."""
    query = db.query(WorkspaceAuditLog).filter(
        WorkspaceAuditLog.workspace_id == workspace.id,
        WorkspaceAuditLog.action == SENDER_CLASSIFICATION_ACTION,
        WorkspaceAuditLog.entity_type == SENDER_CLASSIFICATION_ENTITY,
    )
    if domain:
        normalized_domain = normalize_domain_name(domain)
        query = query.filter(WorkspaceAuditLog.entity_name == normalized_domain)
    rows = query.order_by(WorkspaceAuditLog.created_at.desc(), WorkspaceAuditLog.id.desc()).all()
    result: Dict[tuple[str, str], Dict[str, Any]] = {}
    for row in rows:
        details = _details(row)
        key = (str(details.get("domain") or ""), str(details.get("source_ip") or ""))
        classification = str(details.get("classification") or "")
        if not all(key) or classification not in SENDER_CLASSIFICATIONS or key in result:
            continue
        result[key] = _classification_projection(row, details=details)
    return result


def record_sender_classification(
    db: Session,
    *,
    workspace: Workspace,
    domain: str,
    source_ip: str,
    classification: str,
    reason: Optional[str],
    auth_context: Optional[Dict[str, Any]],
    request: Any = None,
) -> Dict[str, Any]:
    """Append one decision; never mutate report or prior classification evidence."""
    normalized_domain, normalized_ip = normalize_sender_scope(domain, source_ip)
    normalized_classification = str(classification or "").strip().lower()
    if normalized_classification not in SENDER_CLASSIFICATIONS:
        raise ValueError(
            "Unsupported classification. Use one of: " + ", ".join(sorted(SENDER_CLASSIFICATIONS))
        )
    normalized_reason = str(reason or "").strip()[:500] or None
    row = record_workspace_audit_log(
        db,
        workspace=workspace,
        action=SENDER_CLASSIFICATION_ACTION,
        entity_type=SENDER_CLASSIFICATION_ENTITY,
        entity_id=_scope_id(normalized_domain, normalized_ip),
        entity_name=normalized_domain,
        details={
            "domain": normalized_domain,
            "source_ip": normalized_ip,
            "classification": normalized_classification,
            "reason": normalized_reason,
            "scope": "exact_domain_source",
            "historical_report_evidence_changed": False,
        },
        auth_context=auth_context,
        request=request,
        commit=True,
    )
    return _classification_projection(row)
