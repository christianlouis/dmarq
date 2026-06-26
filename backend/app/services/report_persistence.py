import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session, selectinload

from app.core.config import get_settings
from app.models.domain import Domain
from app.models.report import DMARCReport, ReportRecord
from app.services.demo_data import seed_demo_report_store
from app.services.report_store import ReportStore
from app.services.workspaces import assign_default_workspace_to_unscoped_rows


def _parse_timestamp(value: Any) -> int:
    """Return a Unix timestamp from an int-like or ISO date value."""
    if value in (None, ""):
        return 0
    if isinstance(value, (int, float)):
        return int(value)
    try:
        return int(value)
    except (TypeError, ValueError):
        pass
    try:
        return int(datetime.fromisoformat(str(value)).timestamp())
    except (TypeError, ValueError):
        return 0


def _iso_from_timestamp(value: int) -> str:
    if not value:
        return ""
    return datetime.fromtimestamp(value).isoformat()


def _loads_json_list(value: Optional[str]) -> Optional[List[Dict[str, Any]]]:
    if not value:
        return None
    try:
        decoded = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return None
    return decoded if isinstance(decoded, list) else None


def _loads_json_dict(value: Optional[str]) -> Optional[Dict[str, Any]]:
    if not value:
        return None
    try:
        decoded = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return None
    return decoded if isinstance(decoded, dict) else None


def _json_or_none(value: Any) -> Optional[str]:
    if value in (None, "", [], {}):
        return None
    return json.dumps(value, sort_keys=True)


def _policy_parts(report: Dict[str, Any]) -> Dict[str, Any]:
    policy = report.get("policy") or {}
    if isinstance(policy, str):
        return {"p": policy, "sp": "", "pct": "100"}
    if not isinstance(policy, dict):
        return {"p": "none", "sp": "", "pct": "100"}
    return {
        "p": policy.get("p", "none"),
        "sp": policy.get("sp", ""),
        "pct": str(policy.get("pct", "100")),
        "np": policy.get("np"),
        "fo": policy.get("fo"),
        "adkim": policy.get("adkim") or report.get("adkim"),
        "aspf": policy.get("aspf") or report.get("aspf"),
        "testing": policy.get("testing"),
        "discovery_method": policy.get("discovery_method"),
    }


def report_exists(
    db: Session,
    domain_name: str,
    report_id: str,
    *,
    workspace_id: Optional[int] = None,
) -> bool:
    """Return True when the domain/report ID pair is already persisted."""
    if not report_id:
        return False
    query = (
        db.query(DMARCReport.id)
        .join(Domain, DMARCReport.domain_id == Domain.id)
        .filter(Domain.name == domain_name, DMARCReport.report_id == report_id)
    )
    if workspace_id is not None:
        query = query.filter(Domain.workspace_id == workspace_id)
    return query.first() is not None


def save_parsed_report(db: Session, report: Dict[str, Any]) -> tuple[DMARCReport, bool]:
    """Persist a parsed DMARC report and its records.

    Returns ``(row, created)``. The caller owns the transaction and should
    commit after all related work has completed.
    """
    domain_name = report.get("domain") or "unknown"
    report_id = report.get("report_id") or ""
    policy = _policy_parts(report)
    workspace = assign_default_workspace_to_unscoped_rows(db, commit=False)

    domain = (
        db.query(Domain)
        .filter(Domain.name == domain_name, Domain.workspace_id == workspace.id)
        .first()
    )
    if domain is None:
        domain = Domain(name=domain_name, dmarc_policy=policy["p"], workspace_id=workspace.id)
        db.add(domain)
        db.flush()
    elif policy.get("p"):
        domain.dmarc_policy = policy["p"]

    existing = (
        db.query(DMARCReport)
        .filter(DMARCReport.domain_id == domain.id, DMARCReport.report_id == report_id)
        .first()
    )
    if existing is not None:
        return existing, False

    begin_ts = _parse_timestamp(report.get("begin_timestamp") or report.get("begin_date"))
    end_ts = _parse_timestamp(report.get("end_timestamp") or report.get("end_date"))
    pct = _parse_timestamp(policy.get("pct")) or 100

    db_report = DMARCReport(
        domain_id=domain.id,
        report_id=report_id,
        org_name=report.get("org_name") or "",
        begin_date=begin_ts,
        end_date=end_ts,
        source_email=report.get("email") or report.get("source_email"),
        extra_contact_info=report.get("extra_contact_info") or None,
        generator=report.get("generator") or None,
        report_errors=_json_or_none(report.get("errors")),
        policy=policy["p"],
        subdomain_policy=policy.get("sp") or None,
        non_subdomain_policy=policy.get("np") or None,
        adkim=policy.get("adkim") or None,
        aspf=policy.get("aspf") or None,
        percentage=pct,
        failure_options=policy.get("fo") or None,
        testing=policy.get("testing") or None,
        discovery_method=policy.get("discovery_method") or None,
        schema_version=report.get("schema_version") or None,
        report_variant=report.get("variant") or None,
        xml_namespace=report.get("xml_namespace") or None,
        report_extensions=_json_or_none(report.get("extensions")),
    )
    db.add(db_report)
    db.flush()

    for record in report.get("records", []):
        db.add(
            ReportRecord(
                report_id=db_report.id,
                source_ip=record.get("source_ip") or "unknown",
                count=int(record.get("count") or 0),
                disposition=record.get("disposition") or "none",
                dkim=record.get("dkim_result") or record.get("dkim") or "unknown",
                spf=record.get("spf_result") or record.get("spf") or "unknown",
                header_from=record.get("header_from"),
                envelope_from=record.get("envelope_from"),
                envelope_to=record.get("envelope_to"),
                dkim_auth_details=(
                    json.dumps(record.get("dkim")) if isinstance(record.get("dkim"), list) else None
                ),
                spf_auth_details=(
                    json.dumps(record.get("spf")) if isinstance(record.get("spf"), list) else None
                ),
                policy_override_reasons=_json_or_none(record.get("policy_override_reasons")),
                record_extensions=_json_or_none(record.get("extensions")),
            )
        )

    return db_report, True


def persisted_report_to_dict(report: DMARCReport) -> Dict[str, Any]:
    """Convert persisted report rows into the parsed-report shape used by the UI."""
    records: List[Dict[str, Any]] = []
    total_count = 0
    passed_count = 0

    for record in report.records:
        count = int(record.count or 0)
        dkim_result = record.dkim or "unknown"
        spf_result = record.spf or "unknown"
        total_count += count
        if dkim_result == "pass" or spf_result == "pass":
            passed_count += count

        records.append(
            {
                "source_ip": record.source_ip,
                "count": count,
                "disposition": record.disposition or "none",
                "dkim_result": dkim_result,
                "spf_result": spf_result,
                "header_from": record.header_from or "",
                "envelope_from": record.envelope_from or "",
                "envelope_to": record.envelope_to or "",
                "dkim": _loads_json_list(record.dkim_auth_details) or [],
                "spf": _loads_json_list(record.spf_auth_details) or [],
                "policy_override_reasons": (_loads_json_list(record.policy_override_reasons) or []),
                "extensions": _loads_json_dict(record.record_extensions) or {},
            }
        )

    failed_count = total_count - passed_count
    pass_rate = round(passed_count / total_count * 100, 1) if total_count > 0 else 0.0
    return {
        "domain": report.domain.name if report.domain else "unknown",
        "report_id": report.report_id,
        "org_name": report.org_name,
        "email": report.source_email or "",
        "extra_contact_info": report.extra_contact_info or "",
        "generator": report.generator or "",
        "errors": _loads_json_list(report.report_errors) or [],
        "variant": report.report_variant or "",
        "schema_version": report.schema_version or "",
        "xml_namespace": report.xml_namespace or "",
        "extensions": _loads_json_dict(report.report_extensions) or {},
        "begin_date": _iso_from_timestamp(report.begin_date),
        "end_date": _iso_from_timestamp(report.end_date),
        "begin_timestamp": report.begin_date,
        "end_timestamp": report.end_date,
        "policy": {
            "p": report.policy or "none",
            "sp": report.subdomain_policy or "",
            "np": report.non_subdomain_policy or "",
            "pct": str(report.percentage or 100),
            "fo": report.failure_options or "",
            "adkim": report.adkim or "",
            "aspf": report.aspf or "",
            "testing": report.testing or "",
            "discovery_method": report.discovery_method or "",
        },
        "records": records,
        "summary": {
            "total_count": total_count,
            "passed_count": passed_count,
            "failed_count": failed_count,
            "pass_rate": pass_rate,
        },
    }


def hydrate_report_store_from_db(
    db: Session,
    store: Optional[ReportStore] = None,
    *,
    workspace_id: Optional[int] = None,
) -> int:
    """Load persisted reports into ReportStore when the database has report rows."""
    if get_settings().DEMO_MODE:
        return seed_demo_report_store(store)

    count_query = db.query(DMARCReport.id)
    if workspace_id is not None:
        count_query = count_query.join(Domain, DMARCReport.domain_id == Domain.id).filter(
            Domain.workspace_id == workspace_id
        )
    report_count = count_query.count()

    store = store or ReportStore.get_instance()
    if workspace_id is not None:
        store.clear()
    if report_count == 0:
        return 0

    query = db.query(DMARCReport).options(
        selectinload(DMARCReport.domain),
        selectinload(DMARCReport.records),
    )
    if workspace_id is not None:
        query = query.join(Domain, DMARCReport.domain_id == Domain.id).filter(
            Domain.workspace_id == workspace_id
        )
    else:
        store.clear()
    reports = query.order_by(DMARCReport.end_date.desc()).all()
    for report in reports:
        store.add_report(persisted_report_to_dict(report))
    return len(reports)


def delete_persisted_report(
    db: Session,
    domain_name: str,
    report_id: str,
    *,
    workspace_id: Optional[int] = None,
) -> bool:
    """Delete a persisted report by domain/report ID."""
    query = (
        db.query(DMARCReport)
        .join(Domain, DMARCReport.domain_id == Domain.id)
        .filter(Domain.name == domain_name, DMARCReport.report_id == report_id)
    )
    if workspace_id is not None:
        query = query.filter(Domain.workspace_id == workspace_id)
    report = query.first()
    if report is None:
        return False
    db.delete(report)
    return True


def delete_persisted_domain(db: Session, domain_name: str) -> bool:
    """Delete a domain row and cascaded report data."""
    domain = db.query(Domain).filter(Domain.name == domain_name).first()
    if domain is None:
        return False
    db.delete(domain)
    return True
