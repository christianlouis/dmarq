"""Read-only diagnostics for persisted DMARC report identity collisions."""

import json
from collections import defaultdict
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session, joinedload, selectinload

from app.models.domain import Domain
from app.models.report import DMARCReport


def _canonical_json(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    try:
        return json.dumps(json.loads(value), sort_keys=True, separators=(",", ":"))
    except (TypeError, json.JSONDecodeError):
        return value


def _report_signature(report: DMARCReport) -> tuple[Any, ...]:
    """Capture all persisted report semantics, excluding row identity/timestamps."""
    report_fields = (
        report.org_name,
        report.begin_date,
        report.end_date,
        report.source_email,
        report.extra_contact_info,
        report.generator,
        _canonical_json(report.report_errors),
        report.policy,
        report.subdomain_policy,
        report.non_subdomain_policy,
        report.adkim,
        report.aspf,
        report.percentage,
        report.failure_options,
        report.testing,
        report.discovery_method,
        report.schema_version,
        report.report_variant,
        report.xml_namespace,
        _canonical_json(report.report_extensions),
        report.raw_data,
    )
    record_signatures = sorted(
        (
            record.source_ip,
            record.count,
            record.disposition,
            record.dkim,
            record.spf,
            record.header_from,
            record.envelope_from,
            record.envelope_to,
            _canonical_json(record.dkim_auth_details),
            _canonical_json(record.spf_auth_details),
            _canonical_json(record.policy_override_reasons),
            _canonical_json(record.record_extensions),
            _canonical_json(record.source_evidence),
        )
        for record in report.records
    )
    return report_fields + (tuple(record_signatures),)


def duplicate_report_inventory(
    db: Session, *, workspace_id: Optional[int] = None
) -> List[Dict[str, Any]]:
    """Return deterministic duplicate identities without changing persisted data.

    Reports are grouped by the intended identity (domain, report ID).  A
    group is ``exact`` when every persisted semantic field and record matches;
    otherwise it is ``conflict``.  The helper deliberately
    reports every row and never selects, deletes, or rewrites a canonical row.
    """
    query = db.query(DMARCReport).options(
        joinedload(DMARCReport.domain), selectinload(DMARCReport.records)
    )
    if workspace_id is not None:
        query = query.join(Domain, DMARCReport.domain_id == Domain.id).filter(
            Domain.workspace_id == workspace_id
        )

    grouped: Dict[tuple[str, str], List[DMARCReport]] = defaultdict(list)
    for report in query.order_by(DMARCReport.id.asc()).all():
        domain_name = report.domain.name if report.domain else "unknown"
        grouped[(domain_name, report.report_id)].append(report)

    inventory: List[Dict[str, Any]] = []
    for (domain_name, report_id), reports in sorted(grouped.items()):
        if len(reports) < 2:
            continue
        rows = []
        signatures = set()
        for report in reports:
            total_count = sum(int(record.count or 0) for record in report.records)
            passed_count = sum(
                int(record.count or 0)
                for record in report.records
                if record.dkim == "pass" or record.spf == "pass"
            )
            signatures.add(_report_signature(report))
            rows.append(
                {
                    "id": report.id,
                    "org_name": report.org_name or "",
                    "begin_timestamp": int(report.begin_date or 0),
                    "end_timestamp": int(report.end_date or 0),
                    "total_count": total_count,
                    "passed_count": passed_count,
                }
            )
        inventory.append(
            {
                "domain": domain_name,
                "report_id": report_id,
                "classification": "exact" if len(signatures) == 1 else "conflict",
                "row_count": len(rows),
                "rows": rows,
            }
        )
    return inventory
