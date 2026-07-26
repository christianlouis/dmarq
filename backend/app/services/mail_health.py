"""Focused, deterministic interpretation of aggregate DMARC evidence.

This service deliberately only reads ingestion-time projections.  It does not
perform DNS, PTR, reputation, or delivery lookups while an operator is opening
the dashboard.  Aggregate DMARC reports describe authentication observations,
not proof that an individual message was delivered or bounced.
"""

from __future__ import annotations

import json
from collections import defaultdict
from typing import Any, Dict, Iterable

from sqlalchemy.orm import Session

from app.models.domain import Domain
from app.models.report import DomainSourceDailyProjection
from app.models.workspace import Workspace
from app.services.sender_intelligence import identify_sender


def _as_dict(value: object) -> Dict[str, Any]:
    if not value:
        return {}
    if isinstance(value, dict):
        return value
    try:
        parsed = json.loads(str(value))
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _count(value: object) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _hostname(evidence: Dict[str, Any]) -> str | None:
    ptr = evidence.get("ptr")
    if not isinstance(ptr, dict):
        return None
    for key in ("hostname", "ptr", "name"):
        value = str(ptr.get(key) or "").strip().rstrip(".")
        if value:
            return value
    return None


def _merge_source_rows(rows: Iterable[tuple[Domain, DomainSourceDailyProjection]]) -> Dict[str, Any]:
    sources: Dict[tuple[str, str], Dict[str, Any]] = {}
    for domain, row in rows:
        key = (domain.name, str(row.source_ip))
        source = sources.setdefault(
            key,
            {
                "domain": domain.name,
                "source_ip": str(row.source_ip),
                "dmarc_pass_count": 0,
                "dmarc_fail_count": 0,
                "disposition_counts": defaultdict(int),
                "source_evidence": {},
                "captured_at": "",
            },
        )
        source["dmarc_pass_count"] += _count(row.dmarc_pass_count)
        source["dmarc_fail_count"] += _count(row.dmarc_fail_count)
        for disposition, count in _as_dict(row.disposition_counts).items():
            source["disposition_counts"][str(disposition).lower()] += _count(count)
        evidence = _as_dict(row.source_evidence)
        captured_at = str(evidence.get("captured_at") or "")
        if evidence and captured_at >= source["captured_at"]:
            source["source_evidence"] = evidence
            source["captured_at"] = captured_at
    return sources


def _assessment(
    *,
    outcome: str,
    title: str,
    summary: str,
    next_step: str,
    href: str,
    confidence: str,
    reasons: list[str],
    evidence_scope: str,
    domain: str | None = None,
) -> Dict[str, Any]:
    return {
        "outcome": outcome,
        "title": title,
        "summary": summary,
        "next_step": next_step,
        "href": href,
        "confidence": confidence,
        "reasons": reasons,
        "evidence_scope": evidence_scope,
        "domain": domain,
        "claim_type": "aggregate_dmarc_authentication",
    }


def build_workspace_mail_health_assessment(
    db: Session,
    *,
    workspace: Workspace,
    start_ts: int,
    end_ts: int,
) -> Dict[str, Any]:
    """Return one plain-language assessment from indexed aggregate-report facts."""
    rows = (
        db.query(Domain, DomainSourceDailyProjection)
        .join(DomainSourceDailyProjection, DomainSourceDailyProjection.domain_id == Domain.id)
        .filter(
            Domain.workspace_id == workspace.id,
            DomainSourceDailyProjection.observed_at >= start_ts,
            DomainSourceDailyProjection.observed_at < end_ts,
        )
        .all()
    )
    sources = _merge_source_rows(rows)
    if not sources:
        return _assessment(
            outcome="insufficient_evidence",
            title="Waiting for DMARC report data",
            summary=(
                "DMARQ has no aggregate authentication evidence in this period yet. "
                "Connect a report mailbox or upload a report to begin monitoring."
            ),
            next_step="Connect a report mailbox",
            href="/mail-sources",
            confidence="Not enough evidence",
            reasons=["No projected sender facts were found for the selected date window."],
            evidence_scope="No report-backed authentication evidence is available yet.",
        )

    known_failing: list[Dict[str, Any]] = []
    unknown_protected: list[Dict[str, Any]] = []
    unknown_failing: list[Dict[str, Any]] = []
    for source in sources.values():
        failed = _count(source["dmarc_fail_count"])
        if not failed:
            continue
        hostname = _hostname(source["source_evidence"])
        identity = identify_sender(
            source["source_ip"],
            source,
            hostname=hostname,
            domain=source["domain"],
            ptr_lookup_pending=bool(source["source_evidence"].get("ptr_retry_pending")),
        )
        source["identity"] = identity
        if identity.get("status") == "known":
            known_failing.append(source)
            continue
        dispositions = source["disposition_counts"]
        if _count(dispositions.get("reject")) + _count(dispositions.get("quarantine")) >= failed:
            unknown_protected.append(source)
        else:
            unknown_failing.append(source)

    if known_failing:
        source = max(known_failing, key=lambda item: _count(item["dmarc_fail_count"]))
        identity = source["identity"]
        passed = _count(source["dmarc_pass_count"])
        changed = " It also passed authentication in this selected period." if passed else ""
        return _assessment(
            outcome="action_required",
            title=f"Check {identity.get('name') or 'a known sender'} authentication",
            summary=(
                f"{identity.get('name') or 'A known sender'} has {source['dmarc_fail_count']} "
                f"reported authentication failure(s) for {source['domain']}.{changed} "
                "This may affect mail you intend to send, so verify its sender setup before tightening policy."
            ),
            next_step="Review the sender evidence and authentication result",
            href=f"/domains/{source['domain']}#sending-sources",
            confidence="High" if passed else "Medium",
            reasons=[
                "The sender matches a known provider or owned infrastructure profile.",
                f"Aggregate reports recorded {_count(source['dmarc_fail_count'])} DMARC authentication failure(s).",
            ],
            evidence_scope=(
                "Aggregate DMARC reports show receiver authentication evaluation. They do not prove "
                "whether an individual message was delivered, bounced, or read."
            ),
            domain=source["domain"],
        )

    if unknown_protected and not unknown_failing:
        source = max(unknown_protected, key=lambda item: _count(item["dmarc_fail_count"]))
        return _assessment(
            outcome="no_action_likely_unauthorized_use",
            title="Likely unauthorized use is being blocked",
            summary=(
                f"An unrecognized source had {_count(source['dmarc_fail_count'])} authentication failure(s) "
                f"for {source['domain']}, and receivers applied your protective DMARC policy. "
                "Known sender failures were not found in this period."
            ),
            next_step="Review source evidence",
            href=f"/domains/{source['domain']}#sending-sources",
            confidence="Medium",
            reasons=[
                "The source could not be matched to a known provider or owned infrastructure.",
                "Receiver reports recorded quarantine or reject for all observed failures.",
            ],
            evidence_scope=(
                "This is an interpretation of aggregate receiver reports, not proof of a specific delivery outcome."
            ),
            domain=source["domain"],
        )

    if unknown_failing:
        source = max(unknown_failing, key=lambda item: _count(item["dmarc_fail_count"]))
        return _assessment(
            outcome="investigation_required",
            title="Identify an unrecognized sending source",
            summary=(
                f"An unrecognized source had {_count(source['dmarc_fail_count'])} authentication failure(s) "
                f"for {source['domain']}. DMARQ cannot yet determine whether it belongs to your mail estate."
            ),
            next_step="Confirm whether this sender is an approved service before changing DNS",
            href=f"/domains/{source['domain']}#sending-sources",
            confidence="Medium",
            reasons=[
                "The source did not match a known sender profile.",
                "The reported policy outcome does not consistently show protective handling.",
            ],
            evidence_scope=(
                "Aggregate DMARC reports describe authentication and receiver policy evaluation, not end-user delivery."
            ),
            domain=source["domain"],
        )

    return _assessment(
        outcome="healthy",
        title="Known senders are authenticating successfully",
        summary=(
            "DMARQ found report-backed sender activity without current authentication failures in this period."
        ),
        next_step="Keep report intake running",
        href="/reports",
        confidence="High",
        reasons=["Projected sender facts contain successful DMARC authentication and no failure counts."],
        evidence_scope=(
            "Aggregate DMARC reports show authentication results, not a guarantee of inbox placement or delivery."
        ),
    )
