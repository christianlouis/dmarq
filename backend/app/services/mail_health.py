"""Focused, deterministic interpretation of aggregate DMARC evidence.

This service deliberately only reads ingestion-time projections.  It does not
perform DNS, PTR, reputation, or delivery lookups while an operator is opening
the dashboard.  Aggregate DMARC reports describe authentication observations,
not proof that an individual message was delivered or bounced.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from datetime import datetime, timezone
from functools import partial
from ipaddress import ip_address
from typing import Any, Callable, Dict

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.models.domain import Domain
from app.models.mail_source import MailSource
from app.models.report import DomainSourceDailyProjection
from app.models.workspace import Workspace
from app.services.mail_signals import (
    MAIL_SIGNAL_SCHEMA_VERSION,
    build_dmarc_source_signals,
    build_intake_window_signal,
)
from app.services.sender_classifications import latest_sender_classifications
from app.services.sender_intelligence import identify_sender

ASSESSMENT_SCHEMA_VERSION = "dmarq.mail_health_assessment.v2"
ASSESSMENT_ALGORITHM_VERSION = "deterministic-2026-07"


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


def _confidence_band(confidence: str) -> str:
    normalized = str(confidence or "").strip().lower()
    if normalized in {"high", "medium", "low"}:
        return normalized
    return "low"


def _impact_band(value: str) -> str:
    return {
        "likely_affected": "likely",
        "likely_not_affected": "unlikely",
        "possible": "possible",
    }.get(value, "unknown")


def _urgency_band(value: str) -> str:
    return {
        "urgent": "now",
        "now": "now",
        "timely": "soon",
        "soon": "soon",
        "monitor": "watch",
        "watch": "watch",
        "none": "none",
    }.get(value, "watch")


def _canonical_source_ip(value: object) -> str:
    raw_value = str(value or "").strip()
    try:
        return str(ip_address(raw_value))
    except ValueError:
        return raw_value


def _source_signals(source: Dict[str, Any]) -> list[Dict[str, Any]]:
    return build_dmarc_source_signals(
        source,
        workspace_id=source.get("workspace_id"),
        domain=str(source.get("domain") or ""),
        evidence_refs=source.get("evidence_refs") or (),
    )


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
    intended_mail_impact: str = "unknown",
    urgency: str = "monitor",
    known_facts: list[str] | None = None,
    inferences: list[str] | None = None,
    unknowns: list[str] | None = None,
    verification_condition: str = "Review fresh report evidence before changing mail or DNS settings.",
    no_action_reason: str | None = None,
    watch_condition: str | None = None,
    supporting_signals: list[Dict[str, Any]] | None = None,
    conclusion_claim_level: str = "inferred",
    delivery_certainty: str = "inferred_only",
    derived_facts: list[str] | None = None,
    operator_reported_facts: list[str] | None = None,
    workspace_id: int | None = None,
    window_start: int | None = None,
    window_end: int | None = None,
    freshness: str = "current",
    freshness_at: int | None = None,
    conclusion_key: str | None = None,
) -> Dict[str, Any]:
    derived_fact_set = set(derived_facts or [])
    operator_fact_set = set(operator_reported_facts or [])
    observed_claims = [
        {"claim_level": "observed", "statement": statement}
        for statement in known_facts or []
        if statement not in derived_fact_set and statement not in operator_fact_set
    ]
    derived_claims = [
        {"claim_level": "derived", "statement": statement}
        for statement in known_facts or []
        if statement in derived_fact_set
    ]
    inferred_claims = [
        {"claim_level": "inferred", "statement": statement} for statement in inferences or []
    ]
    operator_claims = [
        {"claim_level": "operator_reported", "statement": statement}
        for statement in operator_reported_facts or []
    ]
    unknown_claims = [
        {"claim_level": "unknown", "statement": statement} for statement in unknowns or []
    ]
    resolved_conclusion_key = conclusion_key or f"mail_health.{outcome}"
    evidence_digest = hashlib.sha256(
        json.dumps(
            supporting_signals or [],
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
    ).hexdigest()
    assessment_scope = json.dumps(
        {
            "workspace_id": workspace_id,
            "domain": domain,
            "outcome": outcome,
            "conclusion_key": resolved_conclusion_key,
            "window_start": window_start,
            "window_end": window_end,
            "signal_ids": sorted(
                str(signal.get("signal_id"))
                for signal in supporting_signals or []
                if signal.get("signal_id")
            ),
            "evidence_digest": evidence_digest,
            "algorithm_version": ASSESSMENT_ALGORITHM_VERSION,
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    assessment_id = hashlib.sha256(assessment_scope.encode("utf-8")).hexdigest()
    return {
        "schema_version": ASSESSMENT_SCHEMA_VERSION,
        "assessment_id": assessment_id,
        "workspace_id": workspace_id,
        "outcome": outcome,
        "title": title,
        "summary": summary,
        "next_step": next_step,
        "href": href,
        "confidence": confidence,
        "confidence_band": _confidence_band(confidence),
        "confidence_reasons": reasons,
        "reasons": reasons,
        "evidence_scope": evidence_scope,
        "domain": domain,
        "intended_mail_impact": intended_mail_impact,
        "intended_mail_impact_band": _impact_band(intended_mail_impact),
        "urgency": urgency,
        "urgency_band": _urgency_band(urgency),
        "assessment_version": "v1",
        "assessment_algorithm_version": ASSESSMENT_ALGORITHM_VERSION,
        "evidence_window": {"start": window_start, "end": window_end},
        "freshness": freshness,
        "freshness_at": (
            datetime.fromtimestamp(freshness_at, tz=timezone.utc).isoformat()
            if freshness_at
            else None
        ),
        "conclusion": {
            "key": resolved_conclusion_key,
            "parameters": {"domain": domain} if domain else {},
        },
        "known_facts": known_facts or [],
        "inferences": inferences or [],
        "unknowns": unknowns or [],
        "next_action": {
            "label": next_step,
            "href": href,
            "action_type": "open_evidence",
            "explanation": summary,
            "prerequisites": [],
            "safety_boundary": "Review report-backed evidence before changing DNS or sender settings.",
        },
        "verification_condition": verification_condition,
        "no_action_reason": no_action_reason,
        "watch_condition": watch_condition,
        "claim_type": "aggregate_dmarc_authentication",
        "claim_level": conclusion_claim_level,
        "delivery_certainty": delivery_certainty,
        "signal_schema_version": MAIL_SIGNAL_SCHEMA_VERSION,
        "supporting_signals": supporting_signals or [],
        "claims": (
            observed_claims + derived_claims + operator_claims + inferred_claims + unknown_claims
        ),
    }


def _aggregated_projection_sources(
    db: Session,
    *,
    workspace_id: int,
    start_ts: int,
    end_ts: int,
) -> Dict[tuple[str, str], Dict[str, Any]]:
    """Aggregate counters in SQL and load only compact evidence fields per day."""
    projection = DomainSourceDailyProjection
    grouped_rows = (
        db.query(
            Domain.name.label("domain_name"),
            Domain.workspace_id.label("workspace_id"),
            projection.source_ip.label("source_ip"),
            func.sum(projection.spf_pass_count).label("spf_pass_count"),
            func.sum(projection.spf_fail_count).label("spf_fail_count"),
            func.sum(projection.dkim_pass_count).label("dkim_pass_count"),
            func.sum(projection.dkim_fail_count).label("dkim_fail_count"),
            func.sum(projection.dmarc_pass_count).label("dmarc_pass_count"),
            func.sum(projection.dmarc_fail_count).label("dmarc_fail_count"),
            func.min(func.coalesce(projection.first_seen, projection.observed_at)).label(
                "window_start"
            ),
            func.max(func.coalesce(projection.last_seen, projection.observed_at)).label(
                "window_end"
            ),
        )
        .join(projection, projection.domain_id == Domain.id)
        .filter(
            Domain.workspace_id == workspace_id,
            projection.observed_at >= start_ts,
            projection.observed_at < end_ts,
        )
        .group_by(Domain.name, Domain.workspace_id, projection.source_ip)
        .all()
    )
    sources: Dict[tuple[str, str], Dict[str, Any]] = {}
    for row in grouped_rows:
        normalized_ip = _canonical_source_ip(row.source_ip)
        key = (row.domain_name, normalized_ip)
        source = sources.setdefault(
            key,
            {
                "domain": row.domain_name,
                "source_ip": normalized_ip,
                "spf_pass_count": 0,
                "spf_fail_count": 0,
                "dkim_pass_count": 0,
                "dkim_fail_count": 0,
                "dmarc_pass_count": 0,
                "dmarc_fail_count": 0,
                "disposition_counts": defaultdict(int),
                "source_evidence": {},
                "captured_at": "",
                "workspace_id": row.workspace_id,
                "window_start": None,
                "window_end": None,
                "evidence_refs": [],
                "report_generators": [],
                "header_from_domains": [],
                "envelope_from_domains": [],
                "spf_domains": [],
                "dkim_domains": [],
                "dkim_selectors": [],
            },
        )
        for field in (
            "spf_pass_count",
            "spf_fail_count",
            "dkim_pass_count",
            "dkim_fail_count",
            "dmarc_pass_count",
            "dmarc_fail_count",
        ):
            source[field] += _count(getattr(row, field))
        source["window_start"] = (
            _count(row.window_start)
            if source["window_start"] is None
            else min(source["window_start"], _count(row.window_start))
        )
        source["window_end"] = max(
            _count(source["window_end"]),
            _count(row.window_end),
        )

    detail_rows = (
        db.query(
            Domain.name.label("domain_name"),
            projection.source_ip.label("source_ip"),
            projection.id.label("projection_id"),
            projection.disposition_counts.label("disposition_counts"),
            projection.metadata_json.label("metadata_json"),
            projection.source_evidence.label("source_evidence"),
        )
        .join(projection, projection.domain_id == Domain.id)
        .filter(
            Domain.workspace_id == workspace_id,
            projection.observed_at >= start_ts,
            projection.observed_at < end_ts,
        )
        .all()
    )
    for row in detail_rows:
        key = (row.domain_name, _canonical_source_ip(row.source_ip))
        source = sources.get(key)
        if source is None:
            continue
        source["evidence_refs"].append(f"domain_source_daily_projection:{row.projection_id}")
        metadata = _as_dict(row.metadata_json)
        for field in (
            "report_generators",
            "header_from_domains",
            "envelope_from_domains",
            "spf_domains",
            "dkim_domains",
            "dkim_selectors",
        ):
            for value in metadata.get(field) or []:
                normalized = str(value).strip()
                if normalized and normalized not in source[field]:
                    source[field].append(normalized)
        for disposition, count in _as_dict(row.disposition_counts).items():
            source["disposition_counts"][str(disposition).lower()] += _count(count)
        evidence = _as_dict(row.source_evidence)
        captured_at = str(evidence.get("captured_at") or "")
        if evidence and captured_at >= source["captured_at"]:
            source["source_evidence"] = evidence
            source["captured_at"] = captured_at
    return sources


def _previous_pass_counts(
    db: Session,
    *,
    workspace_id: int,
    start_ts: int,
    end_ts: int,
) -> Dict[tuple[str, str], Dict[str, int]]:
    """Read only the previous-window pass counter used for regression detection."""
    projection = DomainSourceDailyProjection
    rows = (
        db.query(
            Domain.name.label("domain_name"),
            projection.source_ip.label("source_ip"),
            func.sum(projection.dmarc_pass_count).label("previous_pass_count"),
        )
        .join(projection, projection.domain_id == Domain.id)
        .filter(
            Domain.workspace_id == workspace_id,
            projection.observed_at >= start_ts,
            projection.observed_at < end_ts,
        )
        .group_by(Domain.name, projection.source_ip)
        .all()
    )
    previous: Dict[tuple[str, str], Dict[str, int]] = {}
    for row in rows:
        key = (row.domain_name, _canonical_source_ip(row.source_ip))
        target = previous.setdefault(key, {"dmarc_pass_count": 0})
        target["dmarc_pass_count"] += _count(row.previous_pass_count)
    return previous


def _workspace_mail_context(workspace: Workspace) -> Dict[str, Any]:
    """Parse the persisted interview context and ignore malformed legacy values."""
    try:
        value = json.loads(workspace.guidance_mail_context or "{}")
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return value if isinstance(value, dict) else {}


def _classify_failing_sources(
    sources: Dict[tuple[str, str], Dict[str, Any]],
    *,
    previous_sources: Dict[tuple[str, str], Dict[str, Any]],
    classifications: Dict[tuple[str, str], Dict[str, Any]],
) -> tuple[
    list[Dict[str, Any]],
    list[Dict[str, Any]],
    list[Dict[str, Any]],
    list[Dict[str, Any]],
    list[Dict[str, Any]],
]:
    """Group failing sources using stored evidence and auditable operator decisions."""
    known: list[Dict[str, Any]] = []
    forwarding: list[Dict[str, Any]] = []
    unauthorized: list[Dict[str, Any]] = []
    protected: list[Dict[str, Any]] = []
    unknown: list[Dict[str, Any]] = []
    for source in sources.values():
        failed = _count(source["dmarc_fail_count"])
        if not failed:
            continue
        operator_decision = classifications.get((source["domain"], source["source_ip"]))
        operator_classification = (
            str(operator_decision.get("classification") or "") if operator_decision else ""
        )
        source["operator_classification"] = operator_classification
        source["operator_classification_evidence"] = operator_decision
        previous = previous_sources.get((source["domain"], source["source_ip"]), {})
        source["previous_pass_count"] = _count(previous.get("dmarc_pass_count"))
        if operator_classification == "expected_forwarding":
            forwarding.append(source)
            continue
        if operator_classification == "unauthorized":
            unauthorized.append(source)
            continue
        identity = identify_sender(
            source["source_ip"],
            source,
            hostname=_hostname(source["source_evidence"]),
            domain=source["domain"],
            ptr_lookup_pending=bool(source["source_evidence"].get("ptr_retry_pending")),
        )
        source["identity"] = identity
        if operator_classification == "legitimate" or (
            identity.get("status") == "known"
            and operator_classification not in {"unauthorized", "stale"}
        ):
            known.append(source)
            continue
        dispositions = source["disposition_counts"]
        protected_count = _count(dispositions.get("reject")) + _count(
            dispositions.get("quarantine")
        )
        (protected if protected_count >= failed else unknown).append(source)
    return known, forwarding, unauthorized, protected, unknown


def _no_source_assessment(
    *,
    workspace: Workspace,
    start_ts: int,
    end_ts: int,
    low_volume_wait: bool,
) -> Dict[str, Any]:
    """Explain an empty window without turning report absence into an outage."""
    no_evidence_fact = "No projected sender facts were found for the selected date window."
    summary = "DMARQ has no aggregate authentication evidence in this period yet. "
    summary += "Connect a report mailbox or upload a report to begin monitoring."
    if low_volume_wait:
        summary = (
            "Report intake is connected and this domain is expected to send little mail. "
            "No urgent failure is implied; wait for the next receiver report."
        )
    return _assessment(
        workspace_id=workspace.id,
        window_start=start_ts,
        window_end=end_ts,
        outcome="monitor" if low_volume_wait else "insufficient_evidence",
        title="Waiting for DMARC report data",
        summary=summary,
        next_step="Keep report intake running" if low_volume_wait else "Connect a report mailbox",
        href="/mail-sources",
        confidence="Low",
        reasons=[no_evidence_fact],
        evidence_scope="No report-backed authentication evidence is available yet.",
        intended_mail_impact="unknown",
        urgency="monitor",
        known_facts=[no_evidence_fact],
        derived_facts=[no_evidence_fact],
        inferences=["DMARQ cannot assess mail authentication health yet."],
        unknowns=["How receivers evaluate mail from this domain."],
        verification_condition="Ingest an aggregate DMARC report for this domain.",
        watch_condition="DMARQ will reassess when a report is imported.",
        supporting_signals=[
            build_intake_window_signal(
                workspace_id=workspace.id,
                window_start=start_ts,
                window_end=end_ts,
                has_evidence=False,
            )
        ],
        conclusion_claim_level="derived",
        delivery_certainty="not_applicable",
    )


def _priority_unauthorized_source(
    confirmed: list[Dict[str, Any]],
    protected: list[Dict[str, Any]],
    unknown: list[Dict[str, Any]],
) -> Dict[str, Any] | None:
    candidates = confirmed + protected
    if not candidates or unknown:
        return None
    return max(
        candidates,
        key=lambda item: (
            item.get("operator_classification") == "unauthorized",
            _count(item["dmarc_fail_count"]),
        ),
    )


def _contextual_assessment(
    *,
    workspace_id: int,
    start_ts: int,
    end_ts: int,
    freshness: str,
    freshness_at: int | None,
    **values: Any,
) -> Dict[str, Any]:
    """Apply shared scope and freshness rules to one deterministic conclusion."""
    selected_signals = values.get("supporting_signals") or []
    selected_evidence_at = max(
        (_count(signal.get("window_end")) for signal in selected_signals),
        default=0,
    )
    if selected_evidence_at:
        freshness_at = selected_evidence_at
        freshness = "stale" if end_ts - selected_evidence_at > 7 * 86_400 else "current"
    if freshness == "stale":
        values["confidence"] = {"High": "Medium", "Medium": "Low"}.get(
            str(values.get("confidence") or ""), values.get("confidence")
        )
    values.setdefault("freshness", freshness)
    values.setdefault("freshness_at", freshness_at)
    return _assessment(
        workspace_id=workspace_id,
        window_start=start_ts,
        window_end=end_ts,
        **values,
    )


def _unauthorized_use_assessment(
    assessment: Callable[..., Dict[str, Any]],
    source: Dict[str, Any],
) -> Dict[str, Any]:
    """Distinguish confirmed unauthorized use from likely blocked spoofing."""
    failed = _count(source["dmarc_fail_count"])
    dispositions = source["disposition_counts"]
    protected_count = _count(dispositions.get("reject")) + _count(dispositions.get("quarantine"))
    explicit = source.get("operator_classification") == "unauthorized"
    operator_fact = "An operator classified this exact domain and source IP as unauthorized."
    if explicit and protected_count < failed:
        return assessment(
            outcome="action_required",
            title="Protect the domain from confirmed unauthorized use",
            summary=(
                f"An operator classified {source['source_ip']} as unauthorized for "
                f"{source['domain']}, but receivers did not report protective handling for all "
                f"{failed} authentication failure(s). Review policy readiness before tightening DMARC."
            ),
            next_step="Review domain protection and known-sender readiness",
            href=f"/domains/{source['domain']}#remediation-queue",
            confidence="High",
            reasons=[
                "The exact source has an auditable unauthorized classification.",
                "Receiver reports did not consistently record quarantine or reject handling.",
            ],
            evidence_scope="The ownership decision is operator-reported; policy handling comes from aggregate receiver reports.",
            domain=source["domain"],
            intended_mail_impact="likely_not_affected",
            urgency="timely",
            known_facts=[
                operator_fact,
                f"Aggregate reports recorded {failed} authentication failure(s).",
            ],
            operator_reported_facts=[operator_fact],
            inferences=[
                "Current policy may not consistently protect against this unauthorized use."
            ],
            unknowns=["The final delivery outcome of individual messages."],
            verification_condition=(
                "Known senders remain healthy and fresh receiver reports record protective handling "
                "for the unauthorized source."
            ),
            supporting_signals=_source_signals(source),
            conclusion_key="mail_health.confirmed_unauthorized_use_unprotected",
        )

    unmatched_fact = (
        operator_fact
        if explicit
        else "The source did not match a known provider or owned-infrastructure profile."
    )
    return assessment(
        outcome="no_action_likely_unauthorized_use",
        title=(
            "Confirmed unauthorized use is being blocked"
            if explicit
            else "Likely unauthorized use is being blocked"
        ),
        summary=(
            f"The unauthorized source had {failed} authentication failure(s) for "
            f"{source['domain']}, and receivers applied your protective DMARC policy. "
            "Known sender failures were not found in this period."
            if explicit
            else f"An unrecognized source had {failed} authentication failure(s) for "
            f"{source['domain']}, and receivers applied your protective DMARC policy. "
            "Known sender failures were not found in this period."
        ),
        next_step="Review source evidence",
        href=f"/domains/{source['domain']}#sending-sources",
        confidence="High" if explicit else "Medium",
        reasons=[
            (
                "The exact source has an auditable unauthorized classification."
                if explicit
                else "The source could not be matched to known sending infrastructure."
            ),
            "Receiver reports recorded quarantine or reject for all observed failures.",
        ],
        evidence_scope="This is an interpretation of aggregate receiver reports, not proof of a specific delivery outcome.",
        domain=source["domain"],
        intended_mail_impact="likely_not_affected",
        urgency="none",
        known_facts=[
            unmatched_fact,
            "Receiver reports recorded protective quarantine or reject handling for all observed failures.",
        ],
        derived_facts=[] if explicit else [unmatched_fact],
        operator_reported_facts=[operator_fact] if explicit else [],
        inferences=["This does not currently appear to be a fault in your intended sending setup."],
        unknowns=["The final outcome of individual messages."],
        verification_condition="Known senders remain healthy and policy remains protective.",
        no_action_reason="Receivers reported protective handling and no known sender failures were found.",
        watch_condition="DMARQ will surface a new action if the pattern or known-sender health changes.",
        supporting_signals=_source_signals(source),
        conclusion_key="mail_health.confirmed_unauthorized_use_blocked" if explicit else None,
    )


def _bounce_context_source(
    sources: Dict[tuple[str, str], Dict[str, Any]], mail_context: Dict[str, Any]
) -> Dict[str, Any] | None:
    """Match a reported bounce only to the domains selected in the interview."""
    if not mail_context.get("bounce_available"):
        return None
    selected_domains = {
        str(domain).strip().lower().rstrip(".") for domain in mail_context.get("domains") or []
    }
    candidates = [
        source
        for source in sources.values()
        if _count(source["dmarc_pass_count"])
        and (not selected_domains or source["domain"] in selected_domains)
    ]
    return max(candidates, key=lambda item: _count(item["dmarc_pass_count"]), default=None)


def build_workspace_mail_health_assessment(
    db: Session,
    *,
    workspace: Workspace,
    start_ts: int,
    end_ts: int,
) -> Dict[str, Any]:
    """Return one plain-language assessment from indexed aggregate-report facts."""

    sources = _aggregated_projection_sources(
        db,
        workspace_id=workspace.id,
        start_ts=start_ts,
        end_ts=end_ts,
    )
    newest_evidence_at = max(
        (_count(source.get("window_end")) for source in sources.values()), default=0
    )
    freshness = (
        "stale" if newest_evidence_at and end_ts - newest_evidence_at > 7 * 86_400 else "current"
    )
    for source in sources.values():
        source_evidence_at = _count(source.get("window_end"))
        source["freshness"] = (
            "stale"
            if source_evidence_at and end_ts - source_evidence_at > 7 * 86_400
            else "current"
        )
    window_seconds = max(1, end_ts - start_ts)
    previous_sources = _previous_pass_counts(
        db,
        workspace_id=workspace.id,
        start_ts=start_ts - window_seconds,
        end_ts=start_ts,
    )
    classifications = latest_sender_classifications(db, workspace=workspace)
    mail_context = _workspace_mail_context(workspace)
    enabled_source_count = (
        db.query(MailSource)
        .filter(MailSource.workspace_id == workspace.id, MailSource.enabled.is_(True))
        .count()
    )
    if not sources:
        return _no_source_assessment(
            workspace=workspace,
            start_ts=start_ts,
            end_ts=end_ts,
            low_volume_wait=bool(enabled_source_count and mail_context.get("low_volume")),
        )
    assessment = partial(
        _contextual_assessment,
        workspace_id=workspace.id,
        start_ts=start_ts,
        end_ts=end_ts,
        freshness=freshness,
        freshness_at=newest_evidence_at or None,
    )

    (
        known_failing,
        forwarding_failing,
        confirmed_unauthorized,
        unknown_protected,
        unknown_failing,
    ) = _classify_failing_sources(
        sources,
        previous_sources=previous_sources,
        classifications=classifications,
    )

    if known_failing:
        source = max(
            known_failing,
            key=lambda item: (
                bool(item.get("previous_pass_count")),
                _count(item["dmarc_fail_count"]),
            ),
        )
        identity = source["identity"]
        passed = _count(source["dmarc_pass_count"])
        changed = " It also passed authentication in this selected period." if passed else ""
        operator_legitimate = source.get("operator_classification") == "legitimate"
        sender_match_fact = (
            "An operator classified this exact domain and source IP as legitimate."
            if operator_legitimate
            else f"{identity.get('name') or 'A known sender'} matched a known sender profile."
        )
        previous_passes = _count(source.get("previous_pass_count"))
        regression_fact = (
            f"The same source passed DMARC for {previous_passes} message(s) in the previous window."
            if previous_passes
            else None
        )
        return assessment(
            outcome="action_required",
            title=f"Check {identity.get('name') or 'a known sender'} authentication",
            summary=(
                f"{identity.get('name') or 'A known sender'} has {source['dmarc_fail_count']} "
                f"reported authentication failure(s) for {source['domain']}.{changed} "
                "This may affect mail you intend to send, so verify its sender setup before tightening policy."
            ),
            next_step="Review the sender evidence and authentication result",
            href=f"/domains/{source['domain']}#sending-sources",
            confidence="High" if previous_passes or (passed and operator_legitimate) else "Medium",
            reasons=[
                (
                    "An operator classified this exact domain and source IP as legitimate."
                    if operator_legitimate
                    else "The sender matches a known provider or owned infrastructure profile."
                ),
                f"Aggregate reports recorded {_count(source['dmarc_fail_count'])} DMARC authentication failure(s).",
            ],
            evidence_scope=(
                "Aggregate DMARC reports show receiver authentication evaluation. They do not prove "
                "whether an individual message was delivered, bounced, or read."
            ),
            domain=source["domain"],
            intended_mail_impact="likely_affected",
            urgency="timely",
            known_facts=[
                sender_match_fact,
                *([regression_fact] if regression_fact else []),
                f"Aggregate reports recorded {_count(source['dmarc_fail_count'])} authentication failure(s).",
            ],
            derived_facts=[] if operator_legitimate else [sender_match_fact],
            operator_reported_facts=[sender_match_fact] if operator_legitimate else [],
            inferences=["This sender may affect mail you intend to send."],
            unknowns=["Whether each affected message was delivered, bounced, or read."],
            verification_condition="Fresh reports show the sender authenticating without DMARC failures.",
            supporting_signals=_source_signals(source),
        )

    unauthorized_source = _priority_unauthorized_source(
        confirmed_unauthorized, unknown_protected, unknown_failing
    )
    if unauthorized_source:
        source = unauthorized_source
        return _unauthorized_use_assessment(assessment, source)

    if unknown_failing:
        source = max(unknown_failing, key=lambda item: _count(item["dmarc_fail_count"]))
        unmatched_fact = "The source did not match a known sender profile."
        return assessment(
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
            intended_mail_impact="unknown",
            urgency="timely",
            known_facts=[
                unmatched_fact,
                f"Aggregate reports recorded {_count(source['dmarc_fail_count'])} authentication failure(s).",
            ],
            derived_facts=[unmatched_fact],
            inferences=["DMARQ cannot yet tell whether this source belongs to your mail estate."],
            unknowns=["Whether the source is an approved sender and its final delivery outcome."],
            verification_condition="Classify the source or collect fresh report evidence that identifies its owner.",
            supporting_signals=_source_signals(source),
        )

    if forwarding_failing:
        source = max(forwarding_failing, key=lambda item: _count(item["dmarc_fail_count"]))
        return assessment(
            outcome="monitor",
            title="Review an expected forwarding path",
            summary=(
                f"An operator marked {source['source_ip']} as expected forwarding for "
                f"{source['domain']}. Forwarding can break SPF while DKIM still preserves alignment; "
                "do not add the intermediary IP to SPF without sender-side evidence."
            ),
            next_step="Review forwarding and DKIM evidence",
            href=f"/domains/{source['domain']}#sending-sources",
            confidence="Medium",
            reasons=[
                "An operator classified this exact source as expected forwarding.",
                "Aggregate DMARC evidence alone cannot identify the forwarding configuration.",
            ],
            evidence_scope="The assessment uses stored report and operator evidence only.",
            domain=source["domain"],
            intended_mail_impact="possible",
            urgency="monitor",
            known_facts=[
                "The source has an auditable expected-forwarding classification.",
                f"Aggregate reports recorded {_count(source['dmarc_fail_count'])} authentication failure(s).",
            ],
            derived_facts=["The source has an auditable expected-forwarding classification."],
            inferences=[
                "SPF failure may be caused by forwarding rather than an unauthorized sender."
            ],
            unknowns=["Whether aligned DKIM survives the forwarding path for each message stream."],
            verification_condition="Fresh reports or forwarding-system evidence isolate the aligned DKIM path.",
            watch_condition="Escalate if aligned DKIM also regresses or intended mail is reported missing.",
            supporting_signals=_source_signals(source),
            conclusion_key="mail_health.expected_forwarding",
        )

    observed_passes = sum(_count(source["dmarc_pass_count"]) for source in sources.values())
    if not observed_passes:
        source = max(
            sources.values(),
            key=lambda item: _count(item["dmarc_pass_count"]) + _count(item["dmarc_fail_count"]),
        )
        return assessment(
            outcome="insufficient_evidence",
            title="Waiting for usable DMARC authentication evidence",
            summary=(
                "DMARQ found sender records in this period, but they do not yet contain "
                "successful or failed DMARC authentication results. Keep report intake running "
                "until receivers provide usable authentication evidence."
            ),
            next_step="Review report intake",
            href="/reports",
            confidence="Not enough evidence",
            reasons=[
                "Projected sender facts contain no successful or failed DMARC authentication counts."
            ],
            evidence_scope="Sender activity alone is not enough to assess mail authentication health.",
            intended_mail_impact="unknown",
            urgency="monitor",
            known_facts=[
                "Projected sender records contain no successful or failed DMARC authentication counts."
            ],
            inferences=["Sender activity by itself is not enough to assess mail health."],
            unknowns=["Whether receivers accept or reject mail from these sources."],
            verification_condition="A later report includes successful or failed DMARC authentication results.",
            watch_condition="DMARQ will reassess when usable authentication evidence arrives.",
            supporting_signals=_source_signals(source),
            conclusion_claim_level="derived",
            delivery_certainty="not_applicable",
        )

    bounce_source = _bounce_context_source(sources, mail_context)
    if bounce_source:
        source = bounce_source
        return assessment(
            outcome="insufficient_evidence",
            title="DMARC passes do not explain the reported bounce",
            summary=(
                "Receivers reported successful DMARC authentication, but the operator also reported "
                "a bounce. Use the SMTP response, DSN, or sending-provider event to diagnose delivery."
            ),
            next_step="Review the bounce or provider delivery event",
            href=f"/domains/{source['domain']}#sending-sources",
            confidence="High",
            reasons=[
                "Aggregate reports show DMARC authentication passes.",
                "The workspace interview records that bounce evidence is available.",
            ],
            evidence_scope="Authentication success is not proof of delivery or inbox placement.",
            domain=source["domain"],
            intended_mail_impact="possible",
            urgency="timely",
            known_facts=[
                "Aggregate reports contain successful DMARC authentication.",
                "The operator reported that bounce evidence is available.",
            ],
            derived_facts=["The operator reported that bounce evidence is available."],
            inferences=["The reported delivery problem requires evidence outside aggregate DMARC."],
            unknowns=[
                "The SMTP status and rejecting system are not present in aggregate DMARC data."
            ],
            verification_condition="Identify the SMTP status, receiver, timestamp, and affected sender.",
            supporting_signals=_source_signals(source),
            conclusion_key="mail_health.dmarc_pass_bounce_mismatch",
        )
    source = max(sources.values(), key=lambda item: _count(item["dmarc_pass_count"]))
    return assessment(
        outcome="healthy",
        title="Known senders are authenticating successfully",
        summary=(
            "DMARQ found report-backed sender activity without current authentication failures in this period."
        ),
        next_step="Keep report intake running",
        href="/reports",
        confidence="High",
        reasons=[
            "Projected sender facts contain successful DMARC authentication and no failure counts."
        ],
        evidence_scope=(
            "Aggregate DMARC reports show authentication results, not a guarantee of inbox placement or delivery."
        ),
        intended_mail_impact="likely_not_affected",
        urgency="none",
        known_facts=[
            "Projected sender facts contain successful DMARC authentication and no reported failures."
        ],
        inferences=["Known sender activity appears healthy in the selected evidence window."],
        unknowns=["Inbox placement and individual delivery outcomes."],
        verification_condition="Continue receiving aggregate reports without a new authentication failure pattern.",
        no_action_reason="No current authentication failures were found in the selected evidence window.",
        watch_condition="DMARQ will notify when a meaningful sender or authentication change appears.",
        supporting_signals=_source_signals(source),
    )
