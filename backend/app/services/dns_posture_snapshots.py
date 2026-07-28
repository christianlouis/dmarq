"""Materialize DNS posture outside request-time read paths.

The cache is an optimisation for resolvers. These snapshots are the operator
evidence contract: completed observations are immutable and a tiny current
pointer keeps the last accepted result available even when a later lookup is
unavailable or inconclusive.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from datetime import datetime, timedelta
from typing import Any, Dict, Iterable, Optional

from sqlalchemy.orm import Session

from app.models.dns_posture_snapshot import DomainDNSPostureCurrent, DomainDNSPostureSnapshot
from app.models.domain import Domain
from app.services.dns_resolver import DomainDNSResult


def _utcnow() -> datetime:
    return datetime.utcnow()


def _canonical_selectors(selectors: Iterable[str] | None) -> list[str]:
    return sorted(
        {str(selector).strip().lower() for selector in selectors or [] if str(selector).strip()}
    )


def selector_fingerprint(selectors: Iterable[str] | None) -> str:
    payload = json.dumps(_canonical_selectors(selectors), separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _result_payload(result: DomainDNSResult) -> Dict[str, Any]:
    return asdict(result)


def _result_fingerprint(payload: Dict[str, Any]) -> str:
    # Capture time/cache metadata must not create a new immutable observation.
    stable = {
        key: value
        for key, value in payload.items()
        if key not in {"checked_at", "cached", "pending", "fallback_attempts"}
    }
    return hashlib.sha256(
        json.dumps(stable, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()


def _has_dns_evidence(result: DomainDNSResult) -> bool:
    return any(
        (
            result.dmarc,
            result.dmarc_record,
            result.spf,
            result.spf_record,
            result.dkim,
            result.dkim_record,
            result.dkim_selectors,
            result.nameservers,
            result.dmarc_policy_domain,
        )
    )


def _acceptable_result(result: DomainDNSResult) -> bool:
    return str(result.lookup_status or "ok") in {"ok", "stale_cache"}


def _decode_result(snapshot: DomainDNSPostureSnapshot) -> Optional[DomainDNSResult]:
    try:
        data = json.loads(snapshot.result_json)
    except (TypeError, ValueError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return DomainDNSResult(
        dmarc=bool(data.get("dmarc")),
        dmarc_record=data.get("dmarc_record"),
        spf=bool(data.get("spf")),
        spf_record=data.get("spf_record"),
        dkim=bool(data.get("dkim")),
        dkim_selectors=list(data.get("dkim_selectors") or []),
        dkim_record=data.get("dkim_record"),
        selectors_checked=list(data.get("selectors_checked") or []),
        dmarc_policy_domain=data.get("dmarc_policy_domain"),
        dmarc_discovery_method=data.get("dmarc_discovery_method"),
        dmarc_tags=dict(data.get("dmarc_tags") or {}),
        dmarc_warnings=list(data.get("dmarc_warnings") or []),
        dmarc_suggestions=list(data.get("dmarc_suggestions") or []),
        nameservers=list(data.get("nameservers") or []),
        lookup_status=str(data.get("lookup_status") or "ok"),
        lookup_error=data.get("lookup_error"),
        resolver_route=data.get("resolver_route"),
        resolver_identity=data.get("resolver_identity"),
        fallback_attempts=list(data.get("fallback_attempts") or []),
    )


def request_dns_posture_refresh(
    db: Session,
    *,
    domain: Domain,
    selectors: Iterable[str] | None,
    trigger: str,
    minimum_interval_seconds: int = 60,
) -> DomainDNSPostureCurrent:
    """Coalesce work requested by ingestion, operators, or provider verification."""
    now = _utcnow()
    requested_hash = selector_fingerprint(selectors)
    current = db.query(DomainDNSPostureCurrent).filter_by(domain_id=domain.id).one_or_none()
    if current is None:
        current = DomainDNSPostureCurrent(domain_id=domain.id, workspace_id=domain.workspace_id)
        db.add(current)
    selectors_changed = current.selector_hash not in {None, requested_hash}
    stale_request = current.requested_at is None or current.requested_at <= now - timedelta(
        seconds=max(1, minimum_interval_seconds)
    )
    if (
        selectors_changed
        or stale_request
        or trigger in {"operator_refresh", "provider_verification"}
    ):
        current.requested_at = now
        current.next_trigger = trigger
    current.selector_hash = requested_hash
    return current


def capture_dns_posture_snapshot(
    db: Session,
    *,
    domain: Domain,
    result: DomainDNSResult,
    selectors: Iterable[str] | None,
    trigger: str,
    provenance: Optional[Dict[str, Any]] = None,
    absence_confirmations_required: int = 2,
) -> DomainDNSPostureSnapshot:
    """Persist one immutable result and atomically advance only safe pointers."""
    now = _utcnow()
    selector_hash = selector_fingerprint(selectors)
    payload = _result_payload(result)
    fingerprint = _result_fingerprint(payload)
    current = db.query(DomainDNSPostureCurrent).filter_by(domain_id=domain.id).one_or_none()
    if current is None:
        current = DomainDNSPostureCurrent(domain_id=domain.id, workspace_id=domain.workspace_id)
        db.add(current)
        db.flush()

    previous = None
    if current.accepted_snapshot_id:
        previous = db.get(DomainDNSPostureSnapshot, current.accepted_snapshot_id)
    previous_payload: Dict[str, Any] = {}
    if previous:
        try:
            previous_payload = json.loads(previous.result_json)
        except (TypeError, ValueError, json.JSONDecodeError):
            previous_payload = {}

    lookup_ok = _acceptable_result(result)
    has_evidence = _has_dns_evidence(result)
    if lookup_ok and has_evidence:
        accepted = True
        current.absence_observations = 0
    elif lookup_ok and not has_evidence:
        current.absence_observations = int(current.absence_observations or 0) + 1
        accepted = current.accepted_snapshot_id is None or (
            current.absence_observations >= max(2, absence_confirmations_required)
        )
    else:
        accepted = False
        current.absence_observations = 0

    delta = {
        "kind": "initial_observation" if previous is None else "dns_evidence_refresh",
        "accepted": accepted,
        "previous_snapshot_id": previous.id if previous else None,
        "changed": previous is None or previous.result_fingerprint != fingerprint,
        "preserved_last_known_good": bool(previous and not accepted),
        "reason": (
            "Accepted DNS evidence."
            if accepted
            else "Kept the last accepted DNS evidence because this lookup was unavailable or needs confirmation."
        ),
    }
    snapshot = DomainDNSPostureSnapshot(
        domain_id=domain.id,
        workspace_id=domain.workspace_id,
        trigger=trigger,
        selector_hash=selector_hash,
        result_fingerprint=fingerprint,
        result_json=json.dumps(payload, sort_keys=True, default=str),
        provenance_json=json.dumps(provenance or {}, sort_keys=True, default=str),
        delta_json=json.dumps(delta, sort_keys=True),
        lookup_status=str(result.lookup_status or "unknown"),
        accepted=accepted,
        captured_at=now,
    )
    db.add(snapshot)
    db.flush()
    current.latest_snapshot_id = snapshot.id
    current.completed_at = now
    current.requested_at = None
    current.next_trigger = None
    current.selector_hash = selector_hash
    current.last_error = None if lookup_ok else str(result.lookup_error or "DNS lookup failed")
    if accepted:
        current.accepted_snapshot_id = snapshot.id
    return snapshot


def accepted_dns_posture_result(
    db: Session,
    *,
    domain_name: str,
) -> tuple[Optional[DomainDNSResult], Optional[datetime], Optional[Dict[str, Any]]]:
    """Return persisted last-known-good evidence for a normal page read."""
    domain = db.query(Domain).filter(Domain.name == domain_name).one_or_none()
    if domain is None:
        return None, None, None
    current = db.query(DomainDNSPostureCurrent).filter_by(domain_id=domain.id).one_or_none()
    if current is None or current.accepted_snapshot_id is None:
        return None, None, None
    snapshot = db.get(DomainDNSPostureSnapshot, current.accepted_snapshot_id)
    if snapshot is None:
        return None, None, None
    result = _decode_result(snapshot)
    if result is None:
        return None, None, None
    provenance = {
        "snapshot_id": snapshot.id,
        "captured_at": snapshot.captured_at.isoformat(),
        "trigger": snapshot.trigger,
        "accepted": snapshot.accepted,
        "last_error": current.last_error,
    }
    return result, snapshot.captured_at, provenance
