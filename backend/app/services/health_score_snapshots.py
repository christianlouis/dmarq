"""Persist and export domain health score snapshots."""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import date, datetime
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy.orm import Session

from app.models.health_score_snapshot import HealthScoreSnapshot
from app.services.health_score import health_grade


def _as_int(value: Any) -> int:
    try:
        return int(round(float(value or 0)))
    except (TypeError, ValueError):
        return 0


def _top_action_rows(actions: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows = []
    for action in list(actions or [])[:5]:
        rows.append(
            {
                "type": str(action.get("type") or ""),
                "severity": str(action.get("severity") or ""),
                "title": str(action.get("title") or ""),
                "detail": str(action.get("detail") or ""),
                "next_step": str(action.get("next_step") or ""),
                "score_impact": _as_int(action.get("score_impact")),
                "evidence": list(action.get("evidence") or [])[:5],
            }
        )
    return rows


def _snapshot_actions(snapshot: HealthScoreSnapshot) -> List[Dict[str, Any]]:
    if not snapshot.top_actions:
        return []
    try:
        parsed = json.loads(snapshot.top_actions)
    except (TypeError, json.JSONDecodeError):
        return []
    if not isinstance(parsed, list):
        return []
    return [item for item in parsed if isinstance(item, dict)]


def _snapshot_evidence(snapshot: HealthScoreSnapshot) -> Dict[str, Any]:
    if not snapshot.evidence_summary:
        return {}
    try:
        parsed = json.loads(snapshot.evidence_summary)
    except (TypeError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _legacy_path_to_100(snapshot: HealthScoreSnapshot) -> Dict[str, Any]:
    """Explain a non-perfect snapshot created before path-to-100 existed.

    Older persisted assessments contain the factor scores but not the
    presentation explanation. Never let that produce the contradictory "96"
    plus "nothing remains" result in the UI.
    """
    remaining_points = max(0, 100 - _as_int(snapshot.score))
    if not remaining_points:
        return {
            "score": _as_int(snapshot.score),
            "remaining_points": 0,
            "items": [],
            "summary": (
                "Core mail health is at 100/100. Optional hardening and DMARC "
                "protection are shown separately."
            ),
        }

    factors = {
        "dmarc_compliance": _as_int(snapshot.compliance_rate),
        "dns_posture": _as_int(snapshot.dns_posture_score),
        "report_confidence": _as_int(snapshot.report_confidence_score),
        "source_reputation": _as_int(snapshot.source_reputation_score),
    }
    weights = {
        "dmarc_compliance": 0.50,
        "dns_posture": 0.30,
        "report_confidence": 0.10,
        "source_reputation": 0.10,
    }
    labels = {
        "dmarc_compliance": "Improve observed DMARC compliance",
        "dns_posture": "Review saved DNS authentication evidence",
        "report_confidence": "Collect a more representative report window",
        "source_reputation": "Review saved sender-reputation evidence",
    }
    details = {
        "dmarc_compliance": "Recent aggregate reports still contain DMARC failures.",
        "dns_posture": "The saved DMARC, SPF, or DKIM evidence is not fully healthy.",
        "report_confidence": "The current score is bounded by the amount of available report evidence.",
        "source_reputation": "The saved sender evidence includes unresolved reputation uncertainty.",
    }
    items = []
    for factor, weight in weights.items():
        deduction = round(max(0, 100 - factors[factor]) * weight, 1)
        if deduction <= 0:
            continue
        items.append(
            {
                "id": f"legacy_{factor}",
                "factor": factor,
                "title": labels[factor],
                "kind": "investigation_required",
                "expected_score_delta": deduction,
                "detail": details[factor],
                "next_step": "Open the saved evidence before making a DNS or sender change.",
                "verification": "A refreshed persisted assessment confirms the updated evidence.",
                "evidence": [],
            }
        )
    if not items:
        items.append(
            {
                "id": "legacy_assessment_gap",
                "factor": "assessment",
                "title": "Review the saved assessment evidence",
                "kind": "investigation_required",
                "expected_score_delta": remaining_points,
                "detail": "This older assessment predates the detailed score explanation.",
                "next_step": "Refresh the stored DNS and report evidence to capture a full explanation.",
                "verification": "A new persisted assessment includes its verified path to 100.",
                "evidence": [],
            }
        )
    items.sort(key=lambda item: float(item["expected_score_delta"]), reverse=True)
    return {
        "score": _as_int(snapshot.score),
        "remaining_points": remaining_points,
        "items": items,
        "summary": "These remaining points come from saved assessment evidence. Review the listed evidence before making a change.",
    }


def _snapshot_path_to_100(
    snapshot: HealthScoreSnapshot, evidence: Dict[str, Any]
) -> Dict[str, Any]:
    path = evidence.get("path_to_100")
    if isinstance(path, dict) and path.get("items"):
        return path
    if _as_int(snapshot.score) >= 100:
        return _legacy_path_to_100(snapshot)
    return _legacy_path_to_100(snapshot)


def _factor_deltas(previous: Dict[str, Any], current: Dict[str, Any]) -> Dict[str, int]:
    return {
        key: _as_int(current.get(key)) - _as_int(previous.get(key))
        for key in sorted(set(previous) | set(current))
        if _as_int(current.get(key)) != _as_int(previous.get(key))
    }


def _snapshot_change(
    baseline: Optional[HealthScoreSnapshot],
    *,
    factors: Dict[str, Any],
    score: Any,
) -> Dict[str, Any]:
    if baseline is None:
        return {"kind": "initial_assessment", "score_delta": None, "factor_deltas": {}}
    previous = _snapshot_evidence(baseline)
    previous_factors = previous.get("factors") if isinstance(previous.get("factors"), dict) else {}
    score_delta = _as_int(score) - _as_int(baseline.score)
    factor_deltas = _factor_deltas(previous_factors, factors)
    return {
        "kind": "evidence_refresh",
        "previous_snapshot_date": baseline.snapshot_date.isoformat(),
        "previous_evidence_captured_at": baseline.updated_at.isoformat(),
        "score_delta": score_delta,
        "factor_deltas": factor_deltas,
        "reason": (
            "No scored factor changed; evidence was refreshed."
            if score_delta == 0 and not factor_deltas
            else "Score changed because the listed persisted factors changed."
        ),
    }


def upsert_health_score_snapshot(
    db: Session,
    *,
    workspace_id: int,
    domain_name: str,
    health: Dict[str, Any],
    policy: Optional[str] = None,
    compliance_rate: Any = 0,
    total_emails: Any = 0,
    failed_emails: Any = 0,
    report_count: Any = 0,
    snapshot_date: Optional[date] = None,
) -> HealthScoreSnapshot:
    """Create or update one daily health score snapshot."""
    captured_date = snapshot_date or date.today()
    factors = health.get("factors") or {}
    actions = _top_action_rows(health.get("actions") or [])
    existing = (
        db.query(HealthScoreSnapshot)
        .filter(
            HealthScoreSnapshot.workspace_id == workspace_id,
            HealthScoreSnapshot.domain_name == domain_name,
            HealthScoreSnapshot.snapshot_date == captured_date,
        )
        .one_or_none()
    )
    baseline = existing
    if baseline is None:
        baseline = (
            db.query(HealthScoreSnapshot)
            .filter(
                HealthScoreSnapshot.workspace_id == workspace_id,
                HealthScoreSnapshot.domain_name == domain_name,
                HealthScoreSnapshot.snapshot_date < captured_date,
            )
            .order_by(
                HealthScoreSnapshot.snapshot_date.desc(), HealthScoreSnapshot.updated_at.desc()
            )
            .first()
        )
    change = _snapshot_change(
        baseline,
        factors=factors,
        score=health.get("score"),
    )
    snapshot = existing or HealthScoreSnapshot(
        workspace_id=workspace_id,
        domain_name=domain_name,
        snapshot_date=captured_date,
    )
    snapshot.score = _as_int(health.get("score"))
    snapshot.grade = str(health.get("grade") or "F")
    snapshot.status = str(health.get("status") or "critical")
    snapshot.policy = policy
    snapshot.compliance_rate = _as_int(compliance_rate)
    snapshot.total_emails = _as_int(total_emails)
    snapshot.failed_emails = _as_int(failed_emails)
    snapshot.report_count = _as_int(report_count)
    snapshot.dns_posture_score = _as_int(factors.get("dns_posture"))
    snapshot.policy_strength_score = _as_int(factors.get("policy_strength"))
    snapshot.report_confidence_score = _as_int(factors.get("report_confidence"))
    snapshot.source_reputation_score = _as_int(factors.get("source_reputation"))
    snapshot.top_actions = json.dumps(actions, sort_keys=True)
    snapshot.evidence_summary = json.dumps(
        {
            "calculation_version": health.get("assessment_version") or "1",
            "report_count": snapshot.report_count,
            "total_emails": snapshot.total_emails,
            "failed_emails": snapshot.failed_emails,
            "core_mail_health": health.get("core_mail_health") or {},
            "domain_protection": health.get("domain_protection") or {},
            "monitoring_confidence": health.get("monitoring_confidence") or {},
            "path_to_100": health.get("path_to_100") or {},
            "dns_evidence": health.get("dns_evidence") or {},
            "change": change,
            "factors": {
                "dmarc_compliance": _as_int(factors.get("dmarc_compliance")),
                "dns_posture": snapshot.dns_posture_score,
                "policy_strength": snapshot.policy_strength_score,
                "report_confidence": snapshot.report_confidence_score,
                "source_reputation": snapshot.source_reputation_score,
            },
        },
        sort_keys=True,
    )
    snapshot.updated_at = datetime.utcnow()
    if existing is None:
        db.add(snapshot)
    db.commit()
    db.refresh(snapshot)
    return snapshot


def latest_health_score_snapshot(
    db: Session,
    *,
    workspace_id: int,
    domain_name: str,
) -> Optional[HealthScoreSnapshot]:
    """Return the one authoritative score currently shown for a domain."""
    return (
        db.query(HealthScoreSnapshot)
        .filter(
            HealthScoreSnapshot.workspace_id == workspace_id,
            HealthScoreSnapshot.domain_name == domain_name,
        )
        .order_by(HealthScoreSnapshot.snapshot_date.desc(), HealthScoreSnapshot.updated_at.desc())
        .first()
    )


def snapshot_to_domain_health(snapshot: HealthScoreSnapshot) -> Dict[str, Any]:
    """Restore the API health object without recalculating its evidence."""
    evidence = _snapshot_evidence(snapshot)
    return {
        "domain": snapshot.domain_name,
        "score": snapshot.score,
        "grade": snapshot.grade,
        "status": snapshot.status,
        "factors": {
            "dmarc_compliance": float(snapshot.compliance_rate),
            "dns_posture": float(snapshot.dns_posture_score),
            "policy_strength": float(snapshot.policy_strength_score),
            "report_confidence": float(snapshot.report_confidence_score),
            "source_reputation": float(snapshot.source_reputation_score),
        },
        "actions": _snapshot_actions(snapshot),
        "evidence_captured_at": snapshot.updated_at.isoformat(),
        "assessment_version": str(evidence.get("calculation_version") or "1"),
        "core_mail_health": evidence.get("core_mail_health")
        or {
            "score": snapshot.score,
            "grade": snapshot.grade,
            "status": snapshot.status,
        },
        "domain_protection": evidence.get("domain_protection")
        or {
            "policy": snapshot.policy or "unknown",
            "status": "unknown",
        },
        "monitoring_confidence": evidence.get("monitoring_confidence")
        or {
            "score": float(snapshot.report_confidence_score),
            "band": "unknown",
            "reasons": [],
        },
        "path_to_100": _snapshot_path_to_100(snapshot, evidence),
        "dns_evidence": evidence.get("dns_evidence") or {},
        "change": evidence.get("change") or {},
    }


def list_health_score_snapshots(
    db: Session,
    *,
    workspace_id: int,
    domain_name: str,
    start_date: Optional[date] = None,
    end_date: Optional[date] = None,
    limit: int = 120,
) -> List[HealthScoreSnapshot]:
    """Return recent health score snapshots in chronological order."""
    query = db.query(HealthScoreSnapshot).filter(
        HealthScoreSnapshot.workspace_id == workspace_id,
        HealthScoreSnapshot.domain_name == domain_name,
    )
    if start_date:
        query = query.filter(HealthScoreSnapshot.snapshot_date >= start_date)
    if end_date:
        query = query.filter(HealthScoreSnapshot.snapshot_date <= end_date)
    rows = query.order_by(HealthScoreSnapshot.snapshot_date.desc()).limit(limit).all()
    return list(reversed(rows))


def list_workspace_health_score_snapshots(
    db: Session,
    *,
    workspace_id: int,
    start_date: Optional[date] = None,
    end_date: Optional[date] = None,
    limit: int = 120,
) -> List[HealthScoreSnapshot]:
    """Return snapshots for the latest workspace-level history dates."""
    date_query = db.query(HealthScoreSnapshot.snapshot_date).filter(
        HealthScoreSnapshot.workspace_id == workspace_id,
    )
    if start_date:
        date_query = date_query.filter(HealthScoreSnapshot.snapshot_date >= start_date)
    if end_date:
        date_query = date_query.filter(HealthScoreSnapshot.snapshot_date <= end_date)

    date_rows = (
        date_query.distinct().order_by(HealthScoreSnapshot.snapshot_date.desc()).limit(limit).all()
    )
    history_dates = sorted(row[0] for row in date_rows)
    if not history_dates:
        return []

    return (
        db.query(HealthScoreSnapshot)
        .filter(
            HealthScoreSnapshot.workspace_id == workspace_id,
            HealthScoreSnapshot.snapshot_date.in_(history_dates),
        )
        .order_by(HealthScoreSnapshot.snapshot_date.asc(), HealthScoreSnapshot.domain_name.asc())
        .all()
    )


def snapshot_to_history_point(snapshot: HealthScoreSnapshot) -> Dict[str, Any]:
    """Serialize one snapshot for API responses."""
    return {
        "date": snapshot.snapshot_date.isoformat(),
        "score": snapshot.score,
        "grade": snapshot.grade,
        "status": snapshot.status,
        "policy": snapshot.policy,
        "compliance_rate": snapshot.compliance_rate,
        "total_emails": snapshot.total_emails,
        "failed_emails": snapshot.failed_emails,
        "report_count": snapshot.report_count,
        "dns_posture_score": snapshot.dns_posture_score,
        "policy_strength_score": snapshot.policy_strength_score,
        "report_confidence_score": snapshot.report_confidence_score,
        "source_reputation_score": snapshot.source_reputation_score,
        "evidence_captured_at": snapshot.updated_at.isoformat(),
        "top_actions": _snapshot_actions(snapshot),
        "path_to_100": _snapshot_path_to_100(snapshot, _snapshot_evidence(snapshot)),
    }


def aggregate_workspace_health_points(
    points_by_domain: Dict[str, List[Dict[str, Any]]],
) -> List[Dict[str, Any]]:
    """Aggregate per-domain history points into workspace-level daily points."""
    grouped: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for domain_name, points in points_by_domain.items():
        for point in points:
            grouped[str(point["date"])].append({**point, "domain": domain_name})

    workspace_points = []
    for snapshot_date in sorted(grouped):
        day_points = grouped[snapshot_date]
        weights = [max(1, _as_int(point.get("total_emails"))) for point in day_points]
        total_weight = sum(weights) or len(day_points) or 1

        def weighted_average(field: str) -> int:
            return round(
                sum(
                    _as_int(point.get(field)) * weight for point, weight in zip(day_points, weights)
                )
                / total_weight
            )

        score = weighted_average("score")
        actions: List[Dict[str, Any]] = []
        for point in day_points:
            for action in point.get("top_actions", []) or []:
                action_row = dict(action)
                action_row.setdefault("domain", point.get("domain"))
                actions.append(action_row)
        actions.sort(key=lambda item: _as_int(item.get("score_impact")), reverse=True)
        critical_actions = sum(1 for action in actions if action.get("severity") == "critical")
        system_policy = (
            "reject"
            if day_points
            and all((point.get("policy") or "").lower() == "reject" for point in day_points)
            else None
        )
        workspace_points.append(
            {
                "date": snapshot_date,
                "score": score,
                "grade": health_grade(
                    score,
                    policy=system_policy,
                    critical_actions=critical_actions,
                ),
                "status": "healthy" if score >= 90 else "attention" if score >= 70 else "critical",
                "policy": system_policy,
                "compliance_rate": weighted_average("compliance_rate"),
                "total_emails": sum(_as_int(point.get("total_emails")) for point in day_points),
                "failed_emails": sum(_as_int(point.get("failed_emails")) for point in day_points),
                "report_count": sum(_as_int(point.get("report_count")) for point in day_points),
                "dns_posture_score": weighted_average("dns_posture_score"),
                "policy_strength_score": weighted_average("policy_strength_score"),
                "report_confidence_score": weighted_average("report_confidence_score"),
                "domain_count": len(
                    {point.get("domain") for point in day_points if point.get("domain")}
                ),
                "top_actions": actions[:5],
            }
        )
    return workspace_points


def build_health_score_history(
    *,
    domain_name: str,
    snapshots: List[HealthScoreSnapshot],
) -> Dict[str, Any]:
    """Build trend metadata from chronological snapshots."""
    points = [snapshot_to_history_point(snapshot) for snapshot in snapshots]
    current = points[-1] if points else None
    previous = points[-2] if len(points) > 1 else None
    return {
        "domain": domain_name,
        "points": points,
        "current_score": current["score"] if current else None,
        "previous_score": previous["score"] if previous else None,
        "score_delta": (current["score"] - previous["score"] if current and previous else None),
        "current_grade": current["grade"] if current else None,
        "previous_grade": previous["grade"] if previous else None,
        "top_drivers": current["top_actions"] if current else [],
    }


def build_workspace_health_score_history(
    snapshots: List[HealthScoreSnapshot],
) -> Dict[str, Any]:
    """Build workspace-level score history from domain snapshots."""
    points_by_domain: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for snapshot in snapshots:
        points_by_domain[snapshot.domain_name].append(snapshot_to_history_point(snapshot))
    points = aggregate_workspace_health_points(points_by_domain)
    current = points[-1] if points else None
    previous = points[-2] if len(points) > 1 else None
    return {
        "scope": "workspace",
        "points": points,
        "current_score": current["score"] if current else None,
        "previous_score": previous["score"] if previous else None,
        "score_delta": (current["score"] - previous["score"] if current and previous else None),
        "current_grade": current["grade"] if current else None,
        "previous_grade": previous["grade"] if previous else None,
        "top_drivers": current["top_actions"] if current else [],
    }


def build_health_evidence_export_rows(
    snapshots: List[HealthScoreSnapshot],
) -> List[Dict[str, Any]]:
    """Return sanitized rows suitable for CSV/JSON evidence exports."""
    rows = []
    for snapshot in snapshots:
        actions = _snapshot_actions(snapshot)
        rows.append(
            {
                "domain": snapshot.domain_name,
                "snapshot_date": snapshot.snapshot_date.isoformat(),
                "score": snapshot.score,
                "grade": snapshot.grade,
                "status": snapshot.status,
                "policy": snapshot.policy or "",
                "compliance_rate": snapshot.compliance_rate,
                "total_emails": snapshot.total_emails,
                "failed_emails": snapshot.failed_emails,
                "report_count": snapshot.report_count,
                "dns_posture_score": snapshot.dns_posture_score,
                "policy_strength_score": snapshot.policy_strength_score,
                "report_confidence_score": snapshot.report_confidence_score,
                "top_actions": "; ".join(
                    f"{action.get('severity')}:{action.get('title')}"
                    for action in actions
                    if action.get("title")
                ),
            }
        )
    return rows
