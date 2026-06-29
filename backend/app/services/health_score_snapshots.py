"""Persist and export domain health score snapshots."""

from __future__ import annotations

import json
from datetime import date, datetime
from typing import Any, Dict, Iterable, List, Optional

from sqlalchemy.orm import Session

from app.models.health_score_snapshot import HealthScoreSnapshot


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
                "score_impact": _as_int(action.get("score_impact")),
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
    snapshot.top_actions = json.dumps(actions, sort_keys=True)
    snapshot.updated_at = datetime.utcnow()
    if existing is None:
        db.add(snapshot)
    db.commit()
    db.refresh(snapshot)
    return snapshot


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
        "top_actions": _snapshot_actions(snapshot),
    }


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
