"""Persistence helpers for alert history."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.models.alert import AlertConfigurationAudit, AlertHistory


def _json_dumps(value: Dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def alert_fingerprint(alert: Dict[str, Any]) -> str:
    """Return a stable fingerprint for one alert signal."""
    identity = {
        "rule": alert.get("rule"),
        "domain": alert.get("domain"),
        "source_ip": alert.get("source_ip"),
        "threshold": alert.get("threshold"),
    }
    return hashlib.sha256(_json_dumps(identity).encode("utf-8")).hexdigest()


def _row_to_dict(row: AlertHistory) -> Dict[str, Any]:
    payload = {}
    if row.payload:
        try:
            payload = json.loads(row.payload)
        except json.JSONDecodeError:
            payload = {}
    return {
        "id": row.id,
        "fingerprint": row.fingerprint,
        "rule": row.rule,
        "severity": row.severity,
        "domain": row.domain,
        "title": row.title,
        "detail": row.detail,
        "payload": payload,
        "observed_count": row.observed_count,
        "is_active": row.is_active,
        "first_seen_at": row.first_seen_at.isoformat() if row.first_seen_at else None,
        "last_seen_at": row.last_seen_at.isoformat() if row.last_seen_at else None,
        "resolved_at": row.resolved_at.isoformat() if row.resolved_at else None,
    }


def record_alert_evaluation(
    db: Session,
    alerts: List[Dict[str, Any]],
    *,
    observed_at: Optional[datetime] = None,
) -> List[Dict[str, Any]]:
    """Upsert current alerts and resolve active alerts that are no longer present."""
    timestamp = observed_at or datetime.utcnow()
    fingerprints = {alert_fingerprint(alert): alert for alert in alerts}

    if fingerprints:
        existing_rows = (
            db.query(AlertHistory)
            .filter(AlertHistory.fingerprint.in_(list(fingerprints.keys())))
            .all()
        )
    else:
        existing_rows = []
    existing_by_fingerprint = {row.fingerprint: row for row in existing_rows}

    for fingerprint, alert in fingerprints.items():
        row = existing_by_fingerprint.get(fingerprint)
        if row is None:
            row = AlertHistory(
                fingerprint=fingerprint,
                rule=str(alert.get("rule") or "unknown"),
                severity=str(alert.get("severity") or "warning"),
                domain=alert.get("domain"),
                title=str(alert.get("title") or "DMARC alert"),
                detail=str(alert.get("detail") or ""),
                payload=_json_dumps(alert),
                observed_count=1,
                is_active=True,
                first_seen_at=timestamp,
                last_seen_at=timestamp,
            )
            db.add(row)
            continue

        row.rule = str(alert.get("rule") or row.rule)
        row.severity = str(alert.get("severity") or row.severity)
        row.domain = alert.get("domain")
        row.title = str(alert.get("title") or row.title)
        row.detail = str(alert.get("detail") or row.detail)
        row.payload = _json_dumps(alert)
        row.observed_count = int(row.observed_count or 0) + 1
        row.is_active = True
        row.last_seen_at = timestamp
        row.resolved_at = None

    active_rows = db.query(AlertHistory).filter(AlertHistory.is_active == True).all()  # noqa: E712
    for row in active_rows:
        if row.fingerprint not in fingerprints:
            row.is_active = False
            row.resolved_at = timestamp

    db.commit()
    return list_alert_history(db, limit=max(50, len(alerts)))


def list_alert_history(
    db: Session,
    *,
    active: Optional[bool] = None,
    limit: int = 50,
) -> List[Dict[str, Any]]:
    """Return alert history rows ordered by most recent observation."""
    query = db.query(AlertHistory)
    if active is not None:
        query = query.filter(AlertHistory.is_active == active)
    rows = (
        query.order_by(AlertHistory.last_seen_at.desc(), AlertHistory.id.desc()).limit(limit).all()
    )
    return [_row_to_dict(row) for row in rows]


def _actor_from_auth(auth_context: Optional[Dict[str, Any]]) -> Dict[str, Optional[str]]:
    auth_context = auth_context or {}
    user_id = auth_context.get("user_id")
    if user_id is not None:
        changed_by = str(user_id)
    elif auth_context.get("payload", {}).get("sub"):
        changed_by = str(auth_context["payload"]["sub"])
    else:
        changed_by = str(auth_context.get("auth_type") or "unknown")
    return {
        "changed_by": changed_by,
        "auth_type": str(auth_context.get("auth_type") or "unknown"),
    }


def record_alert_config_change(
    db: Session,
    *,
    key: str,
    old_value: Optional[str],
    new_value: Optional[str],
    auth_context: Optional[Dict[str, Any]] = None,
    changed_at: Optional[datetime] = None,
) -> None:
    """Record one sanitized alert/notification setting change."""
    actor = _actor_from_auth(auth_context)
    db.add(
        AlertConfigurationAudit(
            key=key,
            old_value=old_value,
            new_value=new_value,
            changed_by=actor["changed_by"],
            auth_type=actor["auth_type"],
            changed_at=changed_at or datetime.utcnow(),
        )
    )


def _config_audit_row_to_dict(row: AlertConfigurationAudit) -> Dict[str, Any]:
    return {
        "id": row.id,
        "key": row.key,
        "old_value": row.old_value,
        "new_value": row.new_value,
        "changed_by": row.changed_by,
        "auth_type": row.auth_type,
        "changed_at": row.changed_at.isoformat() if row.changed_at else None,
    }


def list_alert_config_audit(db: Session, *, limit: int = 50) -> List[Dict[str, Any]]:
    """Return recent alert/notification configuration changes."""
    rows = (
        db.query(AlertConfigurationAudit)
        .order_by(AlertConfigurationAudit.changed_at.desc(), AlertConfigurationAudit.id.desc())
        .limit(limit)
        .all()
    )
    return [_config_audit_row_to_dict(row) for row in rows]
