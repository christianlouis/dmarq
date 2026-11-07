"""Alert rule evaluation for DMARC report data."""

from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import case, func
from sqlalchemy.orm import Session

from app.models.domain import Domain
from app.models.report import DMARCReport, ReportRecord
from app.models.setting import Setting
from app.services.alert_history import (
    pending_alert_notifications,
    record_alert_evaluation,
    record_alert_notifications,
)
from app.services.notifications import NotificationResult, send_notification
from app.services.webhook_events import (
    EVENT_ALERT_CREATED,
    EVENT_COMPLIANCE_DROP,
    EVENT_REPORTS_MISSING,
    EVENT_SENDER_NEW,
    enqueue_webhook_event,
)

logger = logging.getLogger(__name__)


def _truthy(value: Optional[str], default: bool = True) -> bool:
    if value in (None, ""):
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _int_setting(value: Optional[str], default: int) -> int:
    try:
        return int(value or default)
    except (TypeError, ValueError):
        return default


def _settings(db: Session) -> Dict[str, Optional[str]]:
    rows = db.query(Setting).filter(Setting.category == "notifications").all()
    return {row.key: row.value for row in rows}


def _days_ago_ts(days: int) -> int:
    return int((datetime.now(timezone.utc) - timedelta(days=days)).timestamp())


def _new_source_alerts(db: Session, window_days: int = 7) -> List[Dict[str, Any]]:
    cutoff_ts = _days_ago_ts(window_days)
    previous_sources = {
        (row.domain, row.source_ip)
        for row in (
            db.query(Domain.name.label("domain"), ReportRecord.source_ip.label("source_ip"))
            .join(DMARCReport, DMARCReport.domain_id == Domain.id)
            .join(ReportRecord, ReportRecord.report_id == DMARCReport.id)
            .filter(DMARCReport.begin_date < cutoff_ts)
            .distinct()
            .all()
        )
    }

    current_sources = (
        db.query(
            Domain.name.label("domain"),
            ReportRecord.source_ip.label("source_ip"),
            func.sum(ReportRecord.count).label("message_count"),
        )
        .join(DMARCReport, DMARCReport.domain_id == Domain.id)
        .join(ReportRecord, ReportRecord.report_id == DMARCReport.id)
        .filter(DMARCReport.begin_date >= cutoff_ts)
        .group_by(Domain.name, ReportRecord.source_ip)
        .order_by(func.sum(ReportRecord.count).desc())
        .all()
    )

    alerts = []
    for row in current_sources:
        if (row.domain, row.source_ip) in previous_sources:
            continue
        count = int(row.message_count or 0)
        alerts.append(
            {
                "rule": "new_sender_source",
                "severity": "warning",
                "domain": row.domain,
                "source_ip": row.source_ip,
                "message_count": count,
                "title": "New sending source",
                "detail": f"{row.source_ip} first appeared for {row.domain} with {count} messages.",
            }
        )
    return alerts


def _failure_threshold_alerts(
    db: Session, threshold: int, window_days: int = 1
) -> List[Dict[str, Any]]:
    cutoff_ts = _days_ago_ts(window_days)
    rows = (
        db.query(
            Domain.name.label("domain"),
            func.sum(ReportRecord.count).label("failed_messages"),
        )
        .join(DMARCReport, DMARCReport.domain_id == Domain.id)
        .join(ReportRecord, ReportRecord.report_id == DMARCReport.id)
        .filter(DMARCReport.begin_date >= cutoff_ts)
        .filter(func.coalesce(ReportRecord.dkim, "fail") != "pass")
        .filter(func.coalesce(ReportRecord.spf, "fail") != "pass")
        .group_by(Domain.name)
        .having(func.sum(ReportRecord.count) >= threshold)
        .all()
    )
    return [
        {
            "rule": "dmarc_failures_above_threshold",
            "severity": "error",
            "domain": row.domain,
            "failed_messages": int(row.failed_messages or 0),
            "threshold": threshold,
            "title": "DMARC failures above threshold",
            "detail": (
                f"{row.domain} had {int(row.failed_messages or 0)} DMARC failures "
                f"in the last {window_days} day(s)."
            ),
        }
        for row in rows
    ]


def _missing_report_alerts(db: Session, missing_days: int) -> List[Dict[str, Any]]:
    cutoff_ts = _days_ago_ts(missing_days)
    latest_rows = (
        db.query(
            Domain.name.label("domain"),
            func.max(DMARCReport.end_date).label("last_report_ts"),
        )
        .outerjoin(DMARCReport, DMARCReport.domain_id == Domain.id)
        .group_by(Domain.id, Domain.name)
        .all()
    )
    alerts = []
    for row in latest_rows:
        last_report_ts = int(row.last_report_ts or 0)
        if last_report_ts >= cutoff_ts:
            continue
        alerts.append(
            {
                "rule": "missing_reports",
                "severity": "warning",
                "domain": row.domain,
                "missing_days": missing_days,
                "last_report_at": (
                    datetime.fromtimestamp(last_report_ts, tz=timezone.utc).isoformat()
                    if last_report_ts
                    else None
                ),
                "title": "Missing DMARC reports",
                "detail": f"{row.domain} has no DMARC report in the last {missing_days} day(s).",
            }
        )
    return alerts


def _compliance_drop_alerts(
    db: Session, drop_points: int, window_days: int = 2
) -> List[Dict[str, Any]]:
    cutoff_ts = _days_ago_ts(window_days)
    rows = (
        db.query(
            Domain.name.label("domain"),
            DMARCReport.begin_date.label("begin_date"),
            func.sum(ReportRecord.count).label("total"),
            func.sum(
                case(
                    (
                        (ReportRecord.dkim == "pass") | (ReportRecord.spf == "pass"),
                        ReportRecord.count,
                    ),
                    else_=0,
                )
            ).label("passed"),
        )
        .join(DMARCReport, DMARCReport.domain_id == Domain.id)
        .join(ReportRecord, ReportRecord.report_id == DMARCReport.id)
        .filter(DMARCReport.begin_date >= cutoff_ts)
        .group_by(Domain.name, DMARCReport.begin_date)
        .order_by(Domain.name, DMARCReport.begin_date)
        .all()
    )

    by_domain: Dict[str, List[Dict[str, float]]] = {}
    for row in rows:
        total = int(row.total or 0)
        passed = int(row.passed or 0)
        rate = round((passed / total) * 100, 1) if total else 0.0
        by_domain.setdefault(row.domain, []).append({"date": row.begin_date, "rate": rate})

    alerts = []
    for domain, points in by_domain.items():
        if len(points) < 2:
            continue
        previous = points[-2]
        current = points[-1]
        drop = round(previous["rate"] - current["rate"], 1)
        if drop < drop_points:
            continue
        alerts.append(
            {
                "rule": "compliance_drop",
                "severity": "error" if drop >= 25 else "warning",
                "domain": domain,
                "previous_rate": previous["rate"],
                "current_rate": current["rate"],
                "drop": drop,
                "threshold": drop_points,
                "title": "Compliance dropped",
                "detail": f"{domain} compliance fell by {drop} percentage points.",
            }
        )
    return alerts


def evaluate_alert_rules(db: Session) -> List[Dict[str, Any]]:
    """Evaluate all enabled alert rules against persisted DMARC data."""
    settings = _settings(db)
    alerts: List[Dict[str, Any]] = []

    if _truthy(settings.get("notifications.alert_new_sources_enabled")):
        alerts.extend(_new_source_alerts(db))

    if _truthy(settings.get("notifications.alert_failure_threshold_enabled")):
        threshold = _int_setting(settings.get("notifications.alert_failure_threshold_count"), 100)
        alerts.extend(_failure_threshold_alerts(db, threshold))

    if _truthy(settings.get("notifications.alert_missing_reports_enabled")):
        missing_days = _int_setting(settings.get("notifications.alert_missing_reports_days"), 2)
        alerts.extend(_missing_report_alerts(db, missing_days))

    if _truthy(settings.get("notifications.alert_compliance_drop_enabled")):
        drop_points = _int_setting(settings.get("notifications.alert_compliance_drop_points"), 10)
        alerts.extend(_compliance_drop_alerts(db, drop_points))

    domain_names = {str(alert["domain"]) for alert in alerts if alert.get("domain")}
    workspace_ids = {
        row.name: row.workspace_id
        for row in db.query(Domain.name, Domain.workspace_id)
        .filter(Domain.name.in_(domain_names))
        .all()
    }
    for alert in alerts:
        domain = alert.get("domain")
        if domain in workspace_ids:
            # Preserve an explicit None for legacy, unscoped domains.  The
            # webhook enqueue path distinguishes it from an unknown owner.
            alert["workspace_id"] = workspace_ids[domain]
    return alerts


def enqueue_alert_webhook_events(db: Session, alerts: List[Dict[str, Any]]) -> None:
    """Queue webhook events for alert-rule results without failing alert evaluation."""
    event_by_rule = {
        "new_sender_source": EVENT_SENDER_NEW,
        "missing_reports": EVENT_REPORTS_MISSING,
        "compliance_drop": EVENT_COMPLIANCE_DROP,
    }
    for alert in alerts:
        rule = alert.get("rule", "alert")
        event_type = event_by_rule.get(rule, EVENT_ALERT_CREATED)
        domain = alert.get("domain", "global")
        if "workspace_id" not in alert:
            logger.warning("Skipping webhook for alert with unknown domain owner: %s", domain)
            continue
        alert_workspace_id = alert.get("workspace_id")
        legacy_key = f"{event_type}:{domain}:{rule}:{alert.get('detail', '')}"
        idempotency_key = legacy_key
        if len(idempotency_key) > 160:
            digest = hashlib.sha256(idempotency_key.encode("utf-8")).hexdigest()
            idempotency_key = f"{idempotency_key[:95]}:{digest}"
        try:
            enqueue_webhook_event(
                db,
                event_type=event_type,
                payload=alert,
                idempotency_key=idempotency_key,
                workspace_id=alert_workspace_id,
            )
        except Exception as exc:  # pylint: disable=broad-exception-caught
            db.rollback()
            logger.warning("Failed to queue alert webhook event: %s", exc)


def send_current_alerts(db: Session, *, only_unnotified: bool = False) -> Dict[str, Any]:
    """Evaluate alerts; scheduled delivery only sends unsent or escalated occurrences."""
    alerts = evaluate_alert_rules(db)
    record_alert_evaluation(db, alerts)
    enqueue_alert_webhook_events(db, alerts)
    if not alerts:
        return {
            "alerts": alerts,
            "notification": NotificationResult(
                success=True,
                skipped=True,
                message="No alerts.",
            ).to_dict(),
        }

    pending = pending_alert_notifications(db, alerts) if only_unnotified else alerts
    if not pending:
        return {
            "alerts": alerts,
            "notification": NotificationResult(
                success=True,
                skipped=True,
                message="All active alerts have already been notified.",
            ).to_dict(),
        }

    result = send_alert_summary_notification(db, pending)
    if result["notification"]["success"] and not result["notification"]["skipped"]:
        record_alert_notifications(db, pending)
    # Keep API callers' view of all active alerts, even when only a subset was sent.
    return {"alerts": alerts, "notification": result["notification"]}


def send_alert_summary_notification(db: Session, alerts: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Send one notification for an already evaluated alert set."""
    # Every receipted alert must have its details in the delivered summary.
    lines = [f"{alert['title']}: {alert['detail']}" for alert in alerts]
    result = send_notification(
        db,
        title=f"DMARQ alert summary: {len(alerts)} alert(s)",
        body="\n".join(lines),
    )
    return {"alerts": alerts, "notification": result.to_dict()}
