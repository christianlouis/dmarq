"""Daily and weekly DMARC summary notification helpers."""

from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import case, func
from sqlalchemy.orm import Session

from app.models.domain import Domain
from app.models.report import DMARCReport, ReportRecord
from app.models.setting import Setting
from app.services.alert_history import record_alert_evaluation
from app.services.alert_rules import evaluate_alert_rules
from app.services.notifications import send_notification

logger = logging.getLogger(__name__)

SUMMARY_PERIODS = {
    "daily": 1,
    "weekly": 7,
}


def _truthy(value: Optional[str], default: bool = False) -> bool:
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


def _set_setting(db: Session, key: str, value: str) -> None:
    row = db.query(Setting).filter(Setting.key == key).first()
    if row is None:
        row = Setting(
            key=key,
            value=value,
            category="notifications",
            value_type="string",
        )
        db.add(row)
    else:
        row.value = value
    db.commit()


def _period_days(period: str) -> int:
    if period not in SUMMARY_PERIODS:
        raise ValueError("Summary period must be daily or weekly.")
    return SUMMARY_PERIODS[period]


def _cutoff_ts(period: str, now: Optional[datetime] = None) -> int:
    reference = now or datetime.now(timezone.utc)
    return int((reference - timedelta(days=_period_days(period))).timestamp())


def _recent_records_query(db: Session, cutoff_ts: int):
    return (
        db.query(
            Domain.name.label("domain"),
            ReportRecord.source_ip.label("source_ip"),
            ReportRecord.count.label("count"),
            ReportRecord.dkim.label("dkim"),
            ReportRecord.spf.label("spf"),
        )
        .join(DMARCReport, DMARCReport.domain_id == Domain.id)
        .join(ReportRecord, ReportRecord.report_id == DMARCReport.id)
        .filter(DMARCReport.begin_date >= cutoff_ts)
    )


def _aggregate_totals(db: Session, cutoff_ts: int) -> Dict[str, int]:
    row = (
        db.query(
            func.coalesce(func.sum(ReportRecord.count), 0).label("total_messages"),
            func.coalesce(
                func.sum(
                    case(
                        (
                            (ReportRecord.dkim == "pass") | (ReportRecord.spf == "pass"),
                            ReportRecord.count,
                        ),
                        else_=0,
                    )
                ),
                0,
            ).label("compliant_messages"),
            func.coalesce(
                func.sum(
                    case(
                        (
                            (func.coalesce(ReportRecord.dkim, "fail") != "pass")
                            & (func.coalesce(ReportRecord.spf, "fail") != "pass"),
                            ReportRecord.count,
                        ),
                        else_=0,
                    )
                ),
                0,
            ).label("failed_messages"),
        )
        .join(DMARCReport, DMARCReport.id == ReportRecord.report_id)
        .filter(DMARCReport.begin_date >= cutoff_ts)
        .first()
    )
    if row is None:
        return {"total_messages": 0, "compliant_messages": 0, "failed_messages": 0}
    return {
        "total_messages": int(row.total_messages or 0),
        "compliant_messages": int(row.compliant_messages or 0),
        "failed_messages": int(row.failed_messages or 0),
    }


def _top_domains(db: Session, cutoff_ts: int, limit: int = 5) -> List[Dict[str, Any]]:
    rows = (
        _recent_records_query(db, cutoff_ts)
        .with_entities(
            Domain.name.label("domain"),
            func.sum(ReportRecord.count).label("message_count"),
        )
        .group_by(Domain.name)
        .order_by(func.sum(ReportRecord.count).desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "domain": row.domain,
            "message_count": int(row.message_count or 0),
        }
        for row in rows
    ]


def _top_sources(db: Session, cutoff_ts: int, limit: int = 5) -> List[Dict[str, Any]]:
    rows = (
        _recent_records_query(db, cutoff_ts)
        .with_entities(
            ReportRecord.source_ip.label("source_ip"),
            func.sum(ReportRecord.count).label("message_count"),
        )
        .group_by(ReportRecord.source_ip)
        .order_by(func.sum(ReportRecord.count).desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "source_ip": row.source_ip,
            "message_count": int(row.message_count or 0),
        }
        for row in rows
    ]


def build_summary(
    db: Session, period: str = "daily", now: Optional[datetime] = None
) -> Dict[str, Any]:
    """Build a daily or weekly DMARC activity summary."""
    cutoff = _cutoff_ts(period, now)
    totals = _aggregate_totals(db, cutoff)
    total_messages = totals["total_messages"]
    compliance_rate = (
        round((totals["compliant_messages"] / total_messages) * 100, 1) if total_messages else 0.0
    )
    reports_processed = (
        db.query(func.count(DMARCReport.id)).filter(DMARCReport.begin_date >= cutoff).scalar() or 0
    )
    return {
        "period": period,
        "period_days": _period_days(period),
        "generated_at": (now or datetime.now(timezone.utc)).isoformat(),
        "total_domains": int(db.query(func.count(Domain.id)).scalar() or 0),
        "reports_processed": int(reports_processed),
        "total_messages": total_messages,
        "compliant_messages": totals["compliant_messages"],
        "failed_messages": totals["failed_messages"],
        "compliance_rate": compliance_rate,
        "top_domains": _top_domains(db, cutoff),
        "top_sources": _top_sources(db, cutoff),
        "alerts": evaluate_alert_rules(db),
    }


def format_summary_body(summary: Dict[str, Any]) -> str:
    """Format a DMARC summary as a concise notification body."""
    period_label = summary["period"].capitalize()
    lines = [
        f"{period_label} DMARC summary",
        f"Reports processed: {summary['reports_processed']}",
        f"Messages observed: {summary['total_messages']}",
        f"Compliance rate: {summary['compliance_rate']}%",
        f"DMARC failures: {summary['failed_messages']}",
        f"Active alerts: {len(summary['alerts'])}",
    ]

    if summary["top_domains"]:
        lines.append("")
        lines.append("Top domains:")
        lines.extend(
            f"- {item['domain']}: {item['message_count']} messages"
            for item in summary["top_domains"][:5]
        )

    if summary["top_sources"]:
        lines.append("")
        lines.append("Top sources:")
        lines.extend(
            f"- {item['source_ip']}: {item['message_count']} messages"
            for item in summary["top_sources"][:5]
        )

    if summary["alerts"]:
        lines.append("")
        lines.append("Alerts:")
        lines.extend(f"- {alert['title']}: {alert['detail']}" for alert in summary["alerts"][:5])
        if len(summary["alerts"]) > 5:
            lines.append(f"...and {len(summary['alerts']) - 5} more alert(s).")

    return "\n".join(lines)


def send_summary_notification(db: Session, period: str = "daily") -> Dict[str, Any]:
    """Build and send a daily or weekly summary notification."""
    summary = build_summary(db, period)
    record_alert_evaluation(db, summary["alerts"])
    title = (
        f"DMARQ {period} summary: "
        f"{summary['total_messages']} message(s), {len(summary['alerts'])} alert(s)"
    )
    result = send_notification(
        db,
        title=title,
        body=format_summary_body(summary),
    )
    return {"summary": summary, "notification": result.to_dict()}


def _daily_due(settings: Dict[str, Optional[str]], now: datetime) -> bool:
    last_sent = settings.get("notifications.summary_daily_last_sent_date")
    return last_sent != now.date().isoformat()


def _weekly_due(settings: Dict[str, Optional[str]], now: datetime) -> bool:
    last_sent = settings.get("notifications.summary_weekly_last_sent_week")
    year, week, _ = now.isocalendar()
    return last_sent != f"{year}-W{week:02d}"


def send_due_scheduled_summaries(
    db: Session,
    now: Optional[datetime] = None,
) -> Dict[str, Dict[str, Any]]:
    """Send enabled daily and weekly summaries when their schedule is due."""
    settings = _settings(db)
    current_time = now or datetime.now(timezone.utc)
    send_hour = max(
        0, min(23, _int_setting(settings.get("notifications.summary_send_hour_utc"), 8))
    )
    if current_time.hour < send_hour:
        return {}

    results: Dict[str, Dict[str, Any]] = {}
    if _truthy(settings.get("notifications.summary_daily_enabled")) and _daily_due(
        settings, current_time
    ):
        results["daily"] = send_summary_notification(db, "daily")
        if results["daily"]["notification"].get("success"):
            _set_setting(
                db,
                "notifications.summary_daily_last_sent_date",
                current_time.date().isoformat(),
            )

    weekday = max(0, min(6, _int_setting(settings.get("notifications.summary_weekday_utc"), 0)))
    if (
        _truthy(settings.get("notifications.summary_weekly_enabled"))
        and current_time.weekday() == weekday
        and _weekly_due(settings, current_time)
    ):
        results["weekly"] = send_summary_notification(db, "weekly")
        if results["weekly"]["notification"].get("success"):
            year, week, _ = current_time.isocalendar()
            _set_setting(db, "notifications.summary_weekly_last_sent_week", f"{year}-W{week:02d}")

    return results
