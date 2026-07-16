from fastapi import APIRouter, Depends
from sqlalchemy import func, text
from sqlalchemy.orm import Session

from app.api.api_v1.endpoints.setup import setup_status
from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.mail_source import MailSource
from app.models.mail_source_import import MailSourceImport
from app.models.report import DMARCReport
from app.services.mailbox_recovery import import_row_diagnostic, not_configured_guidance
from app.services.microsoft_graph_client import (
    M365_AUTH_MODE_APPLICATION,
    m365_application_configuration_error,
    m365_source_can_authenticate,
    normalize_m365_auth_mode,
)
from app.services.release_info import build_release_info
from app.services.runtime_status import get_scheduler_status

router = APIRouter()


@router.get("/health", status_code=200)
async def health_check():
    """
    Health check endpoint to verify API status.
    For Milestone 1, this simply returns status information without checking a database.
    """
    release = build_release_info(get_settings())
    return {
        "status": "ok",
        "version": release["version"],
        "service": "dmarq",
        "release": {
            "label": release["label"],
            "environment": release["environment"],
            "build": release["build"],
        },
        "is_setup_complete": setup_status["is_setup_complete"],
    }


@router.get("/health/release", status_code=200)
async def release_info():
    """Return safe release/build metadata for support and the in-product changelog."""
    return build_release_info(get_settings())


def _iso(value):
    return value.isoformat() if value else None


def _latest_imports_by_source(db: Session, source_ids):
    if not source_ids:
        return {}
    rows = (
        db.query(MailSourceImport)
        .filter(MailSourceImport.mail_source_id.in_(source_ids))
        .order_by(
            MailSourceImport.mail_source_id.asc(),
            MailSourceImport.started_at.desc(),
            MailSourceImport.id.desc(),
        )
        .all()
    )
    latest = {}
    for row in rows:
        latest.setdefault(int(row.mail_source_id), row)
    return latest


def _source_label(source: MailSource) -> str:
    method = (source.method or "IMAP").upper()
    if method == "GMAIL_API":
        return f"Gmail API: {source.gmail_email or source.name}"
    if method == "M365_GRAPH":
        return f"Microsoft 365: {source.m365_email or source.m365_mailbox or source.name}"
    if method == "IMAP":
        return f"IMAP: {source.username or source.name}"
    return f"{method}: {source.name}"


def _source_health(source: MailSource, latest_import=None):
    method = (source.method or "IMAP").upper()
    if method == "GMAIL_API" and not source.gmail_access_token:
        return {
            "source_id": source.id,
            "label": _source_label(source),
            "method": method,
            "status": "not_authorized",
            "attention": True,
            "message": "Gmail is not authorised yet.",
            "action_label": "Connect Gmail",
            "diagnostic_category": "auth_required",
        }
    if method == "GMAIL_API" and not source.gmail_refresh_token:
        return {
            "source_id": source.id,
            "label": _source_label(source),
            "method": method,
            "status": "reauth_required",
            "attention": True,
            "message": "Gmail is connected without a refresh token.",
            "action_label": "Reconnect Gmail",
            "diagnostic_category": "auth_expired",
        }
    if method == "M365_GRAPH" and not m365_source_can_authenticate(source):
        application_mode = (
            normalize_m365_auth_mode(getattr(source, "m365_auth_mode", "delegated"))
            == M365_AUTH_MODE_APPLICATION
        )
        return {
            "source_id": source.id,
            "label": _source_label(source),
            "method": method,
            "status": "missing_config" if application_mode else "not_authorized",
            "attention": True,
            "message": m365_application_configuration_error(source)
            or "Microsoft 365 is not authorised yet.",
            "action_label": (
                "Review application settings" if application_mode else "Connect Microsoft 365"
            ),
            "diagnostic_category": "missing_config" if application_mode else "auth_required",
        }
    if (
        method == "M365_GRAPH"
        and normalize_m365_auth_mode(getattr(source, "m365_auth_mode", "delegated"))
        == M365_AUTH_MODE_APPLICATION
        and not source.m365_access_token
    ):
        return {
            "source_id": source.id,
            "label": _source_label(source),
            "method": method,
            "status": "ready_to_test",
            "attention": False,
            "message": "Application credentials are saved; test mailbox access.",
            "action_label": "Test connection",
            "diagnostic_category": "ok",
        }

    diagnostic = import_row_diagnostic(latest_import)
    category = (diagnostic or {}).get("category")
    if (
        latest_import
        and latest_import.status == "failed"
        and category
        in {
            "auth_expired",
            "authentication",
            "permissions",
        }
    ):
        return {
            "source_id": source.id,
            "label": _source_label(source),
            "method": method,
            "status": "reauth_required",
            "attention": True,
            "message": diagnostic["summary"],
            "action_label": "Reconnect mailbox",
            "diagnostic_category": category,
        }

    return {
        "source_id": source.id,
        "label": _source_label(source),
        "method": method,
        "status": "connected" if method in {"GMAIL_API", "M365_GRAPH"} else "configured",
        "attention": False,
        "message": None,
        "action_label": None,
        "diagnostic_category": category or "ok",
    }


@router.get("/health/operations", status_code=200)
async def operations_health(  # noqa: C901
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Return operational health details for the web health page."""
    database = {"ok": True, "detail": "Connected"}
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:  # pylint: disable=broad-exception-caught
        database = {"ok": False, "detail": str(exc)}

    enabled_sources = 0
    total_sources = 0
    report_count = 0
    latest_report = None
    latest_import = None
    latest_successful_import = None
    mail_source_health = []
    if database["ok"]:
        enabled_source_rows = (
            db.query(MailSource).filter(MailSource.enabled == True).all()  # noqa: E712
        )
        enabled_sources = len(enabled_source_rows)
        total_sources = db.query(func.count(MailSource.id)).scalar()
        report_count = db.query(func.count(DMARCReport.id)).scalar()
        latest_report = db.query(func.max(DMARCReport.processed_at)).scalar()
        latest_import = (
            db.query(MailSourceImport)
            .order_by(MailSourceImport.finished_at.desc(), MailSourceImport.id.desc())
            .first()
        )
        latest_successful_import = (
            db.query(MailSourceImport)
            .filter(MailSourceImport.status.in_(["success", "warning"]))
            .order_by(MailSourceImport.finished_at.desc(), MailSourceImport.id.desc())
            .first()
        )
        latest_by_source = _latest_imports_by_source(
            db,
            [int(source.id) for source in enabled_source_rows],
        )
        mail_source_health = [
            _source_health(source, latest_by_source.get(int(source.id)))
            for source in enabled_source_rows
        ]

    scheduler = get_scheduler_status()
    status = "ok"
    checks = []
    mailbox_recovery = []
    if not database["ok"]:
        status = "degraded"
        checks.append("Database connectivity failed.")
    if database["ok"] and enabled_sources == 0:
        mailbox_recovery.append(not_configured_guidance())
    if total_sources and enabled_sources == 0:
        status = "degraded"
        checks.append("All mail sources are disabled.")
    attention_sources = [source for source in mail_source_health if source["attention"]]
    if attention_sources:
        status = "degraded"
        attention_count = len(attention_sources)
        source_label = "source" if attention_count == 1 else "sources"
        needs_label = "needs" if attention_count == 1 else "need"
        checks.append(
            f"{attention_count} mail {source_label} {needs_label} authorization attention."
        )
        for source in attention_sources:
            mailbox_recovery.append(
                {
                    "category": source["diagnostic_category"],
                    "summary": source["message"] or "Mail source needs attention.",
                    "recovery_steps": [source["action_label"]] if source["action_label"] else [],
                    "source_label": source["label"],
                    "source_id": source["source_id"],
                }
            )
    if scheduler.get("last_error"):
        status = "degraded"
        checks.append("The scheduler reported a recent error.")
    latest_import_diagnostic = import_row_diagnostic(latest_import)
    if latest_import_diagnostic and latest_import_diagnostic["category"] not in {
        "ok",
        "duplicate_only",
    }:
        status = "degraded"
        checks.append(latest_import_diagnostic["summary"])
        mailbox_recovery.append(latest_import_diagnostic)

    return {
        "status": status,
        "service": "dmarq",
        "database": database,
        "scheduler": {
            **scheduler,
            "enabled_sources": int(enabled_sources or 0),
            "total_sources": int(total_sources or 0),
            "attention_sources": len(attention_sources),
            "reauth_required_sources": len(
                [source for source in mail_source_health if source["status"] == "reauth_required"]
            ),
            "sources": mail_source_health,
        },
        "imports": {
            "latest": (
                {
                    "status": latest_import.status,
                    "trigger": latest_import.trigger,
                    "reports_found": latest_import.reports_found,
                    "finished_at": _iso(latest_import.finished_at),
                    "diagnostic": latest_import_diagnostic,
                }
                if latest_import
                else None
            ),
            "latest_successful": (
                {
                    "status": latest_successful_import.status,
                    "trigger": latest_successful_import.trigger,
                    "reports_found": latest_successful_import.reports_found,
                    "finished_at": _iso(latest_successful_import.finished_at),
                }
                if latest_successful_import
                else None
            ),
        },
        "reports": {
            "count": int(report_count or 0),
            "latest_processed_at": _iso(latest_report),
        },
        "checks": checks,
        "mailbox_recovery": mailbox_recovery,
    }
