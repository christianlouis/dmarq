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


@router.get("/health/operations", status_code=200)
async def operations_health(
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
    if database["ok"]:
        enabled_sources = (
            db.query(func.count(MailSource.id))
            .filter(MailSource.enabled == True)  # noqa: E712
            .scalar()
        )
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
        },
        "imports": {
            "latest": {
                "status": latest_import.status,
                "trigger": latest_import.trigger,
                "reports_found": latest_import.reports_found,
                "finished_at": _iso(latest_import.finished_at),
                "diagnostic": latest_import_diagnostic,
            }
            if latest_import
            else None,
            "latest_successful": {
                "status": latest_successful_import.status,
                "trigger": latest_successful_import.trigger,
                "reports_found": latest_successful_import.reports_found,
                "finished_at": _iso(latest_successful_import.finished_at),
            }
            if latest_successful_import
            else None,
        },
        "reports": {
            "count": int(report_count or 0),
            "latest_processed_at": _iso(latest_report),
        },
        "checks": checks,
        "mailbox_recovery": mailbox_recovery,
    }
