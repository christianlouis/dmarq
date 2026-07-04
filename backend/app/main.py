import asyncio
import logging
import os
from datetime import datetime
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool

import app.models.alert  # noqa: F401 – ensure AlertHistory table is registered
import app.models.api_token  # noqa: F401 – ensure APIToken table is registered
import app.models.dns_cache  # noqa: F401 – ensure DNSCache table is registered
import app.models.domain  # noqa: F401 – ensure Domain/UserDomain tables are registered
import app.models.mail_source_import  # noqa: F401 – ensure import history table is registered
import app.models.report  # noqa: F401 – ensure DMARCReport/ReportRecord tables are registered
import app.models.setting  # noqa: F401 – ensure Setting table is registered
import app.models.user  # noqa: F401 – ensure User table is registered
import app.models.webhook  # noqa: F401 – ensure webhook tables are registered
import app.models.workspace  # noqa: F401 – ensure workspace table is registered
import app.models.workspace_access  # noqa: F401 – ensure RBAC/audit tables are registered
from app.api.api_v1.api import api_router
from app.core.auth_providers import auth_provider_registry
from app.core.config import get_settings
from app.core.database import Base, SessionLocal, engine
from app.core.security import add_api_key, generate_api_key, require_admin_auth
from app.core.startup_checks import run_startup_checks
from app.middleware.auth import AuthRedirectMiddleware
from app.middleware.demo import DemoReadOnlyMiddleware
from app.middleware.security import SecurityHeadersMiddleware
from app.models.domain import Domain
from app.models.mail_source import MailSource  # noqa: F401 – ensure table is registered
from app.services.dns_prewarm import prewarm_dns_cache
from app.services.gmail_client import GmailClient
from app.services.imap_client import IMAPClient
from app.services.import_history import record_import_attempt
from app.services.mail_service_imports import mail_service_context_from_domain
from app.services.mail_source_backfill_worker import run_due_mail_source_backfill_jobs
from app.services.microsoft_graph_client import MicrosoftGraphClient
from app.services.release_info import build_release_info
from app.services.report_persistence import hydrate_report_store_from_db
from app.services.report_store import ReportStore
from app.services.runtime_status import (
    mark_scheduler_cycle_started,
    mark_scheduler_error,
    mark_scheduler_started,
    mark_scheduler_stopped,
    mark_scheduler_success,
)
from app.services.summary_notifications import send_due_scheduled_summaries
from app.services.webhook_events import deliver_due_webhooks

# Set up logging
logger = logging.getLogger(__name__)

settings = get_settings()

# Global variables for background task management
background_task = None
dns_prewarm_task = None
last_check_time = None


async def _cancel_background_task(task: Optional[asyncio.Task], label: str) -> None:
    """Cancel and await a background task so shutdown does not leave it pending."""
    if not task:
        return
    if task.done():
        return
    logger.info("Cancelling %s background task", label)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        logger.debug("%s background task cancelled during shutdown", label)


def _poll_single_imap_source(source: MailSource) -> None:
    """Fetch DMARC reports for a single IMAP mail source and update its last_checked timestamp."""
    global last_check_time  # pylint: disable=global-statement

    db = SessionLocal()
    try:
        src = db.query(MailSource).get(source.id)
        poll_source = src or source
        imap_client = IMAPClient(
            server=poll_source.server,
            port=poll_source.port or 993,
            username=poll_source.username,
            password=poll_source.password,
            folder=poll_source.folder,
            db=db,
            workspace_id=getattr(poll_source, "workspace_id", None),
        )
        started_at = datetime.utcnow()
        results = imap_client.fetch_reports(days=9999)
        if src:
            src.last_checked = datetime.utcnow()
            record_import_attempt(db, src, results, started_at=started_at, trigger="scheduled")
            db.commit()
    finally:
        db.close()

    last_check_time = datetime.now()

    if results["success"]:
        logger.info(
            "IMAP polling (source id=%d): %s emails processed, %s aggregate reports found, "
            "%s forensic reports found",
            source.id,
            results["processed"],
            results["reports_found"],
            results.get("forensic_reports_found", 0),
        )
        if results["new_domains"]:
            logger.info("New domains found: %s", ", ".join(results["new_domains"]))
    else:
        logger.error(
            "IMAP polling (source id=%d) failed: %s",
            source.id,
            results.get("error", "Unknown error"),
        )


def _poll_single_gmail_source(source: MailSource) -> None:
    """Fetch DMARC reports for a single GMAIL_API mail source."""
    global last_check_time  # pylint: disable=global-statement

    if not source.gmail_access_token:
        logger.info(
            "Gmail polling (source id=%d): skipped – OAuth2 not yet authorised",
            source.id,
        )
        return

    db = SessionLocal()
    try:
        src = db.query(MailSource).get(source.id)
        poll_source = src or source
        already = GmailClient.load_ingested_ids(poll_source.gmail_ingested_ids)
        client = GmailClient(
            client_id=poll_source.gmail_client_id or "",
            client_secret=poll_source.gmail_client_secret or "",
            access_token=poll_source.gmail_access_token,
            refresh_token=poll_source.gmail_refresh_token or "",
            already_ingested_ids=already,
            db=db,
            workspace_id=getattr(poll_source, "workspace_id", None),
        )

        started_at = datetime.utcnow()
        results = client.fetch_reports()
        if src:
            if results.get("new_ingested_ids"):
                all_ids = list(dict.fromkeys(already + results["new_ingested_ids"]))
                src.gmail_ingested_ids = GmailClient.dump_ingested_ids(all_ids)

            refreshed = client.get_refreshed_tokens()
            if refreshed:
                src.gmail_access_token = refreshed["access_token"]
                if "refresh_token" in refreshed:
                    src.gmail_refresh_token = refreshed["refresh_token"]

            src.last_checked = datetime.utcnow()
            record_import_attempt(db, src, results, started_at=started_at, trigger="scheduled")
            db.commit()
    finally:
        db.close()

    last_check_time = datetime.now()

    if results["success"]:
        logger.info(
            "Gmail polling (source id=%d): %s emails processed, %s aggregate reports found, "
            "%s forensic reports found",
            source.id,
            results["processed"],
            results["reports_found"],
            results.get("forensic_reports_found", 0),
        )
        if results["new_domains"]:
            logger.info("New domains found: %s", ", ".join(results["new_domains"]))
    else:
        logger.error(
            "Gmail polling (source id=%d) failed: %s",
            source.id,
            results.get("error", "Unknown error"),
        )


def _poll_single_m365_source(source: MailSource) -> None:
    """Fetch DMARC reports for a single M365_GRAPH mail source."""
    global last_check_time  # pylint: disable=global-statement

    if not source.m365_access_token:
        logger.info(
            "Microsoft 365 polling (source id=%d): skipped – OAuth2 not yet authorised",
            source.id,
        )
        return

    db = SessionLocal()
    try:
        src = db.query(MailSource).get(source.id)
        poll_source = src or source
        already = MicrosoftGraphClient.load_ingested_ids(poll_source.m365_ingested_ids)
        client = MicrosoftGraphClient(
            tenant_id=poll_source.m365_tenant_id or "common",
            client_id=poll_source.m365_client_id or "",
            client_secret=poll_source.m365_client_secret or "",
            access_token=poll_source.m365_access_token,
            refresh_token=poll_source.m365_refresh_token or "",
            mailbox=poll_source.m365_mailbox,
            folder=poll_source.folder or "INBOX",
            folder_id=getattr(poll_source, "m365_folder_id", None),
            already_ingested_ids=already,
            db=db,
            workspace_id=getattr(poll_source, "workspace_id", None),
        )

        started_at = datetime.utcnow()
        results = client.fetch_reports(days=7)
        if src:
            if results.get("new_ingested_ids"):
                all_ids = list(dict.fromkeys(already + results["new_ingested_ids"]))
                src.m365_ingested_ids = MicrosoftGraphClient.dump_ingested_ids(all_ids)

            refreshed = client.get_refreshed_tokens()
            if refreshed:
                src.m365_access_token = refreshed["access_token"]
                if "refresh_token" in refreshed:
                    src.m365_refresh_token = refreshed["refresh_token"]

            src.last_checked = datetime.utcnow()
            record_import_attempt(db, src, results, started_at=started_at, trigger="scheduled")
            db.commit()
    finally:
        db.close()

    last_check_time = datetime.now()

    if results["success"]:
        logger.info(
            "Microsoft 365 polling (source id=%d): %s emails processed, "
            "%s aggregate reports found",
            source.id,
            results["processed"],
            results["reports_found"],
        )
        if results["new_domains"]:
            logger.info("New domains found: %s", ", ".join(results["new_domains"]))
    else:
        logger.error(
            "Microsoft 365 polling (source id=%d) failed: %s",
            source.id,
            results.get("error", "Unknown error"),
        )


def _poll_all_enabled_sources() -> list[MailSource]:  # noqa: C901
    """Iterate over all enabled mail sources and poll each one."""
    db = SessionLocal()
    try:
        enabled_sources = (
            db.query(MailSource).filter(MailSource.enabled == True).all()  # noqa: E712
        )
    finally:
        db.close()

    if not enabled_sources:
        logger.info("No enabled mail sources configured – polling skipped")
        return enabled_sources

    for source in enabled_sources:
        if source.method == "GMAIL_API":
            try:
                _poll_single_gmail_source(source)
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.error("Error polling Gmail source id=%d: %s", source.id, str(e))
        elif source.method == "M365_GRAPH":
            try:
                _poll_single_m365_source(source)
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.error("Error polling Microsoft 365 source id=%d: %s", source.id, str(e))
        elif source.method == "IMAP":
            try:
                _poll_single_imap_source(source)
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.error("Error polling mail source id=%d: %s", source.id, str(e))
        else:
            logger.info(
                "Skipping mail source id=%d method=%r (not yet implemented)",
                source.id,
                source.method,
            )
    return enabled_sources


def _send_due_summary_notifications() -> None:
    """Send scheduled summary notifications when their configured cadence is due."""
    db = SessionLocal()
    try:
        results = send_due_scheduled_summaries(db)
        for period, result in results.items():
            notification = result.get("notification", {})
            if notification.get("success"):
                logger.info("Sent %s DMARC summary notification", period)
            else:
                logger.warning(
                    "%s DMARC summary notification was not sent: %s",
                    period.capitalize(),
                    notification.get("message", "Unknown error"),
                )
    finally:
        db.close()


def _deliver_due_webhook_events() -> None:
    """Attempt due outbound webhook deliveries."""
    db = SessionLocal()
    try:
        deliveries = deliver_due_webhooks(db)
        if deliveries:
            delivered = sum(1 for item in deliveries if item.status == "delivered")
            logger.info(
                "Processed %d webhook deliveries (%d delivered)", len(deliveries), delivered
            )
    finally:
        db.close()


def _run_due_mail_source_backfills() -> int:
    """Execute a bounded batch of queued mail-source backfill jobs."""
    db = SessionLocal()
    try:
        count = run_due_mail_source_backfill_jobs(db)
        if count:
            logger.info("Processed %d queued mail-source backfill job(s)", count)
        return count
    finally:
        db.close()


def _next_sleep_seconds(
    min_sleep: int = 60, enabled_sources: Optional[List[MailSource]] = None
) -> int:
    """Return how many seconds to sleep until the next polling cycle."""
    try:
        if enabled_sources is None:
            db = SessionLocal()
            try:
                enabled_sources = (
                    db.query(MailSource).filter(MailSource.enabled == True).all()  # noqa: E712
                )
            finally:
                db.close()
        intervals = [s.polling_interval or 60 for s in enabled_sources]
        return max(min_sleep, min(intervals, default=3600) * 60)
    except Exception:  # pylint: disable=broad-exception-caught
        return 3600


async def scheduled_imap_polling():
    """Background task for periodically checking IMAP for new DMARC reports"""
    try:
        while True:
            logger.info("Starting scheduled IMAP polling for DMARC reports")
            mark_scheduler_cycle_started()
            try:
                enabled_sources = _poll_all_enabled_sources()
                _run_due_mail_source_backfills()
                _send_due_summary_notifications()
                _deliver_due_webhook_events()
                mark_scheduler_success()
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.error("Error in IMAP polling task: %s", str(e))
                mark_scheduler_error(e)
                enabled_sources = None

            try:
                await asyncio.sleep(_next_sleep_seconds(enabled_sources=enabled_sources))
            except asyncio.CancelledError:
                raise
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.error("Error sleeping in IMAP polling task: %s", str(e))
                await asyncio.sleep(3600)

    except asyncio.CancelledError:
        logger.info("IMAP polling task cancelled")
        mark_scheduler_stopped()


def _migrate_imap_env_vars_to_db() -> None:
    """
    One-time migration: if IMAP_* environment variables are configured and no
    MailSource rows exist yet, create an initial MailSource from those settings.

    This ensures that existing deployments continue to work without manual
    reconfiguration after the upgrade.
    """
    if not all([settings.IMAP_SERVER, settings.IMAP_USERNAME, settings.IMAP_PASSWORD]):
        return

    db = SessionLocal()
    try:
        if db.query(MailSource).first() is not None:
            return  # already migrated or manually configured

        migrated = MailSource(
            name="Default IMAP (migrated from environment)",
            method="IMAP",
            server=settings.IMAP_SERVER,
            port=settings.IMAP_PORT,
            username=settings.IMAP_USERNAME,
            password=settings.IMAP_PASSWORD,
            use_ssl=True,
            folder="INBOX",
            polling_interval=60,
            enabled=True,
        )
        db.add(migrated)
        db.commit()
        logger.info(
            "Migrated IMAP settings from environment variables to "
            "database (MailSource id=%d). "
            "You can now manage this source via the Mail Sources admin UI.",
            migrated.id,
        )
    except Exception as e:  # pylint: disable=broad-exception-caught
        logger.error("Failed to migrate IMAP env vars to database: %s", str(e))
    finally:
        db.close()


def _encrypt_legacy_mail_source_secrets() -> None:
    """Encrypt plaintext mail-source secrets left by earlier versions."""
    db = SessionLocal()
    try:
        changed = 0
        for source in db.query(MailSource).all():
            if source.encrypt_legacy_secrets():
                changed += 1

        if changed:
            db.commit()
            logger.info("Encrypted legacy mail-source credentials for %d source(s).", changed)
    except Exception as e:  # pylint: disable=broad-exception-caught
        db.rollback()
        logger.error("Failed to encrypt legacy mail-source credentials: %s", str(e))
    finally:
        db.close()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application"""
    application = FastAPI(
        title=settings.PROJECT_NAME,
        openapi_url=f"{settings.API_V1_STR}/openapi.json",
        version="0.1.0",
    )

    # Add security headers middleware
    # Determine environment from settings or environment variable
    environment = os.getenv("ENVIRONMENT", "development")
    application.add_middleware(SecurityHeadersMiddleware, environment=environment)
    application.add_middleware(DemoReadOnlyMiddleware)

    # Auth redirect middleware – protects HTML pages; must sit outside CORS
    application.add_middleware(AuthRedirectMiddleware)

    # Improved CORS configuration - restrict to specific methods and headers
    if settings.BACKEND_CORS_ORIGINS:
        application.add_middleware(
            CORSMiddleware,
            allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
            allow_credentials=True,
            # Security: Restrict to only necessary HTTP methods
            allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            # Security: Specify allowed headers instead of wildcard
            allow_headers=[
                "Content-Type",
                "Authorization",
                "X-API-Key",
                "Accept",
                "Origin",
                "X-Requested-With",
            ],
            # Security: Limit exposed headers
            expose_headers=["Content-Length", "X-RateLimit-Limit"],
            max_age=600,  # Cache preflight requests for 10 minutes
        )

    # Include API router
    application.include_router(api_router, prefix=settings.API_V1_STR)

    # Mount static files directory
    application.mount(
        "/static",
        StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")),
        name="static",
    )

    # Set up event handlers for startup and shutdown
    @application.on_event("startup")
    async def startup_event():
        """Initialize background tasks and security on application startup"""
        global background_task, dns_prewarm_task  # pylint: disable=global-statement

        run_startup_checks(settings)

        # Ensure all tables exist (no-op if already present)
        Base.metadata.create_all(bind=engine)

        # Warn loudly when authentication is completely disabled
        if settings.AUTH_DISABLED:
            if settings.DEMO_MODE:
                logger.warning(
                    "%s\n"
                    "AUTH_DISABLED=true with DEMO_MODE=true — browser access is public, "
                    "and mutating requests are blocked by the demo read-only guard.\n"
                    "%s",
                    "=" * 80,
                    "=" * 80,
                )
            else:
                logger.warning(
                    "%s\n"
                    "⚠️  AUTH_DISABLED=true — authentication is turned OFF.\n"
                    "All requests have unrestricted admin access.\n"
                    "Do NOT expose this instance directly to the internet.\n"
                    "%s",
                    "=" * 80,
                    "=" * 80,
                )

        # Load or generate the admin API key
        if settings.ADMIN_API_KEY:
            api_key = settings.ADMIN_API_KEY
            add_api_key(api_key)
            logger.info(
                "Admin API key loaded from ADMIN_API_KEY environment variable "
                "(length: %d chars).",
                len(api_key),
            )
        else:
            api_key = generate_api_key()
            add_api_key(api_key)
            logger.warning(
                "%s\nIMPORTANT: Admin API Key Generated\n"
                "Key length: %d chars. Full key stored securely in memory.\n"
                "Set ADMIN_API_KEY in your environment to use a fixed key across restarts.\n"
                "Use this key in the X-API-Key header for admin endpoints.\n%s",
                "=" * 80,
                len(api_key),
                "=" * 80,
            )

        # One-time migration: if IMAP_* env vars are set and no mail sources exist,
        # create an initial MailSource from those settings so existing deployments
        # continue to work without manual reconfiguration.
        _migrate_imap_env_vars_to_db()
        _encrypt_legacy_mail_source_secrets()

        # Start background polling task (iterates over DB-enabled mail sources)
        logger.info("Starting IMAP polling background task")
        mark_scheduler_started()
        background_task = asyncio.create_task(scheduled_imap_polling())
        dns_prewarm_task = asyncio.create_task(prewarm_dns_cache())

    @application.on_event("shutdown")
    async def shutdown_event():
        """Clean up background tasks on application shutdown"""
        global dns_prewarm_task  # pylint: disable=global-statement

        await _cancel_background_task(dns_prewarm_task, "DNS prewarm")
        dns_prewarm_task = None
        if background_task:
            logger.info("Cancelling IMAP polling background task")
            background_task.cancel()
            try:
                await background_task
            except asyncio.CancelledError:
                pass
            mark_scheduler_stopped()

    return application


app = create_app()  # noqa: F811 – intentional rebind; `app` package imported above for side-effects

# Initialize Jinja2 templates
templates_dir = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=templates_dir)
templates.env.globals["multi_workspace_ui_enabled"] = settings.MULTI_WORKSPACE_UI_ENABLED
templates.env.globals["release_info"] = build_release_info(settings)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html")


@app.get("/favicon.ico", include_in_schema=False)
async def favicon():
    return FileResponse(os.path.join(os.path.dirname(__file__), "static", "img", "favicon.ico"))


# Individual page routes
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(request, "index.html")


@app.get("/login", response_class=HTMLResponse)
async def login(request: Request, next: str = "/"):
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "app_name": settings.PROJECT_NAME,
            "logto_configured": settings.logto_configured,
            "auth_configured": settings.auth_configured,
            "auth_provider": settings.active_auth_provider,
            "auth_provider_label": settings.auth_provider_label,
            "auth_disabled": settings.AUTH_DISABLED,
            "next": next,
        },
    )


@app.get("/setup", response_class=HTMLResponse)
async def setup(request: Request):
    return templates.TemplateResponse(
        request,
        "setup.html",
        {
            "app_name": settings.PROJECT_NAME,
            "logto_configured": settings.logto_configured,
            "auth_configured": settings.auth_configured,
            "auth_provider": settings.active_auth_provider,
            "auth_provider_label": settings.auth_provider_label,
            "auth_provider_options": auth_provider_registry(settings),
        },
    )


@app.get("/onboarding", response_class=HTMLResponse)
async def onboarding(request: Request):
    return templates.TemplateResponse(request, "onboarding.html")


@app.get("/domains", response_class=HTMLResponse)
async def domains(request: Request):
    return templates.TemplateResponse(request, "domains.html")


@app.get("/domain/{domain_id}", response_class=HTMLResponse)
async def domain_details(request: Request, domain_id: str):
    """View detailed reports for a specific domain"""
    store = ReportStore.get_instance()
    db = SessionLocal()
    try:
        hydrate_report_store_from_db(db, store)
        stored_domain = db.query(Domain).filter(Domain.name == domain_id).first()
    finally:
        db.close()
    known_domains = store.get_domains()

    if domain_id not in known_domains and stored_domain is None:
        # Domain not found, redirect to domains list
        return templates.TemplateResponse(
            request, "domains.html", {"error": f"Domain {domain_id} not found"}
        )

    domain_summary = store.get_domain_summary(domain_id) if domain_id in known_domains else {}

    return templates.TemplateResponse(
        request,
        "domain_details.html",
        {
            "domain_id": domain_id,
            "domain": {
                "name": domain_id,
                "description": stored_domain.description if stored_domain else "",
                "mail_service_context": mail_service_context_from_domain(stored_domain),
                "policy": (
                    domain_summary.get("policy")
                    or (stored_domain.dmarc_policy if stored_domain else None)
                    or "unknown"
                ),
            },
        },
    )


@app.get("/domains/{domain_id}", response_class=HTMLResponse)
async def domain_details_plural(request: Request, domain_id: str):
    """View detailed reports for a specific domain (plural /domains/ path alias)"""
    return await domain_details(request, domain_id)


@app.get("/reports", response_class=HTMLResponse)
async def reports(request: Request):
    return templates.TemplateResponse(request, "reports.html")


@app.get("/reports/{report_id}", response_class=HTMLResponse)
async def report_detail(request: Request, report_id: str):
    """View detailed information for a specific DMARC report"""
    return templates.TemplateResponse(request, "report_detail.html", {"report_id": report_id})


@app.get("/forensics", response_class=HTMLResponse)
async def forensic_reports(request: Request):
    """View DMARC forensic authentication failure reports."""
    return templates.TemplateResponse(request, "forensic_reports.html")


@app.get("/tls-reports", response_class=HTMLResponse)
async def tls_reports(request: Request):
    """View SMTP TLS reporting posture summaries."""
    return templates.TemplateResponse(request, "tls_reports.html")


@app.get("/forensics/{report_id}", response_class=HTMLResponse)
async def forensic_report_detail(request: Request, report_id: int):
    """View detailed information for a specific forensic report."""
    return templates.TemplateResponse(
        request,
        "forensic_report_detail.html",
        {"report_id": report_id},
    )


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    return templates.TemplateResponse(request, "settings.html")


@app.get("/profile", response_class=HTMLResponse)
async def profile_page(request: Request):
    return templates.TemplateResponse(
        request,
        "profile.html",
        {
            "app_name": settings.PROJECT_NAME,
            "logto_configured": settings.logto_configured,
            "auth_configured": settings.auth_configured,
            "auth_provider": settings.active_auth_provider,
            "auth_provider_label": settings.auth_provider_label,
            "auth_disabled": settings.AUTH_DISABLED,
        },
    )


@app.get("/members", response_class=HTMLResponse)
async def members_page(request: Request):
    if not settings.MULTI_WORKSPACE_UI_ENABLED:
        return RedirectResponse(url="/settings", status_code=303)
    return templates.TemplateResponse(request, "members.html")


@app.get("/mail-sources", response_class=HTMLResponse)
async def mail_sources_page(request: Request):
    return templates.TemplateResponse(request, "mail_sources.html")


@app.get("/operations", response_class=HTMLResponse)
async def operations_page(request: Request):
    return templates.TemplateResponse(request, "operations.html")


@app.get("/upload", response_class=HTMLResponse)
async def upload_page(request: Request):
    return templates.TemplateResponse(request, "upload.html")


@app.get("/health", status_code=200, tags=["health"])
@app.get("/healthz", status_code=200, tags=["health"], include_in_schema=False)
async def health():
    """Root-level health check endpoint for Kubernetes liveness/readiness probes."""
    release = build_release_info(settings)
    return {
        "status": "ok",
        "service": "dmarq",
        "version": release["version"],
        "release": {
            "label": release["label"],
            "environment": release["environment"],
            "build": release["build"],
        },
    }


# ---------------------------------------------------------------------------
# Helpers for the manual trigger-poll endpoint
# ---------------------------------------------------------------------------


def _trigger_poll_imap_source(source: MailSource, db, days: int = 7) -> dict:
    """Poll a single IMAP source and return a result dict for the API response."""
    global last_check_time  # pylint: disable=global-statement

    imap_client = IMAPClient(
        server=source.server,
        port=source.port or 993,
        username=source.username,
        password=source.password,
        folder=source.folder,
        db=db,
        workspace_id=getattr(source, "workspace_id", None),
    )
    started_at = datetime.utcnow()
    results = imap_client.fetch_reports(days=days)
    last_check_time = datetime.now()
    source.last_checked = datetime.utcnow()
    record_import_attempt(db, source, results, started_at=started_at, trigger="manual")
    db.commit()
    return {
        "source_id": source.id,
        "name": source.name,
        "method": "IMAP",
        "success": results["success"],
        "processed": results.get("processed", 0),
        "reports_found": results.get("reports_found", 0),
        "forensic_reports_found": results.get("forensic_reports_found", 0),
        "duplicate_forensic_reports": results.get("duplicate_forensic_reports", 0),
        "new_domains": results.get("new_domains", []),
    }


def _trigger_poll_gmail_source(source: MailSource, db) -> dict:
    """Poll a single GMAIL_API source and return a result dict for the API response."""
    global last_check_time  # pylint: disable=global-statement

    already = GmailClient.load_ingested_ids(source.gmail_ingested_ids)
    gmail_client = GmailClient(
        client_id=source.gmail_client_id or "",
        client_secret=source.gmail_client_secret or "",
        access_token=source.gmail_access_token,
        refresh_token=source.gmail_refresh_token or "",
        already_ingested_ids=already,
        db=db,
        workspace_id=getattr(source, "workspace_id", None),
    )
    started_at = datetime.utcnow()
    results = gmail_client.fetch_reports()
    last_check_time = datetime.now()

    if results.get("new_ingested_ids"):
        all_ids = list(dict.fromkeys(already + results["new_ingested_ids"]))
        source.gmail_ingested_ids = GmailClient.dump_ingested_ids(all_ids)
    refreshed = gmail_client.get_refreshed_tokens()
    if refreshed:
        source.gmail_access_token = refreshed["access_token"]
        if "refresh_token" in refreshed:
            source.gmail_refresh_token = refreshed["refresh_token"]
    source.last_checked = datetime.utcnow()
    record_import_attempt(db, source, results, started_at=started_at, trigger="manual")
    db.commit()
    return {
        "source_id": source.id,
        "name": source.name,
        "method": "GMAIL_API",
        "success": results["success"],
        "processed": results.get("processed", 0),
        "reports_found": results.get("reports_found", 0),
        "forensic_reports_found": results.get("forensic_reports_found", 0),
        "duplicate_forensic_reports": results.get("duplicate_forensic_reports", 0),
        "new_domains": results.get("new_domains", []),
    }


def _trigger_poll_m365_source(source: MailSource, db, days: int = 7) -> dict:
    """Poll a single M365_GRAPH source and return a result dict for the API response."""
    global last_check_time  # pylint: disable=global-statement

    already = MicrosoftGraphClient.load_ingested_ids(source.m365_ingested_ids)
    graph_client = MicrosoftGraphClient(
        tenant_id=source.m365_tenant_id or "common",
        client_id=source.m365_client_id or "",
        client_secret=source.m365_client_secret or "",
        access_token=source.m365_access_token,
        refresh_token=source.m365_refresh_token or "",
        mailbox=source.m365_mailbox,
        folder=source.folder or "INBOX",
        folder_id=getattr(source, "m365_folder_id", None),
        already_ingested_ids=already,
        db=db,
        workspace_id=getattr(source, "workspace_id", None),
    )
    started_at = datetime.utcnow()
    results = graph_client.fetch_reports(days=days)
    last_check_time = datetime.now()

    if results.get("new_ingested_ids"):
        all_ids = list(dict.fromkeys(already + results["new_ingested_ids"]))
        source.m365_ingested_ids = MicrosoftGraphClient.dump_ingested_ids(all_ids)
    refreshed = graph_client.get_refreshed_tokens()
    if refreshed:
        source.m365_access_token = refreshed["access_token"]
        if "refresh_token" in refreshed:
            source.m365_refresh_token = refreshed["refresh_token"]
    source.last_checked = datetime.utcnow()
    record_import_attempt(db, source, results, started_at=started_at, trigger="manual")
    db.commit()
    return {
        "source_id": source.id,
        "name": source.name,
        "method": "M365_GRAPH",
        "success": results["success"],
        "processed": results.get("processed", 0),
        "reports_found": results.get("reports_found", 0),
        "forensic_reports_found": results.get("forensic_reports_found", 0),
        "duplicate_forensic_reports": results.get("duplicate_forensic_reports", 0),
        "new_domains": results.get("new_domains", []),
    }


def _poll_source_for_trigger(source: MailSource, db, days: int = 7) -> dict:  # noqa: C901
    """Dispatch a single mail source for the manual trigger-poll endpoint.

    Returns a result/summary dict that is included in the API response.
    """
    if source.method == "GMAIL_API":
        if not source.gmail_access_token:
            return {
                "source_id": source.id,
                "name": source.name,
                "method": "GMAIL_API",
                "skipped": True,
                "reason": "Gmail account not yet authorised",
            }
        try:
            return _trigger_poll_gmail_source(source, db)
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Error polling Gmail source id=%d: %s", source.id, str(e))
            return {
                "source_id": source.id,
                "name": source.name,
                "method": "GMAIL_API",
                "success": False,
                "error": "Failed to poll. Check server logs for details.",
            }
    if source.method == "M365_GRAPH":
        if not source.m365_access_token:
            return {
                "source_id": source.id,
                "name": source.name,
                "method": "M365_GRAPH",
                "skipped": True,
                "reason": "Microsoft 365 account not yet authorised",
            }
        try:
            return _trigger_poll_m365_source(source, db, days=days)
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Error polling Microsoft 365 source id=%d: %s", source.id, str(e))
            return {
                "source_id": source.id,
                "name": source.name,
                "method": "M365_GRAPH",
                "success": False,
                "error": "Failed to poll. Check server logs for details.",
            }
    if source.method == "IMAP":
        try:
            return _trigger_poll_imap_source(source, db, days=days)
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Error polling mail source id=%d: %s", source.id, str(e))
            return {
                "source_id": source.id,
                "name": source.name,
                "method": "IMAP",
                "success": False,
                "error": "Failed to poll. Check server logs for details.",
            }
    return {
        "source_id": source.id,
        "name": source.name,
        "method": source.method,
        "skipped": True,
        "reason": f"method '{source.method}' not yet implemented",
    }


def _poll_enabled_sources_for_trigger(days: int) -> list[dict]:
    """Poll all enabled mail sources for the manual trigger-poll endpoint."""
    results_summary = []
    db = SessionLocal()
    try:
        enabled_sources = (
            db.query(MailSource).filter(MailSource.enabled == True).all()  # noqa: E712
        )

        for source in enabled_sources:
            results_summary.append(_poll_source_for_trigger(source, db, days=days))
    finally:
        db.close()

    return results_summary


# API endpoint to manually trigger mail-source polling
@app.get("/api/v1/admin/trigger-poll", include_in_schema=False)
async def trigger_mail_source_poll_get() -> None:
    """Explain that manual polling is a POST action when opened directly."""
    raise HTTPException(
        status_code=405,
        detail={
            "code": "method_not_allowed",
            "message": "Manual polling must be started with the dashboard button or a POST request.",
            "next_steps": [
                "Open the dashboard and use Trigger Poll Now.",
                "For API usage, send POST /api/v1/admin/trigger-poll with admin authentication.",
            ],
        },
        headers={"Allow": "POST"},
    )


@app.post("/api/v1/admin/trigger-poll")
async def trigger_mail_source_poll(
    auth: dict = Depends(require_admin_auth),
    days: int = Query(7, ge=1, le=365, title="Number of days to fetch for mail sources"),
):
    """
    Manually trigger polling for all enabled mail sources (admin only).

    Security: Requires either X-API-Key header or Bearer token
    """
    results_summary = await run_in_threadpool(_poll_enabled_sources_for_trigger, days)
    if not results_summary:
        return {
            "success": True,
            "message": "No enabled mail sources configured.",
            "sources_polled": 0,
            "days": days,
            "authenticated_by": auth.get("auth_type"),
        }

    return {
        "success": all(r.get("success", True) for r in results_summary),
        "message": "Mail-source polling completed.",
        "timestamp": last_check_time.isoformat() if last_check_time else None,
        "days": days,
        "sources_polled": len(results_summary),
        "sources": results_summary,
        "source_methods": sorted(
            {
                str(result.get("method") or "").upper()
                for result in results_summary
                if result.get("method")
            }
        ),
        "authenticated_by": auth.get("auth_type"),
    }


def _source_display_label(source: MailSource) -> str:
    """Return a short, non-secret label for a configured mail source."""
    method = (source.method or "IMAP").upper()
    if method == "GMAIL_API":
        account = source.gmail_email or source.name
        return f"Gmail API: {account}"
    if method == "M365_GRAPH":
        account = source.m365_email or source.m365_mailbox or source.name
        return f"Microsoft 365: {account}"
    if method == "IMAP":
        mailbox = source.username or source.name
        return f"IMAP: {mailbox}"
    return f"{method}: {source.name}"


def _mail_source_status_summary() -> dict:
    """Summarize enabled report intake sources without exposing credentials."""
    db = SessionLocal()
    try:
        enabled_sources = (
            db.query(MailSource).filter(MailSource.enabled == True).all()  # noqa: E712
        )
        by_method: dict[str, int] = {}
        source_labels = []
        latest_checked = None
        for source in enabled_sources:
            method = (source.method or "IMAP").upper()
            by_method[method] = by_method.get(method, 0) + 1
            source_labels.append(_source_display_label(source))
            if source.last_checked and (
                latest_checked is None or source.last_checked > latest_checked
            ):
                latest_checked = source.last_checked

        return {
            "enabled_sources": len(enabled_sources),
            "sources_by_method": by_method,
            "source_labels": source_labels,
            "latest_source_check": latest_checked.isoformat() if latest_checked else None,
        }
    finally:
        db.close()


# API endpoint to check status of report intake polling
@app.get("/api/v1/poll-status")
async def get_poll_status(auth: dict = Depends(require_admin_auth)):
    """
    Get the status of report intake polling (admin only).
    """
    source_summary = await run_in_threadpool(_mail_source_status_summary)
    return {
        "is_running": background_task is not None and not background_task.done(),
        "last_check": last_check_time.isoformat() if last_check_time else None,
        "authenticated_by": auth.get("auth_type"),
        **source_summary,
    }
