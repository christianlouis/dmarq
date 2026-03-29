import asyncio
import logging
import os
from datetime import datetime

from fastapi import Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.api.api_v1.api import api_router
from app.core.config import get_settings
from app.core.database import Base, SessionLocal, engine
from app.core.security import add_api_key, generate_api_key, require_admin_auth
from app.middleware.security import SecurityHeadersMiddleware
from app.models.mail_source import MailSource  # noqa: F401 – ensure table is registered
from app.services.imap_client import IMAPClient
from app.services.report_store import ReportStore

# Set up logging
logger = logging.getLogger(__name__)

settings = get_settings()

# Global variables for background task management
background_task = None
last_check_time = None


def _poll_single_imap_source(source: MailSource) -> None:
    """Fetch DMARC reports for a single IMAP mail source and update its last_checked timestamp."""
    global last_check_time  # pylint: disable=global-statement

    imap_client = IMAPClient(
        server=source.server,
        port=source.port or 993,
        username=source.username,
        password=source.password,
        delete_emails=False,
    )
    results = imap_client.fetch_reports(days=9999)

    db = SessionLocal()
    try:
        src = db.query(MailSource).get(source.id)
        if src:
            src.last_checked = datetime.utcnow()
            db.commit()
    finally:
        db.close()

    last_check_time = datetime.now()

    if results["success"]:
        logger.info(
            "IMAP polling (source id=%d): %s emails processed, %s reports found",
            source.id,
            results["processed"],
            results["reports_found"],
        )
        if results["new_domains"]:
            logger.info("New domains found: %s", ", ".join(results["new_domains"]))
    else:
        logger.error(
            "IMAP polling (source id=%d) failed: %s",
            source.id,
            results.get("error", "Unknown error"),
        )


def _poll_all_enabled_sources() -> None:
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
        return

    for source in enabled_sources:
        if source.method != "IMAP":
            logger.info(
                "Skipping mail source id=%d method=%r (not yet implemented)",
                source.id,
                source.method,
            )
            continue
        try:
            _poll_single_imap_source(source)
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Error polling mail source id=%d: %s", source.id, str(e))


def _next_sleep_seconds(min_sleep: int = 60) -> int:
    """Return how many seconds to sleep until the next polling cycle."""
    try:
        db = SessionLocal()
        try:
            intervals = [
                s.polling_interval or 60
                for s in db.query(MailSource).filter(MailSource.enabled == True).all()  # noqa: E712
            ]
        finally:
            db.close()
        return max(min_sleep, min(intervals, default=3600) * 60)
    except Exception:  # pylint: disable=broad-exception-caught
        return 3600


async def scheduled_imap_polling():
    """Background task for periodically checking IMAP for new DMARC reports"""
    try:
        while True:
            logger.info("Starting scheduled IMAP polling for DMARC reports")
            try:
                _poll_all_enabled_sources()
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.error("Error in IMAP polling task: %s", str(e))

            await asyncio.sleep(_next_sleep_seconds())

    except asyncio.CancelledError:
        logger.info("IMAP polling task cancelled")


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
        global background_task  # pylint: disable=global-statement

        # Ensure all tables exist (no-op if already present)
        Base.metadata.create_all(bind=engine)

        # Generate and provide admin API key
        api_key = generate_api_key()
        add_api_key(api_key)

        # Security: Log only last 8 characters for reference
        logger.warning(
            "%s\nIMPORTANT: Admin API Key Generated\n"
            "API Key (last 8 chars): ...%s\n"
            "Full key stored securely in memory.\n"
            "For production, retrieve the key through secure configuration management.\n"
            "Use this key in the X-API-Key header for admin endpoints.\n%s",
            "=" * 80,
            api_key[-8:],
            "=" * 80,
        )

        # In development, also log the full key for convenience
        # This should be removed in production or controlled by environment variable
        if os.getenv("ENVIRONMENT", "development") == "development":
            logger.info("Development Mode - Full API Key: %s", api_key)

        # One-time migration: if IMAP_* env vars are set and no mail sources exist,
        # create an initial MailSource from those settings so existing deployments
        # continue to work without manual reconfiguration.
        _migrate_imap_env_vars_to_db()

        # Start background polling task (iterates over DB-enabled mail sources)
        logger.info("Starting IMAP polling background task")
        background_task = asyncio.create_task(scheduled_imap_polling())

    @application.on_event("shutdown")
    async def shutdown_event():
        """Clean up background tasks on application shutdown"""
        if background_task:
            logger.info("Cancelling IMAP polling background task")
            background_task.cancel()
            try:
                await background_task
            except asyncio.CancelledError:
                pass

    return application


app = create_app()

# Initialize Jinja2 templates
templates_dir = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=templates_dir)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html")


# Individual page routes
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(
        request, "dashboard.html", {"app_name": settings.PROJECT_NAME}
    )


@app.get("/login", response_class=HTMLResponse)
async def login(request: Request):
    return templates.TemplateResponse(request, "login.html", {"app_name": settings.PROJECT_NAME})


@app.get("/setup", response_class=HTMLResponse)
async def setup(request: Request):
    return templates.TemplateResponse(request, "setup.html", {"app_name": settings.PROJECT_NAME})


@app.get("/domains", response_class=HTMLResponse)
async def domains(request: Request):
    return templates.TemplateResponse(request, "domains.html")


@app.get("/domain/{domain_id}", response_class=HTMLResponse)
async def domain_details(request: Request, domain_id: str):
    """View detailed reports for a specific domain"""
    store = ReportStore.get_instance()
    known_domains = store.get_domains()

    if domain_id not in known_domains:
        # Domain not found, redirect to domains list
        return templates.TemplateResponse(
            request, "domains.html", {"error": f"Domain {domain_id} not found"}
        )

    domain_summary = store.get_domain_summary(domain_id)

    return templates.TemplateResponse(
        request,
        "domain_details.html",
        {
            "domain_id": domain_id,
            "domain": {
                "name": domain_id,
                "description": "",  # Add description if available
                "policy": domain_summary.get("policy", "unknown"),
            },
        },
    )


@app.get("/reports", response_class=HTMLResponse)
async def reports(request: Request):
    return templates.TemplateResponse(request, "reports.html")


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    return templates.TemplateResponse(request, "settings.html")


@app.get("/mail-sources", response_class=HTMLResponse)
async def mail_sources_page(request: Request):
    return templates.TemplateResponse("mail_sources.html", {"request": request})


@app.get("/upload", response_class=HTMLResponse)
async def upload_page(request: Request):
    return templates.TemplateResponse(request, "upload.html")


@app.get("/health", status_code=200, tags=["health"])
@app.get("/healthz", status_code=200, tags=["health"], include_in_schema=False)
async def health():
    """Root-level health check endpoint for Kubernetes liveness/readiness probes."""
    return {"status": "ok", "service": "dmarq"}


# API endpoint to manually trigger IMAP polling
@app.post("/api/v1/admin/trigger-poll")
async def trigger_imap_poll(auth: dict = Depends(require_admin_auth)):
    """
    Manually trigger IMAP polling for all enabled mail sources (admin only).

    Security: Requires either X-API-Key header or Bearer token
    """
    global last_check_time  # pylint: disable=global-statement

    results_summary = []
    db = SessionLocal()
    try:
        enabled_sources = (
            db.query(MailSource).filter(MailSource.enabled == True).all()  # noqa: E712
        )

        if not enabled_sources:
            return {
                "success": True,
                "message": "No enabled mail sources configured.",
                "sources_polled": 0,
                "authenticated_by": auth.get("auth_type"),
            }

        for source in enabled_sources:
            if source.method != "IMAP":
                results_summary.append(
                    {
                        "source_id": source.id,
                        "name": source.name,
                        "skipped": True,
                        "reason": f"method '{source.method}' not yet implemented",
                    }
                )
                continue

            try:
                imap_client = IMAPClient(
                    server=source.server,
                    port=source.port or 993,
                    username=source.username,
                    password=source.password,
                    delete_emails=False,
                )
                results = imap_client.fetch_reports(days=7)
                last_check_time = datetime.now()
                source.last_checked = datetime.utcnow()
                db.commit()

                results_summary.append(
                    {
                        "source_id": source.id,
                        "name": source.name,
                        "success": results["success"],
                        "processed": results.get("processed", 0),
                        "reports_found": results.get("reports_found", 0),
                        "new_domains": results.get("new_domains", []),
                    }
                )
            except Exception as e:  # pylint: disable=broad-exception-caught
                logger.error("Error polling mail source id=%d: %s", source.id, str(e))
                results_summary.append(
                    {
                        "source_id": source.id,
                        "name": source.name,
                        "success": False,
                        "error": "Failed to poll. Check server logs for details.",
                    }
                )
    finally:
        db.close()

    return {
        "success": all(r.get("success", True) for r in results_summary),
        "timestamp": last_check_time.isoformat() if last_check_time else None,
        "sources": results_summary,
        "authenticated_by": auth.get("auth_type"),
    }


# API endpoint to check status of IMAP polling
@app.get("/api/v1/admin/poll-status")
async def get_poll_status(auth: dict = Depends(require_admin_auth)):
    """
    Get the status of IMAP polling (admin only - requires authentication)

    Security: Requires either X-API-Key header or Bearer token
    """
    return {
        "is_running": background_task is not None and not background_task.done(),
        "last_check": last_check_time.isoformat() if last_check_time else None,
        "authenticated_by": auth.get("auth_type"),
    }
