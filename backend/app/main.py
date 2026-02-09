import asyncio
import logging
import os
from datetime import datetime

from app.api.api_v1.api import api_router
from app.core.config import get_settings
from app.core.security import add_api_key, generate_api_key, require_admin_auth
from app.middleware.security import SecurityHeadersMiddleware
from app.services.imap_client import IMAPClient
from app.services.report_store import ReportStore
from fastapi import BackgroundTasks, Depends, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

# Set up logging
logger = logging.getLogger(__name__)

settings = get_settings()

# Global variables for background task management
background_task = None
last_check_time = None


async def scheduled_imap_polling():
    """Background task for periodically checking IMAP for new DMARC reports"""
    global last_check_time

    try:
        # How often to check for emails (in seconds)
        check_interval = 3600  # Default: 1 hour

        while True:
            logger.info("Starting scheduled IMAP polling for DMARC reports")

            try:
                # Create IMAP client and fetch reports
                imap_client = IMAPClient(delete_emails=False)
                results = imap_client.fetch_reports(days=9999)

                # Update last check time
                last_check_time = datetime.now()

                if results["success"]:
                    logger.info(
                        f"IMAP polling completed: {results['processed']} emails processed, "
                        f"{results['reports_found']} reports found"
                    )

                    # If new domains were found, log them
                    if results["new_domains"]:
                        logger.info(f"New domains found: {', '.join(results['new_domains'])}")

                else:
                    logger.error(f"IMAP polling failed: {results.get('error', 'Unknown error')}")

            except Exception as e:
                logger.error(f"Error in IMAP polling task: {str(e)}")

            # Wait for the next check interval
            await asyncio.sleep(check_interval)

    except asyncio.CancelledError:
        logger.info("IMAP polling task cancelled")


def create_app() -> FastAPI:
    """Create and configure the FastAPI application"""
    # Task management for background jobs
    background_task = None

    app = FastAPI(
        title=settings.PROJECT_NAME,
        openapi_url=f"{settings.API_V1_STR}/openapi.json",
        version="0.1.0",
    )

    # Add security headers middleware
    # Determine environment from settings or environment variable
    environment = os.getenv("ENVIRONMENT", "development")
    app.add_middleware(SecurityHeadersMiddleware, environment=environment)

    # Improved CORS configuration - restrict to specific methods and headers
    if settings.BACKEND_CORS_ORIGINS:
        app.add_middleware(
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
    app.include_router(api_router, prefix=settings.API_V1_STR)

    # Mount static files directory
    app.mount(
        "/static",
        StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")),
        name="static",
    )

    # Set up event handlers for startup and shutdown
    @app.on_event("startup")
    async def startup_event():
        """Initialize background tasks and security on application startup"""
        nonlocal background_task

        # Generate and provide admin API key
        api_key = generate_api_key()
        add_api_key(api_key)

        # Security: Log only last 8 characters for reference
        logger.warning(
            "=" * 80 + "\n"
            "IMPORTANT: Admin API Key Generated\n"
            f"API Key (last 8 chars): ...{api_key[-8:]}\n"
            "Full key stored securely in memory.\n"
            "For production, retrieve the key through secure configuration management.\n"
            "Use this key in the X-API-Key header for admin endpoints.\n"
            "=" * 80
        )

        # In development, also log the full key for convenience
        # This should be removed in production or controlled by environment variable
        if os.getenv("ENVIRONMENT", "development") == "development":
            logger.info(f"Development Mode - Full API Key: {api_key}")

        # Check if IMAP credentials are configured
        if all([settings.IMAP_SERVER, settings.IMAP_USERNAME, settings.IMAP_PASSWORD]):
            logger.info("Starting IMAP polling background task")
            background_task = asyncio.create_task(scheduled_imap_polling())
        else:
            logger.warning("IMAP credentials not fully configured, polling disabled")

    @app.on_event("shutdown")
    async def shutdown_event():
        """Clean up background tasks on application shutdown"""
        nonlocal background_task  # noqa: F824
        if background_task:
            logger.info("Cancelling IMAP polling background task")
            background_task.cancel()
            try:
                await background_task
            except asyncio.CancelledError:
                pass

    return app


app = create_app()

# Initialize Jinja2 templates
templates_dir = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=templates_dir)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse("index.html", {"request": request})


# Individual page routes
@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(request: Request):
    return templates.TemplateResponse(
        "dashboard.html", {"request": request, "app_name": settings.PROJECT_NAME}
    )


@app.get("/login", response_class=HTMLResponse)
async def login(request: Request):
    return templates.TemplateResponse(
        "login.html", {"request": request, "app_name": settings.PROJECT_NAME}
    )


@app.get("/setup", response_class=HTMLResponse)
async def setup(request: Request):
    return templates.TemplateResponse(
        "setup.html", {"request": request, "app_name": settings.PROJECT_NAME}
    )


@app.get("/domains", response_class=HTMLResponse)
async def domains(request: Request):
    return templates.TemplateResponse("domains.html", {"request": request})


@app.get("/domain/{domain_id}", response_class=HTMLResponse)
async def domain_details(request: Request, domain_id: str):
    """View detailed reports for a specific domain"""
    store = ReportStore.get_instance()
    domains = store.get_domains()

    if domain_id not in domains:
        # Domain not found, redirect to domains list
        return templates.TemplateResponse(
            "domains.html", {"request": request, "error": f"Domain {domain_id} not found"}
        )

    domain_summary = store.get_domain_summary(domain_id)

    return templates.TemplateResponse(
        "domain_details.html",
        {
            "request": request,
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
    return templates.TemplateResponse("reports.html", {"request": request})


@app.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request):
    return templates.TemplateResponse("settings.html", {"request": request})


@app.get("/upload", response_class=HTMLResponse)
async def upload_page(request: Request):
    return templates.TemplateResponse("upload.html", {"request": request})


# API endpoint to manually trigger IMAP polling
@app.post("/api/v1/admin/trigger-poll")
async def trigger_imap_poll(
    background_tasks: BackgroundTasks, auth: dict = Depends(require_admin_auth)
):
    """
    Manually trigger IMAP polling (admin only - requires authentication)

    Security: Requires either X-API-Key header or Bearer token
    """
    global last_check_time

    try:
        # Create IMAP client and fetch reports
        imap_client = IMAPClient(delete_emails=False)
        results = imap_client.fetch_reports(days=7)

        # Update last check time
        last_check_time = datetime.now()

        return {
            "success": results["success"],
            "timestamp": last_check_time.isoformat(),
            "processed": results["processed"],
            "reports_found": results["reports_found"],
            "new_domains": results["new_domains"],
            "authenticated_by": auth.get("auth_type"),
        }
    except Exception as e:
        logger.error(f"Error triggering IMAP poll: {str(e)}")
        return {
            "success": False,
            "error": "Failed to trigger IMAP poll. Check server logs for details.",
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
