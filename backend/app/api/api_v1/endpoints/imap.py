import logging
from datetime import datetime
from typing import Any, Dict

from app.core.security import require_admin_auth
from app.services.imap_client import IMAPClient
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException

router = APIRouter()
logger = logging.getLogger(__name__)


@router.post("/test-connection")
async def test_imap_connection(
    auth: dict = Depends(require_admin_auth),
    server: str = None,
    port: int = 993,
    username: str = None,
    password: str = None,
    ssl: bool = True,
) -> Dict[str, Any]:
    """
    Test connection to an IMAP server and gather mailbox statistics

    Security: Requires authentication (X-API-Key or Bearer token)
    Note: Credentials should be passed in request body, not query params
    """
    # Security: Don't accept credentials in query parameters (they get logged)
    if any([server, username, password]):
        logger.warning("IMAP credentials passed as query parameters - this is insecure")
        raise HTTPException(
            status_code=400,
            detail="Credentials should be passed in request body, not query parameters",
        )

    imap_client = IMAPClient(server=server, port=port, username=username, password=password)

    success, message, stats = imap_client.test_connection()

    return {
        "success": success,
        "message": message,
        "message_count": stats.get("message_count", 0),
        "unread_count": stats.get("unread_count", 0),
        "dmarc_count": stats.get("dmarc_count", 0),
        "available_mailboxes": stats.get("available_mailboxes", []),
        "timestamp": datetime.now().isoformat(),
    }


@router.post("/fetch-reports")
async def fetch_imap_reports(
    background_tasks: BackgroundTasks,
    auth: dict = Depends(require_admin_auth),
    days: int = 7,
    delete_emails: bool = False,
) -> Dict[str, Any]:
    """
    Fetch DMARC reports from the configured IMAP mailbox

    Security: Requires authentication (X-API-Key or Bearer token)
    """
    # Security: Validate parameters
    if days < 1 or days > 365:
        raise HTTPException(status_code=400, detail="Days parameter must be between 1 and 365")

    imap_client = IMAPClient(delete_emails=delete_emails)

    # Run in background if it might take a while
    if days > 14:
        background_tasks.add_task(imap_client.fetch_reports, days)
        return {
            "success": True,
            "message": f"Background task started to fetch {days} days of reports",
            "timestamp": datetime.now().isoformat(),
        }

    # Otherwise run immediately
    try:
        results = imap_client.fetch_reports(days=days)

        return {
            "success": results["success"],
            "processed_emails": results["processed"],
            "reports_found": results["reports_found"],
            "new_domains": results["new_domains"],
            "errors": results["errors"] if "errors" in results and results["errors"] else None,
            "timestamp": datetime.now().isoformat(),
        }
    except Exception as e:
        logger.error(f"Error fetching IMAP reports: {str(e)}")
        raise HTTPException(
            status_code=500, detail="Failed to fetch reports. Check server logs for details."
        )


@router.get("/status")
async def get_imap_status(auth: dict = Depends(require_admin_auth)) -> Dict[str, Any]:
    """
    Get the current status of IMAP polling background processes

    Security: Requires authentication (X-API-Key or Bearer token)
    """
    # In a real implementation this would check a persistent store
    # or a global variable tracking the status of background tasks
    # For now, returning simplified status

    return {
        "is_running": True,  # In a real app, check if the background task is running
        "last_check": None,  # In production, track actual last check time
        "next_check": None,  # In production, calculate based on polling interval
        "messages_processed": 0,  # In production, track actual messages processed
        "reports_found": 0,  # In production, track reports found
        "timestamp": datetime.now().isoformat(),
    }
