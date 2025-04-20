from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from typing import Dict, Any
from datetime import datetime

from app.services.imap_client import IMAPClient

router = APIRouter()

@router.post("/test-connection")
async def test_imap_connection(
    server: str = None,
    port: int = 993,
    username: str = None,
    password: str = None
) -> Dict[str, Any]:
    """
    Test connection to an IMAP server
    """
    imap_client = IMAPClient(
        server=server,
        port=port,
        username=username,
        password=password
    )
    
    success, message = imap_client.test_connection()
    
    return {
        "success": success,
        "message": message,
        "timestamp": datetime.now().isoformat()
    }


@router.post("/fetch-reports")
async def fetch_imap_reports(
    background_tasks: BackgroundTasks,
    days: int = 7,
    delete_emails: bool = False
) -> Dict[str, Any]:
    """
    Fetch DMARC reports from the configured IMAP mailbox
    """
    imap_client = IMAPClient(delete_emails=delete_emails)
    
    # Run in background if it might take a while
    if days > 14:
        background_tasks.add_task(imap_client.fetch_reports, days)
        return {
            "success": True,
            "message": f"Background task started to fetch {days} days of reports",
            "timestamp": datetime.now().isoformat()
        }
    
    # Otherwise run immediately
    results = imap_client.fetch_reports(days=days)
    
    return {
        "success": results["success"],
        "processed_emails": results["processed"],
        "reports_found": results["reports_found"],
        "new_domains": results["new_domains"],
        "errors": results["errors"] if "errors" in results and results["errors"] else None,
        "timestamp": datetime.now().isoformat()
    }