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
    password: str = None,
    ssl: bool = True
) -> Dict[str, Any]:
    """
    Test connection to an IMAP server and gather mailbox statistics
    """
    imap_client = IMAPClient(
        server=server,
        port=port,
        username=username,
        password=password
    )
    
    success, message, stats = imap_client.test_connection()
    
    return {
        "success": success,
        "message": message,
        "message_count": stats.get("message_count", 0),
        "unread_count": stats.get("unread_count", 0),
        "dmarc_count": stats.get("dmarc_count", 0),
        "available_mailboxes": stats.get("available_mailboxes", []),
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


@router.get("/status")
async def get_imap_status() -> Dict[str, Any]:
    """
    Get the current status of IMAP polling background processes
    """
    # In a real implementation this would check a persistent store
    # or a global variable tracking the status of background tasks
    # For now, returning mock data as this is MVP
    
    # Get the last check time if available
    last_check_time = None
    try:
        # In a production app, this would be stored in database
        # For MVP, using a simple file-based approach
        import os
        status_file = os.path.join(os.path.dirname(__file__), "../../../../../tmp/imap_last_check.txt")
        if os.path.exists(status_file):
            with open(status_file, "r") as f:
                last_check_time = f.read().strip()
    except:
        pass
    
    # If status file doesn't exist, create the directory
    try:
        os.makedirs(os.path.dirname(os.path.join(os.path.dirname(__file__), "../../../../../tmp")), exist_ok=True)
    except:
        pass
    
    # For demonstration purposes, update the last check time to now
    # In a real app, this would be updated by the background process
    try:
        with open(os.path.join(os.path.dirname(__file__), "../../../../../tmp/imap_last_check.txt"), "w") as f:
            now = datetime.now().isoformat()
            f.write(now)
            # If there was no previous check time, set it to now
            if not last_check_time:
                last_check_time = now
    except:
        pass
    
    # Return the status
    return {
        "is_running": True,  # In a real app, check if the background task is running
        "last_check": last_check_time,
        "next_check": None,  # In production, this would be calculated based on polling interval
        "messages_processed": 0,  # In production, this would track actual messages processed
        "reports_found": 0,   # In production, this would track reports found
        "timestamp": datetime.now().isoformat()
    }