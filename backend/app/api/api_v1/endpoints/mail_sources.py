"""
Mail Sources API endpoints.

Provides CRUD operations for MailSource objects stored in the database, plus
a *test-connection* action that validates the supplied credentials without
persisting anything.  Gmail API sources additionally have OAuth2 helper
endpoints (authorize-url, callback, fetch).
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.mail_source import MailSource
from app.services.gmail_client import GmailClient
from app.services.imap_client import IMAPClient

router = APIRouter()
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class MailSourceBase(BaseModel):
    """Fields shared by create and update payloads."""

    name: str
    method: str = "IMAP"  # IMAP | POP3 | GMAIL_API
    server: Optional[str] = None
    port: int = 993
    username: Optional[str] = None
    password: Optional[str] = None
    use_ssl: bool = True
    folder: str = "INBOX"
    polling_interval: int = 60
    enabled: bool = True
    # Gmail API OAuth2 fields (only relevant when method == GMAIL_API)
    gmail_client_id: Optional[str] = None
    gmail_client_secret: Optional[str] = None


class MailSourceCreate(MailSourceBase):
    """Payload for creating a new mail source."""


class MailSourceUpdate(BaseModel):
    """Payload for partial updates – all fields optional."""

    name: Optional[str] = None
    method: Optional[str] = None
    server: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    use_ssl: Optional[bool] = None
    folder: Optional[str] = None
    polling_interval: Optional[int] = None
    enabled: Optional[bool] = None
    gmail_client_id: Optional[str] = None
    gmail_client_secret: Optional[str] = None


class MailSourceResponse(MailSourceBase):
    """Response schema – exposes the stored row without exposing raw password."""

    id: int
    last_checked: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    # Mask the stored password in responses
    password: Optional[str] = None
    # Gmail: show the authorised email address but not tokens
    gmail_email: Optional[str] = None
    # Indicate whether OAuth tokens are present (without exposing them)
    gmail_connected: bool = False

    class Config:
        from_attributes = True


class TestConnectionRequest(BaseModel):
    """Credentials for an ad-hoc connection test (not persisted)."""

    server: Optional[str] = None
    port: int = 993
    username: Optional[str] = None
    password: Optional[str] = None
    ssl: bool = True
    method: str = "IMAP"


class GmailCallbackRequest(BaseModel):
    """Payload for the Gmail OAuth2 callback endpoint."""

    code: str
    redirect_uri: str


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _sanitize_for_log(value: object) -> str:
    """Remove CR/LF characters from a value to prevent log injection attacks."""
    return str(value).replace("\r", "").replace("\n", " ")


def _get_source_or_404(source_id: int, db: Session) -> MailSource:
    source = db.query(MailSource).filter(MailSource.id == source_id).first()
    if source is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mail source {source_id} not found",
        )
    return source


def _source_to_response(source: MailSource) -> MailSourceResponse:
    """Convert ORM row to response schema, masking the stored password."""
    return MailSourceResponse(
        id=source.id,
        name=source.name,
        method=source.method,
        server=source.server,
        port=source.port or 993,
        username=source.username,
        password="**redacted**" if source.password else None,
        use_ssl=source.use_ssl if source.use_ssl is not None else True,
        folder=source.folder or "INBOX",
        polling_interval=source.polling_interval or 60,
        enabled=source.enabled if source.enabled is not None else True,
        last_checked=source.last_checked,
        created_at=source.created_at,
        updated_at=source.updated_at,
        gmail_client_id=source.gmail_client_id,
        gmail_client_secret="**redacted**" if source.gmail_client_secret else None,
        gmail_email=source.gmail_email,
        gmail_connected=bool(source.gmail_access_token),
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("", response_model=List[MailSourceResponse])
async def list_mail_sources(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> List[MailSourceResponse]:
    """Return all configured mail sources (passwords redacted)."""
    sources = db.query(MailSource).order_by(MailSource.id).all()
    return [_source_to_response(s) for s in sources]


@router.post("", response_model=MailSourceResponse, status_code=status.HTTP_201_CREATED)
async def create_mail_source(
    payload: MailSourceCreate,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> MailSourceResponse:
    """Create a new mail source."""
    source = MailSource(
        name=payload.name,
        method=payload.method.upper(),
        server=payload.server,
        port=payload.port,
        username=payload.username,
        password=payload.password,
        use_ssl=payload.use_ssl,
        folder=payload.folder,
        polling_interval=payload.polling_interval,
        enabled=payload.enabled,
        gmail_client_id=payload.gmail_client_id,
        gmail_client_secret=payload.gmail_client_secret,
    )
    db.add(source)
    db.commit()
    db.refresh(source)
    logger.info(
        "Created mail source id=%d name=%r method=%r", source.id, source.name, source.method
    )
    return _source_to_response(source)


@router.get("/{source_id}", response_model=MailSourceResponse)
async def get_mail_source(
    source_id: int,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> MailSourceResponse:
    """Return a single mail source by ID (password redacted)."""
    source = _get_source_or_404(source_id, db)
    return _source_to_response(source)


@router.put("/{source_id}", response_model=MailSourceResponse)
async def update_mail_source(
    source_id: int,
    payload: MailSourceUpdate,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> MailSourceResponse:
    """Update one or more fields of an existing mail source."""
    source = _get_source_or_404(source_id, db)

    update_data = payload.model_dump(exclude_unset=True)
    if "method" in update_data and update_data["method"]:
        update_data["method"] = update_data["method"].upper()

    for field, value in update_data.items():
        setattr(source, field, value)

    source.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(source)
    logger.info("Updated mail source id=%d", source.id)
    return _source_to_response(source)


@router.delete("/{source_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_mail_source(
    source_id: int,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> None:
    """Delete a mail source permanently."""
    source = _get_source_or_404(source_id, db)
    db.delete(source)
    db.commit()
    logger.info("Deleted mail source id=%s", _sanitize_for_log(source_id))


@router.post("/{source_id}/toggle", response_model=MailSourceResponse)
async def toggle_mail_source(
    source_id: int,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> MailSourceResponse:
    """Toggle the *enabled* flag of a mail source."""
    source = _get_source_or_404(source_id, db)
    source.enabled = not source.enabled
    source.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(source)
    return _source_to_response(source)


@router.post("/{source_id}/test", response_model=Dict[str, Any])
async def test_stored_mail_source(
    source_id: int,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> Dict[str, Any]:
    """Test the connection for an already-stored mail source using its saved credentials."""
    source = _get_source_or_404(source_id, db)

    if source.method == "GMAIL_API":
        if not source.gmail_access_token:
            return {
                "success": False,
                "message": "Gmail API source is not yet authorised. "
                "Use the 'Connect Gmail' button to complete OAuth2 authorisation.",
                "timestamp": datetime.now().isoformat(),
            }
        try:
            gmail_client = GmailClient(
                client_id=source.gmail_client_id or "",
                client_secret=source.gmail_client_secret or "",
                access_token=source.gmail_access_token,
                refresh_token=source.gmail_refresh_token or "",
            )
            # Attempt to list one message to verify the credentials work
            service = gmail_client._build_service()  # pylint: disable=protected-access
            service.users().getProfile(userId="me").execute()
            source.last_checked = datetime.utcnow()
            db.commit()
            return {
                "success": True,
                "message": f"Gmail API credentials are valid (account: {source.gmail_email or 'unknown'}).",
                "timestamp": datetime.now().isoformat(),
            }
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.error(
                "Gmail API test failed for source id=%d: %s",
                int(source_id),
                _sanitize_for_log(exc),
            )
            return {
                "success": False,
                "message": "Gmail API test failed. Check server logs for details.",
                "timestamp": datetime.now().isoformat(),
            }

    if source.method != "IMAP":
        return {
            "success": False,
            "message": f"Connection testing for method '{source.method}' is not yet implemented.",
            "timestamp": datetime.now().isoformat(),
        }

    imap_client = IMAPClient(
        server=source.server,
        port=source.port or 993,
        username=source.username,
        password=source.password,
    )
    success, message, stats = imap_client.test_connection()

    if success:
        source.last_checked = datetime.utcnow()
        db.commit()

    return {
        "success": success,
        "message": message,
        "message_count": stats.get("message_count", 0),
        "unread_count": stats.get("unread_count", 0),
        "dmarc_count": stats.get("dmarc_count", 0),
        "available_mailboxes": stats.get("available_mailboxes", []),
        "timestamp": datetime.now().isoformat(),
    }


@router.post("/test-connection", response_model=Dict[str, Any])
async def test_connection_adhoc(
    request: TestConnectionRequest,
    _auth: dict = Depends(require_admin_auth),
) -> Dict[str, Any]:
    """
    Test a connection using ad-hoc credentials (not stored in the database).

    Useful when filling out the *add/edit mail source* form before saving.
    """
    method = request.method.upper()

    if method != "IMAP":
        return {
            "success": False,
            "message": f"Connection testing for method '{method}' is not yet implemented.",
            "timestamp": datetime.now().isoformat(),
        }

    imap_client = IMAPClient(
        server=request.server,
        port=request.port,
        username=request.username,
        password=request.password,
    )
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


# ---------------------------------------------------------------------------
# Gmail API OAuth2 routes
# ---------------------------------------------------------------------------


@router.get("/{source_id}/gmail/authorize-url", response_model=Dict[str, Any])
async def gmail_authorize_url(
    source_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> Dict[str, Any]:
    """
    Return a Google OAuth2 authorization URL for the given GMAIL_API source.

    The frontend should redirect the user to this URL.  After the user
    grants access Google redirects back to
    ``<origin>/mail-sources/<id>/gmail/callback`` with a ``code`` parameter.
    """
    source = _get_source_or_404(source_id, db)

    if source.method != "GMAIL_API":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This endpoint is only available for GMAIL_API sources.",
        )
    if not source.gmail_client_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="gmail_client_id is not configured for this source.",
        )

    # Build a redirect_uri that points back to this server's callback endpoint
    base_url = str(request.base_url).rstrip("/")
    redirect_uri = f"{base_url}/api/v1/mail-sources/{source_id}/gmail/callback"

    auth_url = GmailClient.build_authorization_url(
        client_id=source.gmail_client_id,
        redirect_uri=redirect_uri,
        state=str(source_id),
    )
    return {
        "authorization_url": auth_url,
        "redirect_uri": redirect_uri,
    }


@router.get("/{source_id}/gmail/callback")
async def gmail_oauth_callback(
    source_id: int,
    request: Request,
    db: Session = Depends(get_db),
) -> Any:
    """
    Handle the Google OAuth2 redirect after the user grants Gmail access.

    Exchanges the authorization ``code`` query parameter for access/refresh
    tokens and stores them on the MailSource row.  This endpoint is called
    directly by Google's redirect, so it does not require the usual API key
    authentication; it is protected instead by the state/code being
    single-use and bound to the source_id in the URL.
    """
    from fastapi.responses import HTMLResponse

    code = request.query_params.get("code")
    error = request.query_params.get("error")

    if error or not code:
        html = (
            "<html><body><p>Gmail authorisation failed: "
            f"{error or 'no code received'}. "
            "You may close this window.</p></body></html>"
        )
        return HTMLResponse(content=html, status_code=400)

    source = db.query(MailSource).filter(MailSource.id == source_id).first()
    if source is None or source.method != "GMAIL_API":
        return HTMLResponse(
            content="<html><body><p>Mail source not found.</p></body></html>",
            status_code=404,
        )

    base_url = str(request.base_url).rstrip("/")
    redirect_uri = f"{base_url}/api/v1/mail-sources/{source_id}/gmail/callback"

    try:
        token_data = GmailClient.exchange_code_for_tokens(
            client_id=source.gmail_client_id or "",
            client_secret=source.gmail_client_secret or "",
            code=code,
            redirect_uri=redirect_uri,
        )
    except ValueError as exc:
        logger.error(
            "Gmail token exchange error for source id=%d: %s",
            int(source_id),
            _sanitize_for_log(exc),
        )
        html = (
            "<html><body><p>Token exchange failed. "
            "Please close this window and try again.</p></body></html>"
        )
        return HTMLResponse(content=html, status_code=400)

    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")

    if not access_token:
        return HTMLResponse(
            content="<html><body><p>No access token returned by Google.</p></body></html>",
            status_code=400,
        )

    gmail_email = GmailClient.get_gmail_email(access_token)

    source.gmail_access_token = access_token
    if refresh_token:
        source.gmail_refresh_token = refresh_token
    if gmail_email:
        source.gmail_email = gmail_email
    source.updated_at = datetime.utcnow()
    db.commit()

    logger.info(
        "Gmail OAuth2 authorisation complete for source id=%d (account=%s)",
        int(source_id),
        _sanitize_for_log(gmail_email or "unknown"),
    )

    html = (
        "<html><body>"
        "<p>✅ Gmail account connected successfully"
        f"{(' (' + gmail_email + ')') if gmail_email else ''}. "
        "You may close this window.</p>"
        "<script>window.close();</script>"
        "</body></html>"
    )
    return HTMLResponse(content=html)


@router.post("/{source_id}/gmail/callback", response_model=MailSourceResponse)
async def gmail_oauth_callback_post(
    source_id: int,
    payload: GmailCallbackRequest,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> MailSourceResponse:
    """
    Exchange an OAuth2 authorization code for tokens (JSON / programmatic flow).

    This POST variant is for clients that handle the OAuth2 redirect
    themselves and post the code here as JSON.  Requires the standard
    admin authentication.
    """
    source = _get_source_or_404(source_id, db)

    if source.method != "GMAIL_API":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This endpoint is only available for GMAIL_API sources.",
        )

    try:
        token_data = GmailClient.exchange_code_for_tokens(
            client_id=source.gmail_client_id or "",
            client_secret=source.gmail_client_secret or "",
            code=payload.code,
            redirect_uri=payload.redirect_uri,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        ) from exc

    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")

    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google did not return an access token.",
        )

    gmail_email = GmailClient.get_gmail_email(access_token)

    source.gmail_access_token = access_token
    if refresh_token:
        source.gmail_refresh_token = refresh_token
    if gmail_email:
        source.gmail_email = gmail_email
    source.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(source)

    logger.info(
        "Gmail OAuth2 tokens saved for source id=%d (account=%s)",
        int(source_id),
        _sanitize_for_log(gmail_email or "unknown"),
    )
    return _source_to_response(source)


@router.post("/{source_id}/gmail/fetch", response_model=Dict[str, Any])
async def gmail_fetch_reports(
    source_id: int,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> Dict[str, Any]:
    """
    Manually trigger a Gmail DMARC report fetch for the given source.

    Searches Gmail for emails matching the DMARC report heuristic, ingests
    any attachments not yet seen, and returns a summary.
    """
    source = _get_source_or_404(source_id, db)

    if source.method != "GMAIL_API":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This endpoint is only available for GMAIL_API sources.",
        )
    if not source.gmail_access_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Gmail account not yet authorised. Complete OAuth2 flow first.",
        )

    already = GmailClient.load_ingested_ids(source.gmail_ingested_ids)
    client = GmailClient(
        client_id=source.gmail_client_id or "",
        client_secret=source.gmail_client_secret or "",
        access_token=source.gmail_access_token,
        refresh_token=source.gmail_refresh_token or "",
        already_ingested_ids=already,
    )

    results = client.fetch_reports()

    # Persist updated ingested IDs and any refreshed tokens
    if results.get("new_ingested_ids"):
        all_ids = list(dict.fromkeys(already + results["new_ingested_ids"]))
        source.gmail_ingested_ids = GmailClient.dump_ingested_ids(all_ids)

    refreshed = client.get_refreshed_tokens()
    if refreshed:
        source.gmail_access_token = refreshed["access_token"]
        if "refresh_token" in refreshed:
            source.gmail_refresh_token = refreshed["refresh_token"]

    source.last_checked = datetime.utcnow()
    db.commit()

    logger.info(
        "Gmail fetch for source id=%d: processed=%d reports_found=%d",
        int(source_id),
        int(results.get("processed", 0)),
        int(results.get("reports_found", 0)),
    )

    for err in results.get("errors", []):
        logger.warning(
            "Gmail fetch warning for source id=%d: %s",
            int(source_id),
            _sanitize_for_log(err),
        )

    return {
        "success": bool(results.get("success", False)),
        "processed": int(results.get("processed", 0)),
        "reports_found": int(results.get("reports_found", 0)),
        "new_domains": [str(d) for d in results.get("new_domains", [])],
        "error_count": len(results.get("errors", [])),
        "timestamp": datetime.now().isoformat(),
    }


@router.delete("/{source_id}/gmail/connection", status_code=status.HTTP_204_NO_CONTENT)
async def gmail_disconnect(
    source_id: int,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> None:
    """Revoke / clear the stored Gmail OAuth2 tokens for this source."""
    source = _get_source_or_404(source_id, db)

    if source.method != "GMAIL_API":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This endpoint is only available for GMAIL_API sources.",
        )

    source.gmail_access_token = None
    source.gmail_refresh_token = None
    source.gmail_email = None
    source.updated_at = datetime.utcnow()
    db.commit()
    logger.info("Gmail tokens cleared for source id=%d", int(source_id))
