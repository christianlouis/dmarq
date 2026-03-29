"""
Mail Sources API endpoints.

Provides CRUD operations for MailSource objects stored in the database, plus
a *test-connection* action that validates the supplied credentials without
persisting anything.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.mail_source import MailSource
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


class MailSourceResponse(MailSourceBase):
    """Response schema – exposes the stored row without exposing raw password."""

    id: int
    last_checked: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    # Mask the stored password in responses
    password: Optional[str] = None

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
