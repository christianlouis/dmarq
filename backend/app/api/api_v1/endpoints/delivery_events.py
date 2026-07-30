"""Privacy-minimized DSN and provider delivery event endpoints."""

from datetime import datetime
from typing import Literal, Optional

from fastapi import APIRouter, Depends, File, Header, HTTPException, Query, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_admin_auth, require_api_token_scope
from app.models.workspace import Workspace
from app.services.api_tokens import DELIVERY_EVENTS_WRITE_SCOPE
from app.services.delivery_events import (
    ingest_dsn_email,
    ingest_provider_event,
    list_delivery_events,
)
from app.services.dsn_parser import MAX_DSN_BYTES, DSNParseError
from app.services.workspace_access import (
    PERMISSION_REPORTS_READ,
    PERMISSION_REPORTS_WRITE,
    parse_selected_workspace_id,
    resolve_authorized_workspace,
)

router = APIRouter()


class ProviderDeliveryEvent(BaseModel):
    """Stable provider-neutral write contract; raw message bodies are not accepted."""

    schema_version: Literal["dmarq.provider_delivery_event.v1"]
    provider: str = Field(min_length=1, max_length=80)
    event_id: str = Field(min_length=1, max_length=160)
    event: Literal[
        "accepted",
        "queued",
        "delivered",
        "deferred",
        "bounced",
        "blocked",
        "dropped",
        "spam_complaint",
        "unsubscribe",
        "unknown",
    ]
    occurred_at: datetime
    domain: Optional[str] = Field(default=None, max_length=255)
    recipient: Optional[str] = Field(default=None, max_length=500)
    message_id: Optional[str] = Field(default=None, max_length=500)
    envelope_id: Optional[str] = Field(default=None, max_length=500)
    original_event: Optional[str] = Field(default=None, max_length=120)
    status_code: Optional[str] = Field(default=None, max_length=32)
    diagnostic_type: Optional[str] = Field(default=None, max_length=80)
    diagnostic_text: Optional[str] = Field(default=None, max_length=1500)
    remote_mta: Optional[str] = Field(default=None, max_length=255)
    reason_code: Optional[str] = Field(default=None, max_length=120)
    provider_semantics: Optional[str] = Field(default=None, max_length=1000)


def _token_workspace(db: Session, auth: dict) -> Workspace:
    workspace_id = int(auth.get("workspace_id") or 0)
    workspace = (
        db.query(Workspace).filter(Workspace.id == workspace_id, Workspace.active.is_(True)).first()
    )
    if workspace is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Token workspace not found"
        )
    return workspace


@router.post("/provider", status_code=status.HTTP_202_ACCEPTED)
async def receive_provider_delivery_event(
    payload: ProviderDeliveryEvent,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_api_token_scope(DELIVERY_EVENTS_WRITE_SCOPE)),
):
    """Accept one authenticated, replay-bounded provider delivery event."""
    workspace = _token_workspace(db, _auth)
    try:
        event, created = ingest_provider_event(
            db, workspace=workspace, payload=payload.model_dump()
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc
    return {"accepted": created, "duplicate": not created, "event": event}


@router.post("/dsn", status_code=status.HTTP_202_ACCEPTED)
async def upload_delivery_status_notification(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
):
    """Upload one RFC 822 DSN for a bounded, body-free diagnostic import."""
    workspace = resolve_authorized_workspace(
        db,
        _auth,
        PERMISSION_REPORTS_WRITE,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    raw = await file.read(MAX_DSN_BYTES + 1)
    if len(raw) > MAX_DSN_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE, detail="DSN exceeds 5 MiB"
        )
    try:
        return ingest_dsn_email(
            db,
            raw,
            workspace_id=workspace.id,
            source_system="manual_dsn_upload",
        )
    except DSNParseError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)
        ) from exc


@router.get("")
async def get_delivery_events(
    domain: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
):
    """List only privacy-minimized delivery evidence in the selected workspace."""
    workspace = resolve_authorized_workspace(
        db,
        _auth,
        PERMISSION_REPORTS_READ,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    return {"events": list_delivery_events(db, workspace=workspace, domain=domain, limit=limit)}
