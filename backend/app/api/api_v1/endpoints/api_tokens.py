"""Admin API token management endpoints."""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.api_token import APIToken
from app.services.api_tokens import (
    PUBLIC_READ_SCOPES,
    create_api_token,
    revoke_api_token,
    token_to_dict,
)
from app.services.workspace_access import (
    PERMISSION_WORKSPACE_ADMIN,
    parse_selected_workspace_id,
    resolve_authorized_workspace,
)
from app.services.workspace_audit import record_workspace_audit_log

router = APIRouter()


def _authorized_api_token_workspace(
    auth_context: Dict[str, Any],
    db: Session,
    selected_workspace_id: Optional[int] = None,
):
    """Authorize API-token management for the current workspace."""
    return resolve_authorized_workspace(
        db,
        auth_context,
        PERMISSION_WORKSPACE_ADMIN,
        selected_workspace_id=selected_workspace_id,
    )


class APITokenCreateRequest(BaseModel):
    """Request body for creating a scoped API token."""

    name: str = Field(..., min_length=1, max_length=120)
    scopes: List[str] = Field(default_factory=lambda: sorted(PUBLIC_READ_SCOPES))


class APITokenResponse(BaseModel):
    """API-safe token metadata."""

    id: int
    workspace_id: Optional[int] = None
    name: str
    key_prefix: str
    scopes: List[str]
    active: bool
    created_at: str
    last_used_at: Optional[str] = None
    last_used_ip: Optional[str] = None
    usage_count: int
    revoked_at: Optional[str] = None


class APITokenCreateResponse(BaseModel):
    """New token response. The secret is returned once."""

    token: str
    metadata: APITokenResponse


class APITokenListResponse(BaseModel):
    """List of API token metadata rows."""

    tokens: List[APITokenResponse]
    available_scopes: List[str]


@router.get("", response_model=APITokenListResponse)
async def list_api_tokens(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
):
    """List API token metadata without exposing raw secrets or hashes."""
    workspace = _authorized_api_token_workspace(
        _auth,
        db,
        parse_selected_workspace_id(selected_workspace),
    )
    rows = (
        db.query(APIToken)
        .filter(APIToken.workspace_id == workspace.id)
        .order_by(APIToken.created_at.desc(), APIToken.id.desc())
        .all()
    )
    return APITokenListResponse(
        tokens=[APITokenResponse(**token_to_dict(row)) for row in rows],
        available_scopes=sorted(PUBLIC_READ_SCOPES),
    )


@router.post("", response_model=APITokenCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_public_api_token(
    payload: APITokenCreateRequest,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
):
    """Create a scoped API token for read-only automation."""
    workspace = _authorized_api_token_workspace(
        _auth,
        db,
        parse_selected_workspace_id(selected_workspace),
    )
    try:
        created = create_api_token(
            db,
            name=payload.name,
            scopes=payload.scopes,
            workspace_id=workspace.id,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    record_workspace_audit_log(
        db,
        workspace=workspace,
        action="api_token.created",
        entity_type="api_token",
        entity_id=created.token.id,
        entity_name=created.token.name,
        details={
            "scopes": sorted(created.token.scopes.split(",")),
            "key_prefix": created.token.key_prefix,
        },
        auth_context=_auth,
        request=request,
        commit=True,
    )
    return APITokenCreateResponse(
        token=created.secret,
        metadata=APITokenResponse(**token_to_dict(created.token)),
    )


@router.delete("/{token_id}", status_code=status.HTTP_200_OK)
async def revoke_public_api_token(
    token_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
):
    """Revoke a scoped API token."""
    workspace = _authorized_api_token_workspace(
        _auth,
        db,
        parse_selected_workspace_id(selected_workspace),
    )
    token = (
        db.query(APIToken)
        .filter(APIToken.id == token_id, APIToken.workspace_id == workspace.id)
        .first()
    )
    if not revoke_api_token(db, token_id, workspace_id=workspace.id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API token not found",
        )
    record_workspace_audit_log(
        db,
        workspace=workspace,
        action="api_token.revoked",
        entity_type="api_token",
        entity_id=token_id,
        entity_name=token.name if token else None,
        details={"key_prefix": token.key_prefix if token else None},
        auth_context=_auth,
        request=request,
        commit=True,
    )
    return {"revoked": True}
