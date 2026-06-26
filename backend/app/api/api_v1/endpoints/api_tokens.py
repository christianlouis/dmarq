"""Admin API token management endpoints."""

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
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
    require_workspace_permission,
)
from app.services.workspace_audit import record_workspace_audit_log
from app.services.workspaces import (
    assign_default_workspace_to_unscoped_rows,
    get_default_workspace,
    get_or_create_default_workspace,
)

router = APIRouter()


def _authorized_api_token_workspace(auth_context: Dict[str, Any], db: Session):
    """Authorize API-token management for the current workspace."""
    workspace = get_default_workspace(db) or get_or_create_default_workspace(db)
    require_workspace_permission(auth_context, PERMISSION_WORKSPACE_ADMIN, db, workspace)
    return assign_default_workspace_to_unscoped_rows(db)


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
):
    """List API token metadata without exposing raw secrets or hashes."""
    workspace = _authorized_api_token_workspace(_auth, db)
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
):
    """Create a scoped API token for read-only automation."""
    workspace = _authorized_api_token_workspace(_auth, db)
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
):
    """Revoke a scoped API token."""
    workspace = _authorized_api_token_workspace(_auth, db)
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
