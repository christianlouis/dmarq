"""Admin API token management endpoints."""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, status
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

router = APIRouter()


class APITokenCreateRequest(BaseModel):
    """Request body for creating a scoped API token."""

    name: str = Field(..., min_length=1, max_length=120)
    scopes: List[str] = Field(default_factory=lambda: sorted(PUBLIC_READ_SCOPES))


class APITokenResponse(BaseModel):
    """API-safe token metadata."""

    id: int
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
    rows = db.query(APIToken).order_by(APIToken.created_at.desc(), APIToken.id.desc()).all()
    return APITokenListResponse(
        tokens=[APITokenResponse(**token_to_dict(row)) for row in rows],
        available_scopes=sorted(PUBLIC_READ_SCOPES),
    )


@router.post("", response_model=APITokenCreateResponse, status_code=status.HTTP_201_CREATED)
async def create_public_api_token(
    payload: APITokenCreateRequest,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Create a scoped API token for read-only automation."""
    try:
        created = create_api_token(db, name=payload.name, scopes=payload.scopes)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=str(exc),
        ) from exc
    return APITokenCreateResponse(
        token=created.secret,
        metadata=APITokenResponse(**token_to_dict(created.token)),
    )


@router.delete("/{token_id}", status_code=status.HTTP_200_OK)
async def revoke_public_api_token(
    token_id: int,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Revoke a scoped API token."""
    if not revoke_api_token(db, token_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="API token not found",
        )
    return {"revoked": True}
