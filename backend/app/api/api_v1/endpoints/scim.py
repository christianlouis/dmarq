"""SCIM 2.0 user provisioning endpoints."""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_api_token_any_scope
from app.models.organization import OrganizationMembership
from app.models.user import User
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceMembership
from app.services.api_tokens import SCIM_READ_SCOPE, SCIM_WRITE_SCOPE
from app.services.workspace_audit import record_workspace_audit_log

router = APIRouter()

SCIM_USER_SCHEMA = "urn:ietf:params:scim:schemas:core:2.0:User"
SCIM_LIST_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
SCIM_PATCH_SCHEMA = "urn:ietf:params:scim:api:messages:2.0:PatchOp"

WORKSPACE_ROLE_ALIASES = {
    "workspace_owner": "workspace_owner",
    "owner": "workspace_owner",
    "admin": "workspace_owner",
    "domain_admin": "domain_admin",
    "domain-admin": "domain_admin",
    "operator": "operator",
    "analyst": "analyst",
    "auditor": "auditor",
}

ORGANIZATION_ROLE_ALIASES = {
    "organization_owner": "organization_owner",
    "organization_admin": "organization_admin",
    "billing_admin": "billing_admin",
    "organization_auditor": "organization_auditor",
}


def _scim_auth(scopes: List[str]):
    return Depends(require_api_token_any_scope(scopes, detail_scope="scim:read or scim:write"))


class ScimName(BaseModel):
    """SCIM name payload."""

    formatted: Optional[str] = Field(default=None, max_length=255)
    givenName: Optional[str] = Field(default=None, max_length=120)
    familyName: Optional[str] = Field(default=None, max_length=120)


class ScimEmail(BaseModel):
    """SCIM email payload."""

    value: EmailStr
    primary: bool = False


class ScimGroupRef(BaseModel):
    """SCIM group reference used for role mapping."""

    value: Optional[str] = Field(default=None, max_length=120)
    display: Optional[str] = Field(default=None, max_length=120)


class ScimUserWrite(BaseModel):
    """SCIM user create/replace payload."""

    schemas: List[str] = Field(default_factory=lambda: [SCIM_USER_SCHEMA])
    userName: Optional[EmailStr] = None
    externalId: Optional[str] = Field(default=None, max_length=255)
    active: bool = True
    name: Optional[ScimName] = None
    emails: List[ScimEmail] = Field(default_factory=list)
    groups: List[ScimGroupRef] = Field(default_factory=list)


class ScimPatchOperation(BaseModel):
    """Single SCIM patch operation."""

    op: str
    path: Optional[str] = None
    value: Any = None


class ScimPatchRequest(BaseModel):
    """SCIM patch request."""

    schemas: List[str] = Field(default_factory=lambda: [SCIM_PATCH_SCHEMA])
    Operations: List[ScimPatchOperation] = Field(default_factory=list)


def _workspace_for_token(db: Session, auth_context: Dict[str, Any]) -> Workspace:
    workspace_id = (auth_context or {}).get("workspace_id")
    if workspace_id is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="SCIM token must be bound to a workspace",
        )
    try:
        workspace_id = int(workspace_id)
    except (TypeError, ValueError) as exc:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="SCIM token is not bound to a valid workspace",
        ) from exc
    workspace = (
        db.query(Workspace).filter(Workspace.id == workspace_id, Workspace.active.is_(True)).first()
    )
    if workspace is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Workspace not found")
    return workspace


def _primary_email(payload: ScimUserWrite) -> str:
    if payload.userName:
        return str(payload.userName).strip().lower()
    primary = next((item for item in payload.emails if item.primary), None)
    email = primary or (payload.emails[0] if payload.emails else None)
    if email is None:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="SCIM userName or at least one email is required",
        )
    return str(email.value).strip().lower()


def _display_name(payload: ScimUserWrite) -> Optional[str]:
    if not payload.name:
        return None
    if payload.name.formatted:
        return payload.name.formatted.strip()
    parts = [payload.name.givenName, payload.name.familyName]
    joined = " ".join(part.strip() for part in parts if part and part.strip())
    return joined or None


def _group_values(groups: List[ScimGroupRef]) -> List[str]:
    values: List[str] = []
    for group in groups:
        for value in (group.value, group.display):
            if value and value.strip():
                values.append(value.strip().lower())
    return values


def _role_from_groups(groups: List[ScimGroupRef]) -> Tuple[str, Optional[str]]:
    workspace_role = "analyst"
    organization_role: Optional[str] = None
    for raw in _group_values(groups):
        normalized = raw.replace(" ", "_")
        if normalized.startswith("workspace:"):
            normalized = normalized.split(":", 1)[1]
        if normalized.startswith("org:") or normalized.startswith("organization:"):
            candidate = normalized.split(":", 1)[1]
            organization_role = ORGANIZATION_ROLE_ALIASES.get(candidate, organization_role)
            continue
        workspace_role = WORKSPACE_ROLE_ALIASES.get(normalized, workspace_role)
        organization_role = ORGANIZATION_ROLE_ALIASES.get(normalized, organization_role)
    return workspace_role, organization_role


def _find_user(
    db: Session,
    *,
    workspace: Workspace,
    user_id: Optional[int] = None,
    payload: Optional[ScimUserWrite] = None,
):
    query = (
        db.query(User)
        .join(WorkspaceMembership, WorkspaceMembership.user_id == User.id)
        .filter(WorkspaceMembership.workspace_id == workspace.id)
    )
    if user_id is not None:
        return query.filter(User.id == user_id).first()
    assert payload is not None
    external_id = (payload.externalId or "").strip() or None
    email = _primary_email(payload)
    if external_id:
        user = query.filter(User.logto_id == external_id).first()
        if user is not None:
            return user
    return query.filter(User.email == email).first()


def _scim_active_from_memberships(user: User) -> bool:
    memberships = getattr(user, "_scim_memberships", None)
    if memberships is None:
        return bool(user.is_active)
    return any(membership.active for membership in memberships)


def _coerce_scim_bool(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        normalized = value.strip().lower()
        if normalized in {"true", "1", "yes"}:
            return True
        if normalized in {"false", "0", "no"}:
            return False
    if isinstance(value, int) and value in {0, 1}:
        return bool(value)
    raise HTTPException(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        detail="SCIM active value must be a boolean",
    )


def _upsert_memberships(
    db: Session,
    *,
    workspace: Workspace,
    user: User,
    workspace_role: str,
    organization_role: Optional[str],
    active: bool,
) -> None:
    membership = (
        db.query(WorkspaceMembership)
        .filter(
            WorkspaceMembership.workspace_id == workspace.id,
            WorkspaceMembership.user_id == user.id,
        )
        .first()
    )
    if membership is None:
        db.add(
            WorkspaceMembership(
                workspace_id=workspace.id,
                user_id=user.id,
                role=workspace_role,
                active=active,
            )
        )
    else:
        membership.role = workspace_role
        membership.active = active

    if workspace.organization_id is None or organization_role is None:
        return
    organization_membership = (
        db.query(OrganizationMembership)
        .filter(
            OrganizationMembership.organization_id == workspace.organization_id,
            OrganizationMembership.user_id == user.id,
        )
        .first()
    )
    if organization_membership is None:
        db.add(
            OrganizationMembership(
                organization_id=workspace.organization_id,
                user_id=user.id,
                role=organization_role,
                active=active,
            )
        )
    else:
        organization_membership.role = organization_role
        organization_membership.active = active


def _scim_user_to_dict(user: User, workspace: Workspace) -> Dict[str, Any]:
    memberships = (
        db_memberships
        if (db_memberships := getattr(user, "_scim_memberships", None)) is not None
        else []
    )
    groups = [
        {"value": membership.role, "display": membership.role}
        for membership in memberships
        if membership.active
    ]
    return {
        "schemas": [SCIM_USER_SCHEMA],
        "id": str(user.id),
        "externalId": user.logto_id,
        "userName": user.email,
        "active": _scim_active_from_memberships(user),
        "name": {"formatted": user.full_name},
        "emails": [{"value": user.email, "primary": True}],
        "groups": groups,
        "meta": {
            "resourceType": "User",
            "location": f"/api/v1/scim/v2/Users/{user.id}",
            "workspaceId": workspace.id,
        },
    }


def _load_workspace_memberships(db: Session, workspace: Workspace, users: List[User]) -> None:
    user_ids = [user.id for user in users]
    if not user_ids:
        return
    rows = (
        db.query(WorkspaceMembership)
        .filter(
            WorkspaceMembership.workspace_id == workspace.id,
            WorkspaceMembership.user_id.in_(user_ids),
        )
        .all()
    )
    by_user: Dict[int, List[WorkspaceMembership]] = {user.id: [] for user in users}
    for row in rows:
        by_user.setdefault(row.user_id, []).append(row)
    for user in users:
        user._scim_memberships = by_user.get(user.id, [])


def _upsert_scim_user(
    db: Session,
    *,
    workspace: Workspace,
    payload: ScimUserWrite,
    request: Request,
    auth_context: Dict[str, Any],
    existing_user: Optional[User] = None,
) -> Tuple[User, bool]:
    email = _primary_email(payload)
    user = existing_user or _find_user(db, workspace=workspace, payload=payload)
    created = user is None
    if user is None:
        user = User(email=email, is_superuser=False, is_active=True)
        db.add(user)
    user.email = email
    if payload.externalId:
        user.logto_id = payload.externalId.strip()
    display_name = _display_name(payload)
    if display_name:
        user.full_name = display_name
    user.is_verified = True
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="SCIM user conflicts with an existing identity",
        ) from exc
    workspace_role, organization_role = _role_from_groups(payload.groups)
    _upsert_memberships(
        db,
        workspace=workspace,
        user=user,
        workspace_role=workspace_role,
        organization_role=organization_role,
        active=payload.active,
    )
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="SCIM user conflicts with an existing identity",
        ) from exc
    record_workspace_audit_log(
        db,
        workspace=workspace,
        action="scim.user_created" if created else "scim.user_updated",
        entity_type="user",
        entity_id=user.id,
        entity_name=user.email,
        details={
            "external_id": bool(payload.externalId),
            "active": payload.active,
            "workspace_role": workspace_role,
            "organization_role": organization_role,
        },
        auth_context=auth_context,
        request=request,
    )
    db.commit()
    db.refresh(user)
    _load_workspace_memberships(db, workspace, [user])
    return user, created


def _validate_replace_targets_user(db: Session, *, existing: User, payload: ScimUserWrite) -> None:
    external_id = (payload.externalId or "").strip()
    email = _primary_email(payload)
    if external_id and existing.logto_id and external_id != existing.logto_id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="SCIM payload externalId does not match the requested user",
        )
    if external_id:
        conflicting_external = (
            db.query(User).filter(User.logto_id == external_id, User.id != existing.id).first()
        )
        if conflicting_external is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="SCIM externalId belongs to a different user",
            )
    conflicting_email = db.query(User).filter(User.email == email, User.id != existing.id).first()
    if conflicting_email is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="SCIM email belongs to a different user",
        )


def _user_or_404(db: Session, user_id: int, workspace: Workspace) -> User:
    membership = (
        db.query(WorkspaceMembership)
        .filter(
            WorkspaceMembership.workspace_id == workspace.id,
            WorkspaceMembership.user_id == user_id,
        )
        .first()
    )
    if membership is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SCIM user not found")
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SCIM user not found")
    user._scim_memberships = [membership]
    return user


@router.get("/ServiceProviderConfig")
async def service_provider_config():
    """Return the supported SCIM feature profile."""
    return {
        "schemas": ["urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"],
        "patch": {"supported": True},
        "bulk": {"supported": False, "maxOperations": 0, "maxPayloadSize": 0},
        "filter": {"supported": False, "maxResults": 0},
        "changePassword": {"supported": False},
        "sort": {"supported": False},
        "etag": {"supported": False},
        "authenticationSchemes": [
            {
                "type": "apikey",
                "name": "X-API-Key",
                "description": "Workspace-scoped DMARQ API token passed in the X-API-Key header.",
            }
        ],
    }


@router.get("/Users")
async def list_scim_users(
    db: Session = Depends(get_db),
    _auth: dict = _scim_auth([SCIM_READ_SCOPE, SCIM_WRITE_SCOPE]),
):
    """List SCIM-provisioned users for the token workspace."""
    workspace = _workspace_for_token(db, _auth)
    rows = (
        db.query(User)
        .join(WorkspaceMembership, WorkspaceMembership.user_id == User.id)
        .filter(WorkspaceMembership.workspace_id == workspace.id)
        .order_by(User.id.asc())
        .all()
    )
    _load_workspace_memberships(db, workspace, rows)
    return {
        "schemas": [SCIM_LIST_SCHEMA],
        "totalResults": len(rows),
        "startIndex": 1,
        "itemsPerPage": len(rows),
        "Resources": [_scim_user_to_dict(user, workspace) for user in rows],
    }


@router.post("/Users")
async def create_scim_user(
    payload: ScimUserWrite,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = _scim_auth([SCIM_WRITE_SCOPE]),
):
    """Create or upsert a SCIM user in the token workspace."""
    workspace = _workspace_for_token(db, _auth)
    user, created = _upsert_scim_user(
        db, workspace=workspace, payload=payload, request=request, auth_context=_auth
    )
    return JSONResponse(
        status_code=status.HTTP_201_CREATED if created else status.HTTP_200_OK,
        content=_scim_user_to_dict(user, workspace),
    )


@router.get("/Users/{user_id}")
async def get_scim_user(
    user_id: int,
    db: Session = Depends(get_db),
    _auth: dict = _scim_auth([SCIM_READ_SCOPE, SCIM_WRITE_SCOPE]),
):
    """Return one SCIM user from the token workspace."""
    workspace = _workspace_for_token(db, _auth)
    user = _user_or_404(db, user_id, workspace)
    return _scim_user_to_dict(user, workspace)


@router.put("/Users/{user_id}")
async def replace_scim_user(
    user_id: int,
    payload: ScimUserWrite,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = _scim_auth([SCIM_WRITE_SCOPE]),
):
    """Replace a SCIM user and membership role mapping."""
    workspace = _workspace_for_token(db, _auth)
    existing = _user_or_404(db, user_id, workspace)
    _validate_replace_targets_user(db, existing=existing, payload=payload)
    user, _created = _upsert_scim_user(
        db,
        workspace=workspace,
        payload=payload,
        request=request,
        auth_context=_auth,
        existing_user=existing,
    )
    return _scim_user_to_dict(user, workspace)


@router.patch("/Users/{user_id}")
async def patch_scim_user(
    user_id: int,
    payload: ScimPatchRequest,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = _scim_auth([SCIM_WRITE_SCOPE]),
):
    """Apply a minimal SCIM patch, currently focused on active state."""
    workspace = _workspace_for_token(db, _auth)
    user = _user_or_404(db, user_id, workspace)
    changed = False
    for operation in payload.Operations:
        path = (operation.path or "").strip().lower()
        if operation.op.strip().lower() in {"replace", "add"} and path == "active":
            active = _coerce_scim_bool(operation.value)
            for membership in getattr(user, "_scim_memberships", []):
                membership.active = active
            changed = True
    if not changed:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Only active-state SCIM patch operations are supported",
        )
    active = _scim_active_from_memberships(user)
    record_workspace_audit_log(
        db,
        workspace=workspace,
        action="scim.user_deactivated" if not active else "scim.user_activated",
        entity_type="user",
        entity_id=user.id,
        entity_name=user.email,
        details={"active": active},
        auth_context=_auth,
        request=request,
    )
    db.commit()
    db.refresh(user)
    _load_workspace_memberships(db, workspace, [user])
    return _scim_user_to_dict(user, workspace)


@router.delete("/Users/{user_id}", status_code=status.HTTP_200_OK)
async def deactivate_scim_user(
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = _scim_auth([SCIM_WRITE_SCOPE]),
):
    """Deactivate a SCIM user without deleting audit history."""
    workspace = _workspace_for_token(db, _auth)
    user = _user_or_404(db, user_id, workspace)
    for membership in getattr(user, "_scim_memberships", []):
        membership.active = False
    record_workspace_audit_log(
        db,
        workspace=workspace,
        action="scim.user_deactivated",
        entity_type="user",
        entity_id=user.id,
        entity_name=user.email,
        details={"active": False},
        auth_context=_auth,
        request=request,
    )
    db.commit()
    db.refresh(user)
    _load_workspace_memberships(db, workspace, [user])
    return _scim_user_to_dict(user, workspace)
