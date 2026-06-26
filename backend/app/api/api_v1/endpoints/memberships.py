"""Organization and workspace membership management endpoints."""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.organization import Organization, OrganizationMembership
from app.models.user import User
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceMembership
from app.services.workspace_access import (
    PERMISSION_WORKSPACE_ADMIN,
    ROLE_ANALYST,
    ROLE_AUDITOR,
    ROLE_DOMAIN_ADMIN,
    ROLE_OPERATOR,
    ROLE_WORKSPACE_OWNER,
    require_organization_permission,
    require_workspace_permission,
)
from app.services.workspace_audit import record_workspace_audit_log

router = APIRouter()

WORKSPACE_ROLES = {
    ROLE_WORKSPACE_OWNER,
    ROLE_DOMAIN_ADMIN,
    ROLE_OPERATOR,
    ROLE_ANALYST,
    ROLE_AUDITOR,
}
ORGANIZATION_ROLES = {
    "organization_owner",
    "organization_admin",
    "billing_admin",
    "organization_auditor",
    ROLE_WORKSPACE_OWNER,
    ROLE_AUDITOR,
    ROLE_ANALYST,
}


class MembershipUserResponse(BaseModel):
    """API-safe user identity attached to a membership."""

    id: int
    email: str
    logto_id: Optional[str] = None
    full_name: Optional[str] = None
    is_active: bool
    is_verified: bool


class MembershipResponse(BaseModel):
    """Membership row returned by management endpoints."""

    id: int
    scope: str
    scope_id: int
    user: MembershipUserResponse
    role: str
    active: bool


class MembershipListResponse(BaseModel):
    """List of membership rows."""

    memberships: List[MembershipResponse]
    available_roles: List[str]


class MembershipUpsertRequest(BaseModel):
    """Create or update a membership for an existing user."""

    user_id: int
    role: str = Field(..., min_length=1, max_length=50)
    active: bool = True


class MembershipInviteRequest(BaseModel):
    """Create or link a local OIDC-compatible user and assign a role."""

    email: EmailStr
    role: str = Field(..., min_length=1, max_length=50)
    logto_id: Optional[str] = Field(default=None, max_length=255)
    full_name: Optional[str] = Field(default=None, max_length=255)


def _workspace_or_404(db: Session, workspace_id: int) -> Workspace:
    workspace = db.query(Workspace).filter(Workspace.id == workspace_id).first()
    if workspace is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Workspace {workspace_id} not found",
        )
    return workspace


def _organization_or_404(db: Session, organization_id: int) -> Organization:
    organization = (
        db.query(Organization)
        .filter(Organization.id == organization_id, Organization.active.is_(True))
        .first()
    )
    if organization is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Organization {organization_id} not found",
        )
    return organization


def _user_or_404(db: Session, user_id: int) -> User:
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found",
        )
    return user


def _audit_workspace_for_organization(db: Session, organization: Organization) -> Workspace:
    workspace = (
        db.query(Workspace)
        .filter(Workspace.organization_id == organization.id, Workspace.active.is_(True))
        .order_by(Workspace.id.asc())
        .first()
    )
    if workspace is not None:
        return workspace
    workspace = Workspace(
        organization_id=organization.id,
        slug=f"org-{organization.id}",
        name=f"{organization.name} Workspace",
        active=True,
    )
    db.add(workspace)
    db.flush()
    return workspace


def _normalize_role(role: str, available_roles: set[str]) -> str:
    normalized = (role or "").strip().lower()
    if normalized not in available_roles:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Unsupported role: {role}",
        )
    return normalized


def _user_to_response(user: User) -> MembershipUserResponse:
    return MembershipUserResponse(
        id=user.id,
        email=user.email,
        logto_id=user.logto_id,
        full_name=user.full_name,
        is_active=bool(user.is_active),
        is_verified=bool(user.is_verified),
    )


def _workspace_membership_to_response(row: WorkspaceMembership) -> MembershipResponse:
    return MembershipResponse(
        id=row.id,
        scope="workspace",
        scope_id=row.workspace_id,
        user=_user_to_response(row.user),
        role=row.role,
        active=row.active,
    )


def _organization_membership_to_response(row: OrganizationMembership) -> MembershipResponse:
    return MembershipResponse(
        id=row.id,
        scope="organization",
        scope_id=row.organization_id,
        user=_user_to_response(row.user),
        role=row.role,
        active=row.active,
    )


def _find_or_create_invited_user(
    db: Session,
    payload: MembershipInviteRequest,
) -> User:
    email = str(payload.email).strip().lower()
    user = db.query(User).filter(User.email == email).first()
    if user is None and payload.logto_id:
        user = db.query(User).filter(User.logto_id == payload.logto_id).first()
    if user is None:
        user = User(
            email=email,
            logto_id=payload.logto_id,
            full_name=payload.full_name,
            is_active=True,
            is_verified=False,
            is_superuser=False,
        )
        db.add(user)
        db.flush()
        return user
    if payload.logto_id and not user.logto_id:
        user.logto_id = payload.logto_id
    if payload.full_name and not user.full_name:
        user.full_name = payload.full_name
    user.is_active = True
    db.flush()
    return user


@router.get("/workspaces/{workspace_id}", response_model=MembershipListResponse)
async def list_workspace_memberships(
    workspace_id: int,
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> MembershipListResponse:
    """List users assigned to one workspace."""
    workspace = _workspace_or_404(db, workspace_id)
    require_workspace_permission(_auth, PERMISSION_WORKSPACE_ADMIN, db, workspace)
    query = db.query(WorkspaceMembership).filter(WorkspaceMembership.workspace_id == workspace.id)
    if not include_inactive:
        query = query.filter(WorkspaceMembership.active.is_(True))
    rows = query.order_by(WorkspaceMembership.id.asc()).all()
    return {
        "memberships": [_workspace_membership_to_response(row) for row in rows],
        "available_roles": sorted(WORKSPACE_ROLES),
    }


@router.put("/workspaces/{workspace_id}/users/{user_id}", response_model=MembershipResponse)
async def upsert_workspace_membership(
    workspace_id: int,
    user_id: int,
    payload: MembershipUpsertRequest,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> MembershipResponse:
    """Create or update one workspace membership."""
    if payload.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Payload user_id must match path user_id",
        )
    workspace = _workspace_or_404(db, workspace_id)
    require_workspace_permission(_auth, PERMISSION_WORKSPACE_ADMIN, db, workspace)
    user = _user_or_404(db, user_id)
    role = _normalize_role(payload.role, WORKSPACE_ROLES)
    membership = (
        db.query(WorkspaceMembership)
        .filter(
            WorkspaceMembership.workspace_id == workspace.id,
            WorkspaceMembership.user_id == user.id,
        )
        .first()
    )
    old = {"role": membership.role, "active": membership.active} if membership is not None else None
    if membership is None:
        membership = WorkspaceMembership(
            workspace_id=workspace.id,
            user_id=user.id,
            role=role,
            active=payload.active,
        )
        db.add(membership)
    else:
        membership.role = role
        membership.active = payload.active
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Workspace membership already exists",
        ) from exc
    record_workspace_audit_log(
        db,
        workspace=workspace,
        action="workspace.membership_upserted",
        entity_type="workspace_membership",
        entity_id=membership.id,
        entity_name=user.email,
        details={"old": old, "new": {"role": role, "active": payload.active}},
        auth_context=_auth,
        request=request,
    )
    db.commit()
    db.refresh(membership)
    return _workspace_membership_to_response(membership)


@router.post("/workspaces/{workspace_id}/invites", response_model=MembershipResponse)
async def invite_workspace_member(
    workspace_id: int,
    payload: MembershipInviteRequest,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> MembershipResponse:
    """Invite or link a user by email and assign a workspace role."""
    workspace = _workspace_or_404(db, workspace_id)
    require_workspace_permission(_auth, PERMISSION_WORKSPACE_ADMIN, db, workspace)
    user = _find_or_create_invited_user(db, payload)
    upsert = MembershipUpsertRequest(user_id=user.id, role=payload.role, active=True)
    return await upsert_workspace_membership(
        workspace_id=workspace_id,
        user_id=user.id,
        payload=upsert,
        request=request,
        db=db,
        _auth=_auth,
    )


@router.delete("/workspaces/{workspace_id}/users/{user_id}", response_model=MembershipResponse)
async def deactivate_workspace_membership(
    workspace_id: int,
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> MembershipResponse:
    """Deactivate one workspace membership without deleting audit history."""
    workspace = _workspace_or_404(db, workspace_id)
    require_workspace_permission(_auth, PERMISSION_WORKSPACE_ADMIN, db, workspace)
    membership = (
        db.query(WorkspaceMembership)
        .filter(
            WorkspaceMembership.workspace_id == workspace.id,
            WorkspaceMembership.user_id == user_id,
        )
        .first()
    )
    if membership is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Workspace membership not found",
        )
    old = {"role": membership.role, "active": membership.active}
    membership.active = False
    record_workspace_audit_log(
        db,
        workspace=workspace,
        action="workspace.membership_deactivated",
        entity_type="workspace_membership",
        entity_id=membership.id,
        entity_name=membership.user.email,
        details={"old": old, "new": {"role": membership.role, "active": False}},
        auth_context=_auth,
        request=request,
    )
    db.commit()
    db.refresh(membership)
    return _workspace_membership_to_response(membership)


@router.get("/organizations/{organization_id}", response_model=MembershipListResponse)
async def list_organization_memberships(
    organization_id: int,
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> MembershipListResponse:
    """List users assigned across one organization."""
    organization = _organization_or_404(db, organization_id)
    require_organization_permission(_auth, PERMISSION_WORKSPACE_ADMIN, db, organization)
    query = db.query(OrganizationMembership).filter(
        OrganizationMembership.organization_id == organization.id
    )
    if not include_inactive:
        query = query.filter(OrganizationMembership.active.is_(True))
    rows = query.order_by(OrganizationMembership.id.asc()).all()
    return {
        "memberships": [_organization_membership_to_response(row) for row in rows],
        "available_roles": sorted(ORGANIZATION_ROLES),
    }


@router.put(
    "/organizations/{organization_id}/users/{user_id}",
    response_model=MembershipResponse,
)
async def upsert_organization_membership(
    organization_id: int,
    user_id: int,
    payload: MembershipUpsertRequest,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> MembershipResponse:
    """Create or update one organization membership."""
    if payload.user_id != user_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Payload user_id must match path user_id",
        )
    organization = _organization_or_404(db, organization_id)
    require_organization_permission(_auth, PERMISSION_WORKSPACE_ADMIN, db, organization)
    user = _user_or_404(db, user_id)
    role = _normalize_role(payload.role, ORGANIZATION_ROLES)
    membership = (
        db.query(OrganizationMembership)
        .filter(
            OrganizationMembership.organization_id == organization.id,
            OrganizationMembership.user_id == user.id,
        )
        .first()
    )
    old = {"role": membership.role, "active": membership.active} if membership is not None else None
    if membership is None:
        membership = OrganizationMembership(
            organization_id=organization.id,
            user_id=user.id,
            role=role,
            active=payload.active,
        )
        db.add(membership)
    else:
        membership.role = role
        membership.active = payload.active
    try:
        db.flush()
    except IntegrityError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Organization membership already exists",
        ) from exc
    audit_workspace = _audit_workspace_for_organization(db, organization)
    record_workspace_audit_log(
        db,
        workspace=audit_workspace,
        action="organization.membership_upserted",
        entity_type="organization_membership",
        entity_id=membership.id,
        entity_name=user.email,
        details={
            "organization_id": organization.id,
            "old": old,
            "new": {"role": role, "active": payload.active},
        },
        auth_context=_auth,
        request=request,
    )
    db.commit()
    db.refresh(membership)
    return _organization_membership_to_response(membership)


@router.post("/organizations/{organization_id}/invites", response_model=MembershipResponse)
async def invite_organization_member(
    organization_id: int,
    payload: MembershipInviteRequest,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> MembershipResponse:
    """Invite or link a user by email and assign an organization role."""
    organization = _organization_or_404(db, organization_id)
    require_organization_permission(_auth, PERMISSION_WORKSPACE_ADMIN, db, organization)
    user = _find_or_create_invited_user(db, payload)
    upsert = MembershipUpsertRequest(user_id=user.id, role=payload.role, active=True)
    return await upsert_organization_membership(
        organization_id=organization_id,
        user_id=user.id,
        payload=upsert,
        request=request,
        db=db,
        _auth=_auth,
    )


@router.delete(
    "/organizations/{organization_id}/users/{user_id}",
    response_model=MembershipResponse,
)
async def deactivate_organization_membership(
    organization_id: int,
    user_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> MembershipResponse:
    """Deactivate one organization membership without deleting audit history."""
    organization = _organization_or_404(db, organization_id)
    require_organization_permission(_auth, PERMISSION_WORKSPACE_ADMIN, db, organization)
    membership = (
        db.query(OrganizationMembership)
        .filter(
            OrganizationMembership.organization_id == organization.id,
            OrganizationMembership.user_id == user_id,
        )
        .first()
    )
    if membership is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Organization membership not found",
        )
    old = {"role": membership.role, "active": membership.active}
    membership.active = False
    audit_workspace = _audit_workspace_for_organization(db, organization)
    record_workspace_audit_log(
        db,
        workspace=audit_workspace,
        action="organization.membership_deactivated",
        entity_type="organization_membership",
        entity_id=membership.id,
        entity_name=membership.user.email,
        details={
            "organization_id": organization.id,
            "old": old,
            "new": {"role": membership.role, "active": False},
        },
        auth_context=_auth,
        request=request,
    )
    db.commit()
    db.refresh(membership)
    return _organization_membership_to_response(membership)
