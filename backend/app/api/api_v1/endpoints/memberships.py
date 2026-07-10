"""Organization and workspace membership management endpoints."""

from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.organization import Organization, OrganizationMembership
from app.models.user import User
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceMembership
from app.services.organizations import (
    OrganizationPlanLimitError,
    organization_user_has_active_seat,
    require_organization_feature,
    require_organization_plan_limit,
)
from app.services.workspace_access import (
    PERMISSION_MEMBERS_READ,
    PERMISSION_WORKSPACE_ADMIN,
    ROLE_ANALYST,
    ROLE_AUDITOR,
    ROLE_DOMAIN_ADMIN,
    ROLE_OPERATOR,
    ROLE_WORKSPACE_OWNER,
    require_organization_permission,
    require_workspace_permission,
    support_session_allows_inactive_tenant_read,
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


def _ensure_workspace_accepts_mutation(workspace: Workspace) -> None:
    if workspace.active:
        return
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="Inactive workspace cannot be modified",
    )


def _organization_or_404(
    db: Session,
    organization_id: int,
    auth_context: dict,
) -> Organization:
    query = db.query(Organization).filter(Organization.id == organization_id)
    if not support_session_allows_inactive_tenant_read(
        auth_context,
        organization_id=organization_id,
    ):
        query = query.filter(Organization.active.is_(True))
    organization = query.first()
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
        .filter(Workspace.organization_id == organization.id)
        .order_by(Workspace.id.asc())
        .first()
    )
    if workspace is not None:
        return workspace
    raise HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail="Organization has no workspace available for audit logging",
    )


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


def _raise_plan_limit_error(db: Session, exc: OrganizationPlanLimitError) -> None:
    db.rollback()
    raise HTTPException(
        status_code=status.HTTP_402_PAYMENT_REQUIRED,
        detail=exc.to_detail(),
    ) from exc


def _require_sso_identity_linking(
    db: Session,
    organization: Optional[Organization],
    payload: MembershipInviteRequest,
) -> None:
    if organization is None or not payload.logto_id:
        return
    try:
        require_organization_feature(db, organization, "sso")
    except ValueError as exc:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_402_PAYMENT_REQUIRED,
            detail={
                "code": "feature_not_included",
                "feature": "sso",
                "message": str(exc),
                "can_export": True,
            },
        ) from exc


def _require_user_seat_capacity(
    db: Session,
    organization: Optional[Organization],
    user: User,
    *,
    active: bool,
    activate_user: bool = False,
) -> None:
    if organization is None or not active:
        return
    if not activate_user and not user.is_active:
        return
    if user.is_active and organization_user_has_active_seat(db, organization, user):
        return
    require_organization_plan_limit(db, organization, "users")


def _find_or_create_invited_user(
    db: Session,
    payload: MembershipInviteRequest,
) -> User:
    email = str(payload.email).strip().lower()
    email_user = db.query(User).filter(User.email == email).first()
    logto_user = None
    if payload.logto_id:
        logto_user = db.query(User).filter(User.logto_id == payload.logto_id).first()
    if logto_user is not None and email_user is not None and logto_user.id != email_user.id:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Invite email and logto_id belong to different users",
        )
    user = logto_user or email_user
    if user is None:
        user = User(
            email=email,
            logto_id=payload.logto_id,
            full_name=payload.full_name,
            is_active=False,
            is_verified=False,
            is_superuser=False,
        )
        db.add(user)
        db.flush()
        return user
    if user.email != email:
        user.email = email
    if payload.logto_id and not user.logto_id:
        user.logto_id = payload.logto_id
    if payload.full_name and not user.full_name:
        user.full_name = payload.full_name
    db.flush()
    return user


def _upsert_workspace_membership_row(
    *,
    db: Session,
    workspace: Workspace,
    user: User,
    role: str,
    active: bool,
    request: Request,
    auth_context: dict,
    activate_user: bool = False,
) -> WorkspaceMembership:
    membership = (
        db.query(WorkspaceMembership)
        .filter(
            WorkspaceMembership.workspace_id == workspace.id,
            WorkspaceMembership.user_id == user.id,
        )
        .first()
    )
    old = {"role": membership.role, "active": membership.active} if membership is not None else None
    try:
        _require_user_seat_capacity(
            db,
            workspace.organization,
            user,
            active=active,
            activate_user=activate_user,
        )
    except OrganizationPlanLimitError as exc:
        _raise_plan_limit_error(db, exc)
    if activate_user:
        user.is_active = True
    if membership is None:
        membership = WorkspaceMembership(
            workspace_id=workspace.id,
            user_id=user.id,
            role=role,
            active=active,
        )
        db.add(membership)
    else:
        membership.role = role
        membership.active = active
    try:
        db.flush()
    except IntegrityError as exc:  # pragma: no cover - database race fallback
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
        details={"old": old, "new": {"role": role, "active": active}},
        auth_context=auth_context,
        request=request,
    )
    db.commit()
    db.refresh(membership)
    return membership


def _upsert_organization_membership_row(
    *,
    db: Session,
    organization: Organization,
    user: User,
    role: str,
    active: bool,
    request: Request,
    auth_context: dict,
    activate_user: bool = False,
) -> OrganizationMembership:
    membership = (
        db.query(OrganizationMembership)
        .filter(
            OrganizationMembership.organization_id == organization.id,
            OrganizationMembership.user_id == user.id,
        )
        .first()
    )
    old = {"role": membership.role, "active": membership.active} if membership is not None else None
    try:
        _require_user_seat_capacity(
            db,
            organization,
            user,
            active=active,
            activate_user=activate_user,
        )
    except OrganizationPlanLimitError as exc:
        _raise_plan_limit_error(db, exc)
    if activate_user:
        user.is_active = True
    if membership is None:
        membership = OrganizationMembership(
            organization_id=organization.id,
            user_id=user.id,
            role=role,
            active=active,
        )
        db.add(membership)
    else:
        membership.role = role
        membership.active = active
    try:
        db.flush()
    except IntegrityError as exc:  # pragma: no cover - database race fallback
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
            "new": {"role": role, "active": active},
        },
        auth_context=auth_context,
        request=request,
    )
    db.commit()
    db.refresh(membership)
    return membership


@router.get("/workspaces/{workspace_id}", response_model=MembershipListResponse)
async def list_workspace_memberships(
    workspace_id: int,
    include_inactive: bool = False,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> MembershipListResponse:
    """List users assigned to one workspace."""
    workspace = _workspace_or_404(db, workspace_id)
    require_workspace_permission(_auth, PERMISSION_MEMBERS_READ, db, workspace)
    query = (
        db.query(WorkspaceMembership)
        .options(selectinload(WorkspaceMembership.user))
        .filter(WorkspaceMembership.workspace_id == workspace.id)
    )
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
    _ensure_workspace_accepts_mutation(workspace)
    user = _user_or_404(db, user_id)
    role = _normalize_role(payload.role, WORKSPACE_ROLES)
    membership = _upsert_workspace_membership_row(
        db=db,
        workspace=workspace,
        user=user,
        role=role,
        active=payload.active,
        request=request,
        auth_context=_auth,
    )
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
    _ensure_workspace_accepts_mutation(workspace)
    role = _normalize_role(payload.role, WORKSPACE_ROLES)
    _require_sso_identity_linking(db, workspace.organization, payload)
    user = _find_or_create_invited_user(db, payload)
    membership = _upsert_workspace_membership_row(
        db=db,
        workspace=workspace,
        user=user,
        role=role,
        active=True,
        request=request,
        auth_context=_auth,
        activate_user=True,
    )
    return _workspace_membership_to_response(membership)


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
    _ensure_workspace_accepts_mutation(workspace)
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
    organization = _organization_or_404(db, organization_id, _auth)
    require_organization_permission(_auth, PERMISSION_MEMBERS_READ, db, organization)
    query = (
        db.query(OrganizationMembership)
        .options(selectinload(OrganizationMembership.user))
        .filter(OrganizationMembership.organization_id == organization.id)
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
    organization = _organization_or_404(db, organization_id, _auth)
    require_organization_permission(_auth, PERMISSION_WORKSPACE_ADMIN, db, organization)
    user = _user_or_404(db, user_id)
    role = _normalize_role(payload.role, ORGANIZATION_ROLES)
    membership = _upsert_organization_membership_row(
        db=db,
        organization=organization,
        user=user,
        role=role,
        active=payload.active,
        request=request,
        auth_context=_auth,
    )
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
    organization = _organization_or_404(db, organization_id, _auth)
    require_organization_permission(_auth, PERMISSION_WORKSPACE_ADMIN, db, organization)
    role = _normalize_role(payload.role, ORGANIZATION_ROLES)
    _require_sso_identity_linking(db, organization, payload)
    user = _find_or_create_invited_user(db, payload)
    membership = _upsert_organization_membership_row(
        db=db,
        organization=organization,
        user=user,
        role=role,
        active=True,
        request=request,
        auth_context=_auth,
        activate_user=True,
    )
    return _organization_membership_to_response(membership)


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
    organization = _organization_or_404(db, organization_id, _auth)
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
