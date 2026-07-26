"""Current-user workspace context endpoints."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session, selectinload

from app.core.database import get_db
from app.core.config import get_settings
from app.core.security import require_admin_auth
from app.models.user import User
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceMembership
from app.services.mail_health import build_workspace_mail_health_assessment
from app.services.mail_health_incidents import (
    NOTIFICATION_POSTURES,
    list_mail_health_incidents,
    record_mail_health_assessment,
    update_incident_operator_state,
)
from app.services.workspace_access import (
    ROLE_ANALYST,
    ROLE_WORKSPACE_OWNER,
    PERMISSION_REPORTS_READ,
    PERMISSION_REPORTS_WRITE,
    _auth_user,
    is_platform_admin_auth,
    parse_selected_workspace_id,
    permissions_for_role,
    resolve_authorized_workspace,
)

router = APIRouter()


class WorkspaceContextResponse(BaseModel):
    """Visible workspace context for client-side scope selection."""

    workspaces: List[Dict[str, Any]]
    default_workspace_id: Optional[int] = None


class GuidancePreferenceUpdate(BaseModel):
    """Workspace opt-in with a user's optional presentation preference."""

    enabled: bool
    depth: str = "guided"
    context: str = "watch"


class GuidanceProfileUpdate(BaseModel):
    """Problem-first setup answers that do not change the legacy dashboard."""

    goal: str
    depth: str = "guided"


class NotificationPostureUpdate(BaseModel):
    """How much Calm Watch may interrupt an operator."""

    posture: str


class IncidentActionUpdate(BaseModel):
    """An auditable acknowledgement or bounded snooze."""

    action: str
    note: Optional[str] = None
    snoozed_until: Optional[datetime] = None


def _guidance_payload(workspace: Workspace, user: Optional[User] = None) -> Dict[str, Any]:
    settings = get_settings()
    available = bool(settings.GUIDED_MAIL_HEALTH_UI_ENABLED)
    has_user_preference = bool(user and (user.guidance_depth or user.guidance_context))
    return {
        "available": available,
        "enabled": bool(workspace.guided_mail_health_enabled) and available,
        "requested_enabled": bool(workspace.guided_mail_health_enabled),
        "depth": (user.guidance_depth if user and user.guidance_depth else workspace.guidance_depth) or "standard",
        "context": (user.guidance_context if user and user.guidance_context else workspace.guidance_context) or "watch",
        "preference_scope": "user" if has_user_preference else "workspace",
        "goal": workspace.mail_health_goal,
        "notification_posture": workspace.notification_posture or "actionable_only",
        "interview_completed": workspace.guidance_interview_completed_at is not None,
    }


def _workspace_context_row(
    workspace: Workspace,
    role: str,
) -> Optional[Dict[str, Any]]:
    if not role:
        return None
    organization = workspace.organization
    return {
        "id": workspace.id,
        "slug": workspace.slug,
        "name": workspace.name,
        "active": bool(workspace.active),
        "organization": (
            {
                "id": organization.id,
                "slug": organization.slug,
                "name": organization.name,
                "active": bool(organization.active),
            }
            if organization is not None
            else None
        ),
        "effective_role": role,
        "permissions": sorted(permissions_for_role(role)),
    }


def _visible_workspace_roles(db: Session, auth_context: dict) -> Dict[int, str]:
    if is_platform_admin_auth(auth_context):
        return {
            workspace_id: ROLE_WORKSPACE_OWNER
            for (workspace_id,) in db.query(Workspace.id).all()
        }

    if (auth_context or {}).get("auth_type") == "api_token":
        try:
            workspace_id = int((auth_context or {}).get("workspace_id") or 0)
        except (TypeError, ValueError):
            workspace_id = 0
        return {workspace_id: ROLE_ANALYST} if workspace_id else {}

    user = _auth_user(db, auth_context)
    if user is None:
        return {}

    rows = (
        db.query(WorkspaceMembership.workspace_id, WorkspaceMembership.role)
        .filter(
            WorkspaceMembership.user_id == user.id,
            WorkspaceMembership.active.is_(True),
        )
        .all()
    )
    roles = {workspace_id: role for workspace_id, role in rows}
    if user.is_superuser and user.workspace_id:
        roles.setdefault(user.workspace_id, ROLE_WORKSPACE_OWNER)
    return roles


@router.get("", response_model=WorkspaceContextResponse)
async def list_visible_workspaces(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> WorkspaceContextResponse:
    """Return workspaces visible to the current admin/session context."""
    roles_by_workspace = _visible_workspace_roles(db, _auth)
    if not roles_by_workspace:
        return {"workspaces": [], "default_workspace_id": None}
    workspaces = (
        db.query(Workspace)
        .options(selectinload(Workspace.organization))
        .filter(Workspace.id.in_(list(roles_by_workspace)))
        .order_by(Workspace.active.desc(), Workspace.slug.asc())
        .all()
    )
    visible = []
    for workspace in workspaces:
        row = _workspace_context_row(workspace, roles_by_workspace.get(workspace.id, ""))
        if row is not None:
            visible.append(row)
    default_workspace_id = visible[0]["id"] if visible else None
    return {"workspaces": visible, "default_workspace_id": default_workspace_id}


@router.get("/guidance")
async def get_guidance_preference(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """Return whether this workspace may use the optional guided dashboard."""
    workspace = resolve_authorized_workspace(
        db,
        _auth,
        PERMISSION_REPORTS_READ,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    return _guidance_payload(workspace, _auth_user(db, _auth))


@router.put("/guidance")
async def update_guidance_preference(
    payload: GuidancePreferenceUpdate,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """Persist an opt-in without changing legacy dashboards automatically."""
    if payload.depth not in {"guided", "standard", "expert"}:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid guidance depth")
    if payload.context not in {"watch", "diagnose", "evidence"}:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid guidance context")
    workspace = resolve_authorized_workspace(
        db,
        _auth,
        PERMISSION_REPORTS_WRITE,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    workspace.guided_mail_health_enabled = bool(payload.enabled)
    user = _auth_user(db, _auth)
    if user is not None:
        user.guidance_depth = payload.depth
        user.guidance_context = payload.context
    else:
        workspace.guidance_depth = payload.depth
        workspace.guidance_context = payload.context
    db.commit()
    db.refresh(workspace)
    return _guidance_payload(workspace, user)


@router.put("/guidance/profile")
async def update_guidance_profile(
    payload: GuidanceProfileUpdate,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """Record the user's installation goal without opting them into a new view."""
    valid_goals = {
        "delivery_problem",
        "spam_or_inconsistent",
        "reports_confusing",
        "suspected_abuse",
        "preventive_monitoring",
        "curious",
    }
    if payload.goal not in valid_goals:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid mail health goal")
    if payload.depth not in {"guided", "standard", "expert"}:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid guidance depth")
    workspace = resolve_authorized_workspace(
        db,
        _auth,
        PERMISSION_REPORTS_WRITE,
        selected_workspace_id=parse_selected_workspace_id(selected_workspace),
    )
    workspace.mail_health_goal = payload.goal
    user = _auth_user(db, _auth)
    if user is not None:
        user.guidance_depth = payload.depth
    else:
        workspace.guidance_depth = payload.depth
    workspace.guidance_interview_completed_at = datetime.utcnow()
    db.commit()
    db.refresh(workspace)
    return _guidance_payload(workspace, user)


@router.put("/guidance/notification-posture")
async def update_notification_posture(
    payload: NotificationPostureUpdate,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """Choose whether Calm Watch only interrupts for actionable incidents."""
    if payload.posture not in NOTIFICATION_POSTURES:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail="Invalid notification posture")
    workspace = resolve_authorized_workspace(
        db, _auth, PERMISSION_REPORTS_WRITE, selected_workspace_id=parse_selected_workspace_id(selected_workspace)
    )
    workspace.notification_posture = payload.posture
    db.commit()
    return _guidance_payload(workspace, _auth_user(db, _auth))


@router.get("/mail-health/incidents")
async def get_mail_health_incidents(
    limit: int = 50,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """List only incidents in the caller's authorized workspace."""
    workspace = resolve_authorized_workspace(
        db, _auth, PERMISSION_REPORTS_READ, selected_workspace_id=parse_selected_workspace_id(selected_workspace)
    )
    return {"incidents": list_mail_health_incidents(db, workspace=workspace, limit=limit)}


@router.post("/mail-health/incidents/evaluate")
async def evaluate_mail_health_incident(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """Evaluate one report-backed Calm Watch assessment without sending a notification."""
    workspace = resolve_authorized_workspace(
        db, _auth, PERMISSION_REPORTS_WRITE, selected_workspace_id=parse_selected_workspace_id(selected_workspace)
    )
    end = datetime.utcnow()
    assessment = build_workspace_mail_health_assessment(
        db,
        workspace=workspace,
        start_ts=int((end.timestamp() - 30 * 24 * 60 * 60)),
        end_ts=int(end.timestamp()),
    )
    return record_mail_health_assessment(db, workspace=workspace, assessment=assessment)


@router.put("/mail-health/incidents/{incident_id}")
async def update_mail_health_incident(
    incident_id: int,
    payload: IncidentActionUpdate,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """Acknowledge or snooze an incident without treating it as resolved."""
    workspace = resolve_authorized_workspace(
        db, _auth, PERMISSION_REPORTS_WRITE, selected_workspace_id=parse_selected_workspace_id(selected_workspace)
    )
    try:
        return update_incident_operator_state(
            db,
            workspace=workspace,
            incident_id=incident_id,
            action=payload.action,
            note=payload.note,
            snoozed_until=payload.snoozed_until,
            auth_context=_auth,
        )
    except LookupError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=str(exc)) from exc
