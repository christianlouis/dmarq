"""Optional AI and automation endpoints."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.services.ai_assistance import (
    build_action_proposals,
    build_evidence_summary,
    build_remediation_plan,
    build_safe_context,
    get_assistance_config,
)
from app.services.workspace_access import (
    PERMISSION_REPORTS_READ,
    parse_selected_workspace_id,
    resolve_authorized_workspace,
)
from app.services.workspace_audit import record_workspace_audit_log

router = APIRouter()


class SafeContextResponse(BaseModel):
    """Redacted model/agent context response."""

    context: Dict[str, Any]


class EvidenceSummaryResponse(BaseModel):
    """Evidence-first summary response."""

    summary: Dict[str, Any]


class ActionProposalResponse(BaseModel):
    """Reviewable action proposals response."""

    domain: str
    action_tools_enabled: bool
    proposals: list[Dict[str, Any]]


class RemediationPlanResponse(BaseModel):
    """Step-by-step remediation plan response."""

    plan: Dict[str, Any]


class ProposalConfirmation(BaseModel):
    """Human confirmation payload for a proposal."""

    proposal_id: str
    confirmation_text: str
    note: Optional[str] = None


def _authorized_ai_workspace(
    auth_context: Dict[str, Any],
    db: Session,
    selected_workspace_id: Optional[int] = None,
):
    """Resolve and authorize the selected workspace for AI assistance audit events."""
    return resolve_authorized_workspace(
        db,
        auth_context,
        PERMISSION_REPORTS_READ,
        selected_workspace_id=selected_workspace_id,
    )


def _require_ai_enabled(db: Session) -> None:
    if not get_assistance_config(db).ai_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="AI assistance is disabled. Enable ai.enabled before using this endpoint.",
        )


@router.get("/config")
async def get_ai_config(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> Dict[str, Any]:
    """Return safe AI/MCP configuration without secrets."""
    return {"config": get_assistance_config(db).to_dict()}


@router.get("/domains/{domain}/context", response_model=SafeContextResponse)
async def get_domain_safe_context(
    domain: str,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> SafeContextResponse:
    """Return a redacted, evidence-linked context payload for one domain."""
    _require_ai_enabled(db)
    workspace = _authorized_ai_workspace(_auth, db)
    try:
        return {"context": build_safe_context(db, domain, workspace_id=workspace.id)}
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("/domains/{domain}/summary", response_model=EvidenceSummaryResponse)
async def get_domain_evidence_summary(
    domain: str,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> EvidenceSummaryResponse:
    """Return deterministic evidence-first assistance for one domain."""
    _require_ai_enabled(db)
    workspace = _authorized_ai_workspace(
        _auth,
        db,
        parse_selected_workspace_id(selected_workspace),
    )
    try:
        summary = build_evidence_summary(db, domain, workspace_id=workspace.id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    record_workspace_audit_log(
        db,
        workspace=workspace,
        action="ai.summary_generated",
        entity_type="domain",
        entity_id=domain,
        entity_name=domain,
        details={
            "provider": summary["provider"]["provider"],
            "recommendations": len(summary["recommendations"]),
        },
        auth_context=_auth,
        request=request,
    )
    db.commit()
    return {"summary": summary}


@router.get("/domains/{domain}/remediation-plan", response_model=RemediationPlanResponse)
async def get_domain_remediation_plan(
    domain: str,
    request: Request,
    finding_code: Optional[str] = None,
    refresh: bool = False,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> RemediationPlanResponse:  # pylint: disable=too-many-positional-arguments
    """Return a cached step-by-step remediation plan for DNS/posture findings."""
    _require_ai_enabled(db)
    workspace = _authorized_ai_workspace(
        _auth,
        db,
        parse_selected_workspace_id(selected_workspace),
    )
    try:
        plan = await build_remediation_plan(
            db,
            domain,
            finding_code=finding_code,
            refresh=refresh,
            workspace_id=workspace.id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    record_workspace_audit_log(
        db,
        workspace=workspace,
        action="ai.remediation_plan_generated",
        entity_type="domain",
        entity_id=domain,
        entity_name=domain,
        details={
            "provider": plan.get("provider"),
            "cached": plan.get("cached", False),
            "finding_code": finding_code,
            "action_count": len(plan.get("actions") or []),
        },
        auth_context=_auth,
        request=request,
    )
    db.commit()
    return {"plan": plan}


@router.get("/domains/{domain}/action-proposals", response_model=ActionProposalResponse)
async def get_domain_action_proposals(
    domain: str,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> ActionProposalResponse:
    """Return reviewable proposals; this endpoint never applies changes."""
    _require_ai_enabled(db)
    workspace = _authorized_ai_workspace(
        _auth,
        db,
        parse_selected_workspace_id(selected_workspace),
    )
    try:
        payload = build_action_proposals(db, domain, workspace_id=workspace.id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    record_workspace_audit_log(
        db,
        workspace=workspace,
        action="ai.action_proposals_generated",
        entity_type="domain",
        entity_id=domain,
        entity_name=domain,
        details={"proposal_count": len(payload["proposals"]), "mutates_state": False},
        auth_context=_auth,
        request=request,
    )
    db.commit()
    return payload


@router.post("/domains/{domain}/action-proposals/confirm")
async def confirm_action_proposal(
    domain: str,
    payload: ProposalConfirmation,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """Audit human confirmation for a proposal without applying external changes."""
    _require_ai_enabled(db)
    config = get_assistance_config(db)
    if not config.action_tools_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Action tools are disabled. Enable ai.action_tools_enabled to confirm " "proposals."
            ),
        )
    workspace = _authorized_ai_workspace(
        _auth,
        db,
        parse_selected_workspace_id(selected_workspace),
    )
    proposals = build_action_proposals(db, domain, workspace_id=workspace.id)["proposals"]
    proposal = next(
        (item for item in proposals if item["proposal_id"] == payload.proposal_id),
        None,
    )
    if proposal is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Proposal not found")
    if payload.confirmation_text != payload.proposal_id:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="confirmation_text must match proposal_id",
        )
    record_workspace_audit_log(
        db,
        workspace=workspace,
        action="ai.action_proposal_confirmed",
        entity_type="action_proposal",
        entity_id=payload.proposal_id,
        entity_name=proposal["title"],
        details={
            "domain": domain,
            "proposal_id": payload.proposal_id,
            "mutates_state": False,
            "note": payload.note,
        },
        auth_context=_auth,
        request=request,
    )
    db.commit()
    return {"status": "confirmed", "applied": False, "proposal": proposal}
