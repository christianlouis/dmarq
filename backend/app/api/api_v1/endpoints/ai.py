"""Optional AI and automation endpoints."""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.services.ai_assistance import (
    build_action_proposals,
    build_evidence_summary,
    build_safe_context,
    get_assistance_config,
)
from app.services.workspace_audit import record_workspace_audit_log
from app.services.workspaces import assign_default_workspace_to_unscoped_rows

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


class ProposalConfirmation(BaseModel):
    """Human confirmation payload for a proposal."""

    proposal_id: str
    confirmation_text: str
    note: Optional[str] = None


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
    try:
        return {"context": build_safe_context(db, domain)}
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get("/domains/{domain}/summary", response_model=EvidenceSummaryResponse)
async def get_domain_evidence_summary(
    domain: str,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> EvidenceSummaryResponse:
    """Return deterministic evidence-first assistance for one domain."""
    _require_ai_enabled(db)
    try:
        summary = build_evidence_summary(db, domain)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    workspace = assign_default_workspace_to_unscoped_rows(db, commit=False)
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


@router.get("/domains/{domain}/action-proposals", response_model=ActionProposalResponse)
async def get_domain_action_proposals(
    domain: str,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
) -> ActionProposalResponse:
    """Return reviewable proposals; this endpoint never applies changes."""
    _require_ai_enabled(db)
    try:
        payload = build_action_proposals(db, domain)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    workspace = assign_default_workspace_to_unscoped_rows(db, commit=False)
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
) -> Dict[str, Any]:
    """Audit human confirmation for a proposal without applying external changes."""
    _require_ai_enabled(db)
    config = get_assistance_config(db)
    if not config.action_tools_enabled:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=(
                "Action tools are disabled. Enable ai.action_tools_enabled to confirm "
                "proposals."
            ),
        )
    proposals = build_action_proposals(db, domain)["proposals"]
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
    workspace = assign_default_workspace_to_unscoped_rows(db, commit=False)
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
