"""Stable read-only public API endpoints."""

from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy.orm import Session

from app.api.api_v1.endpoints import ai, domains, tls_reports
from app.core.database import get_db
from app.core.security import require_api_token_scope
from app.services.ai_assistance import build_action_proposals
from app.services.api_tokens import READ_POSTURE_SCOPE, READ_REPORTS_SCOPE, READ_TLS_SCOPE
from app.services.workspace_access import PERMISSION_REPORTS_READ, resolve_authorized_workspace

router = APIRouter()


@router.get("/domains", response_model=domains.DomainSummaryResponse)
async def public_domain_summary(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_api_token_scope(READ_REPORTS_SCOPE)),
):
    """List monitored domains with report and DNS posture summary fields."""
    return await domains.get_domains_summary(db=db, _auth=_auth)


@router.get(
    "/domains/{domain_id}/posture",
    response_model=domains.PostureDashboardResponse,
)
async def public_domain_posture(
    domain_id: str = Path(..., title="The domain ID or name"),
    refresh: bool = Query(False, title="Refresh cached DNS posture"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_api_token_scope(READ_POSTURE_SCOPE)),
):
    """Return the stable evidence-first posture payload for one domain."""
    return await domains.get_domain_posture_dashboard(
        domain_id=domain_id,
        refresh=refresh,
        db=db,
        _auth=_auth,
    )


@router.get(
    "/domains/{domain_id}/action-proposals",
    response_model=ai.ActionProposalResponse,
)
async def public_domain_action_proposals(
    domain_id: str = Path(..., title="The domain ID or name"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_api_token_scope(READ_POSTURE_SCOPE)),
):
    """Return stable read-only remediation proposals for one domain."""
    workspace = resolve_authorized_workspace(db, _auth, PERMISSION_REPORTS_READ)
    try:
        return build_action_proposals(db, domain_id, workspace_id=workspace.id)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc


@router.get(
    "/domains/{domain_id}/reports",
    response_model=domains.DomainReportsResponse,
)
async def public_domain_reports(
    domain_id: str = Path(..., title="The domain ID or name"),
    limit: int = Query(10, ge=1, le=200),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_api_token_scope(READ_REPORTS_SCOPE)),
):
    """Return recent DMARC aggregate report summaries for one domain."""
    return await domains.get_domain_reports(
        domain_id=domain_id,
        limit=limit,
        db=db,
        _auth=_auth,
    )


@router.get(
    "/domains/{domain_id}/sources",
    response_model=domains.DomainSourcesResponse,
)
async def public_domain_sources(
    domain_id: str = Path(..., title="The domain ID or name"),
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_api_token_scope(READ_REPORTS_SCOPE)),
):
    """Return enriched DMARC sending sources for one domain."""
    return await domains.get_domain_sources(
        domain_id=domain_id,
        days=days,
        db=db,
        _auth=_auth,
    )


@router.get(
    "/domains/{domain_id}/source-intelligence",
    response_model=domains.SourceIntelligenceResponse,
)
async def public_domain_source_intelligence(
    domain_id: str = Path(..., title="The domain ID or name"),
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_api_token_scope(READ_REPORTS_SCOPE)),
):
    """Return regional source summaries and anomaly hints for one domain."""
    return await domains.get_domain_source_intelligence(
        domain_id=domain_id,
        days=days,
        db=db,
        _auth=_auth,
    )


@router.get("/tls-reports/summary", response_model=tls_reports.TLSSummaryResponse)
async def public_tls_report_summary(
    domain: Optional[str] = Query(default=None),
    days: int = Query(default=30, ge=1, le=365),
    limit: int = Query(default=10, ge=1, le=50),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_api_token_scope(READ_TLS_SCOPE)),
):
    """Return aggregate SMTP TLS reporting posture trends."""
    return await tls_reports.tls_report_summary(
        domain=domain,
        days=days,
        limit=limit,
        db=db,
        _auth=_auth,
    )
