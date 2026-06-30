"""Stable read-only public API endpoints."""

from datetime import date
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from sqlalchemy.orm import Session

from app.api.api_v1.endpoints import ai, domains, tls_reports
from app.core.database import get_db
from app.core.security import require_api_token_any_scope, require_api_token_scope
from app.services.ai_assistance import build_action_proposals
from app.services.alert_history import alert_history_summary, list_workspace_alert_history
from app.services.api_tokens import (
    MCP_READ_SCOPE,
    READ_POSTURE_SCOPE,
    READ_REPORTS_SCOPE,
    READ_TLS_SCOPE,
)
from app.services.export_catalog import build_export_catalog
from app.services.workspace_access import PERMISSION_REPORTS_READ, resolve_authorized_workspace
from app.services.workspace_usage import build_workspace_usage_summary

router = APIRouter()


@router.get("/domains", response_model=domains.DomainSummaryResponse)
async def public_domain_summary(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_api_token_scope(READ_REPORTS_SCOPE)),
):
    """List monitored domains with report and DNS posture summary fields."""
    return await domains.get_domains_summary(db=db, _auth=_auth)


@router.get("/exports")
async def public_export_catalog(
    db: Session = Depends(get_db),
    _auth: dict = Depends(
        require_api_token_any_scope(
            [READ_REPORTS_SCOPE, READ_POSTURE_SCOPE, READ_TLS_SCOPE, MCP_READ_SCOPE],
            detail_scope="one of reports:read, posture:read, tls-reports:read, mcp:read",
        )
    ),
):
    """Return available public export routes, MCP tools, and token usage metadata."""
    workspace = resolve_authorized_workspace(db, _auth, PERMISSION_REPORTS_READ)
    return build_export_catalog(db, workspace=workspace, auth_context=_auth)


@router.get("/usage")
async def public_workspace_usage(
    db: Session = Depends(get_db),
    _auth: dict = Depends(
        require_api_token_any_scope(
            [READ_REPORTS_SCOPE, READ_POSTURE_SCOPE, MCP_READ_SCOPE],
            detail_scope="one of reports:read, posture:read, mcp:read",
        )
    ),
):
    """Return a read-only usage summary for the API token workspace."""
    workspace = resolve_authorized_workspace(db, _auth, PERMISSION_REPORTS_READ)
    return build_workspace_usage_summary(db, workspace)


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
    "/domains/{domain_id}/dns/lint",
    response_model=domains.DNSGuidanceResponse,
)
async def public_domain_dns_lint(
    domain_id: str = Path(..., title="The domain ID or name"),
    refresh: bool = Query(False, title="Refresh cached DNS result"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_api_token_scope(READ_POSTURE_SCOPE)),
):
    """Return stable read-only DNS lint findings for one domain."""
    return await domains.get_domain_dns_lint(
        domain_id=domain_id,
        refresh=refresh,
        db=db,
        _auth=_auth,
    )


@router.get(
    "/domains/{domain_id}/dns/change-plan",
    response_model=domains.DNSChangePlanResponse,
)
async def public_domain_dns_change_plan(
    domain_id: str = Path(..., title="The domain ID or name"),
    refresh: bool = Query(False, title="Refresh cached DNS result"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_api_token_scope(READ_POSTURE_SCOPE)),
):
    """Return public read-only DNS change plans without write affordances."""
    response = await domains.get_domain_dns_change_plan(
        domain_id=domain_id,
        refresh=refresh,
        db=db,
        _auth=_auth,
    )
    return domains.read_only_dns_change_plan_response(response)


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


@router.get("/alerts")
async def public_alert_history(
    active: Optional[bool] = Query(None, title="Filter active or resolved alerts"),
    domain: Optional[str] = Query(None, title="Limit alerts to one monitored domain"),
    limit: int = Query(50, ge=1, le=200, title="Maximum alert history rows"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_api_token_scope(READ_POSTURE_SCOPE)),
):
    """Return sanitized alert history for the API token workspace."""
    workspace = resolve_authorized_workspace(db, _auth, PERMISSION_REPORTS_READ)
    alerts = list_workspace_alert_history(
        db,
        workspace_id=workspace.id,
        active=active,
        domain=domain,
        limit=limit,
    )
    return {
        "alerts": alerts,
        "summary": alert_history_summary(alerts),
        "filters": {"active": active, "domain": domain, "limit": limit},
    }


@router.get("/domains/{domain_id}/posture/evidence/export")
async def public_domain_health_evidence_export(
    domain_id: str = Path(..., title="The domain ID or name"),
    start_date: Optional[date] = Query(None, title="Start date for evidence export"),
    end_date: Optional[date] = Query(None, title="End date for evidence export"),
    limit: int = Query(400, ge=1, le=1000, title="Maximum exported snapshots"),
    export_format: str = Query(
        "json",
        alias="format",
        pattern="^(csv|json)$",
        title="Evidence export format",
    ),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_api_token_scope(READ_POSTURE_SCOPE)),
):
    """Return sanitized domain health evidence without capturing a new snapshot."""
    rows = await domains.build_domain_health_evidence_export_rows(
        domain_id=domain_id,
        start_date=start_date,
        end_date=end_date,
        limit=limit,
        capture_current=False,
        db=db,
        auth_context=_auth,
    )
    return domains.write_health_evidence_export(
        rows,
        export_id=domain_id,
        scope="domain",
        export_format=export_format,
    )


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
