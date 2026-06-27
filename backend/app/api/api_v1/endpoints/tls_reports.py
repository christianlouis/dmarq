import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, Header, HTTPException, Query, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session, selectinload

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.domain import Domain
from app.models.report import TLSReport
from app.services.demo_data import list_demo_tls_reports, summarize_demo_tls_reports
from app.services.tls_report_parser import MAX_TLS_REPORT_SIZE, TLSReportParser
from app.services.tls_report_persistence import (
    TLS_REPORT_PRIVACY_CONTROLS,
    save_tls_report,
    summarize_tls_reports,
    tls_report_to_dict,
)
from app.services.workspace_access import (
    PERMISSION_REPORTS_READ,
    PERMISSION_REPORTS_WRITE,
    parse_selected_workspace_id,
    resolve_authorized_workspace,
)

logger = logging.getLogger(__name__)

router = APIRouter()


class TLSFailureResponse(BaseModel):
    result_type: str
    failed_session_count: int
    sending_mta_ip: Optional[str] = None
    receiving_mx_hostname: Optional[str] = None
    receiving_mx_helo: Optional[str] = None
    receiving_ip: Optional[str] = None
    failure_reason_code: Optional[str] = None
    additional_information: Optional[str] = None


class TLSReportResponse(BaseModel):
    id: int
    report_id: str
    domain: Optional[str] = None
    org_name: Optional[str] = None
    contact_info: Optional[str] = None
    policy_domain: str
    policy_type: Optional[str] = None
    begin_date: Optional[str] = None
    end_date: Optional[str] = None
    total_successful_sessions: int
    total_failure_sessions: int
    processed_at: Optional[str] = None
    failures: List[TLSFailureResponse] = Field(default_factory=list)


class TLSReportListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    total_pages: int
    reports: List[TLSReportResponse]
    privacy: Dict[str, Any]


class TLSReportUploadResponse(BaseModel):
    success: bool
    report_id: str
    policies_created: int
    policies_skipped: int
    duplicate: bool = False
    message: str
    privacy: Dict[str, Any]


class TLSSummaryResponse(BaseModel):
    domain: Optional[str] = None
    days: int
    totals: Dict[str, Any]
    trends: List[Dict[str, Any]] = Field(default_factory=list)
    top_failures: List[Dict[str, Any]] = Field(default_factory=list)
    affected_domains: List[Dict[str, Any]] = Field(default_factory=list)
    privacy: Dict[str, Any]


def _validate_upload(file: UploadFile, content: bytes) -> None:
    filename = file.filename or ""
    if not filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Filename is required")
    if len(content) == 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is empty")
    if len(content) > MAX_TLS_REPORT_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File too large",
        )
    if not filename.lower().endswith((".json", ".json.gz", ".gzip", ".zip")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file type. Upload a TLS report as .json, .json.gz, or .zip.",
        )


def _authorized_reports_workspace(
    auth_context: Dict[str, Any],
    db: Session,
    permission: str,
    selected_workspace_id: Optional[int] = None,
):
    """Resolve and authorize the selected workspace for TLS report operations."""
    return resolve_authorized_workspace(
        db,
        auth_context,
        permission,
        selected_workspace_id=selected_workspace_id,
    )


def _filtered_tls_query(
    db: Session,
    *,
    domain: Optional[str] = None,
    workspace_id: Optional[int] = None,
):
    query = db.query(TLSReport).options(
        selectinload(TLSReport.domain), selectinload(TLSReport.failures)
    )
    if workspace_id is not None or domain:
        query = query.outerjoin(Domain)
    if workspace_id is not None:
        query = query.filter(Domain.workspace_id == workspace_id)
    if domain:
        normalized = domain.lower().strip(".")
        query = query.filter((Domain.name == normalized) | (TLSReport.policy_domain == normalized))
    return query


@router.post("/upload", response_model=TLSReportUploadResponse)
async def upload_tls_report(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
):
    """Upload and store an SMTP TLS Reporting aggregate."""
    workspace = _authorized_reports_workspace(
        _auth,
        db,
        PERMISSION_REPORTS_WRITE,
        parse_selected_workspace_id(selected_workspace),
    )
    try:
        content = await file.read()
        _validate_upload(file, content)
        parsed = TLSReportParser.parse_file(content, file.filename or "")
        result = save_tls_report(db, parsed, workspace_id=workspace.id)
        db.commit()
        return TLSReportUploadResponse(
            success=True,
            report_id=parsed["report_id"],
            policies_created=result["created"],
            policies_skipped=result["skipped"],
            duplicate=result["created"] == 0 and result["skipped"] > 0,
            message=(
                "TLS report imported."
                if result["created"]
                else "TLS report had already been imported."
            ),
            privacy=TLS_REPORT_PRIVACY_CONTROLS,
        )
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc) or "Invalid TLS report format.",
        ) from exc
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error("Unexpected TLS report upload failure for %s: %s", file.filename, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error processing TLS report.",
        ) from exc


@router.get("", response_model=TLSReportListResponse)
async def list_tls_reports(
    domain: Optional[str] = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
):
    """List stored SMTP TLS reports, newest first."""
    workspace = _authorized_reports_workspace(
        _auth,
        db,
        PERMISSION_REPORTS_READ,
        parse_selected_workspace_id(selected_workspace),
    )
    if get_settings().DEMO_MODE:
        return TLSReportListResponse(
            **list_demo_tls_reports(domain=domain, page=page, page_size=page_size)
        )

    query = _filtered_tls_query(db, domain=domain, workspace_id=workspace.id)
    total = query.count()
    rows = (
        query.order_by(TLSReport.begin_date.desc().nullslast(), TLSReport.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    total_pages = (total + page_size - 1) // page_size if total else 0
    return TLSReportListResponse(
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        reports=[TLSReportResponse(**tls_report_to_dict(row)) for row in rows],
        privacy=TLS_REPORT_PRIVACY_CONTROLS,
    )


@router.get("/summary", response_model=TLSSummaryResponse)
async def tls_report_summary(
    domain: Optional[str] = Query(default=None),
    days: int = Query(default=30, ge=1, le=365),
    limit: int = Query(default=10, ge=1, le=50),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
):
    """Summarize TLS reports into trends and top failure causes."""
    workspace = _authorized_reports_workspace(
        _auth,
        db,
        PERMISSION_REPORTS_READ,
        parse_selected_workspace_id(selected_workspace),
    )
    if get_settings().DEMO_MODE:
        return TLSSummaryResponse(
            **summarize_demo_tls_reports(domain=domain, days=days, limit=limit)
        )

    return TLSSummaryResponse(
        **summarize_tls_reports(
            db,
            domain=domain,
            days=days,
            limit=limit,
            workspace_id=workspace.id,
        )
    )
