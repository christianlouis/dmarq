import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session, selectinload

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.domain import Domain
from app.models.report import ForensicReport
from app.services.demo_data import (
    analyze_demo_forensic_reports,
    get_demo_forensic_report,
    list_demo_forensic_reports,
)
from app.services.forensic_analysis import analyze_forensic_report, summarize_forensic_samples
from app.services.forensic_parser import ForensicParser, MAX_FORENSIC_REPORT_SIZE
from app.services.forensic_persistence import (
    forensic_report_exists,
    forensic_report_to_dict,
    save_forensic_report,
)
from app.services.forensic_redaction import get_forensic_redaction_policy
from app.services.workspace_access import (
    PERMISSION_REPORTS_READ,
    PERMISSION_REPORTS_WRITE,
    require_workspace_permission,
)
from app.services.workspaces import (
    assign_default_workspace_to_unscoped_rows,
    get_default_workspace,
    get_or_create_default_workspace,
)

logger = logging.getLogger(__name__)

router = APIRouter()


class ForensicSampleAnalysisResponse(BaseModel):
    id: int
    report_id: str
    domain: Optional[str] = None
    source_ip: Optional[str] = None
    auth_failure: str
    delivery_result: Optional[str] = None
    priority: str
    diagnosis: str
    recommendations: List[str] = Field(default_factory=list)
    signals: List[str] = Field(default_factory=list)
    authentication_results: Dict[str, str] = Field(default_factory=dict)
    dkim_domain: Optional[str] = None
    mail_from_domain: Optional[str] = None
    privacy_note: str


class ForensicAnalysisGroupResponse(BaseModel):
    key: str
    domain: str
    source_ip: str
    auth_failure: str
    delivery_result: str
    count: int
    priority: str
    latest_arrival: Optional[str] = None
    diagnosis: str
    recommendations: List[str] = Field(default_factory=list)


class ForensicAnalysisResponse(BaseModel):
    total: int
    priority_counts: Dict[str, int] = Field(default_factory=dict)
    failure_counts: Dict[str, int] = Field(default_factory=dict)
    result_counts: Dict[str, int] = Field(default_factory=dict)
    groups: List[ForensicAnalysisGroupResponse] = Field(default_factory=list)
    samples: List[ForensicSampleAnalysisResponse] = Field(default_factory=list)


class ForensicReportResponse(BaseModel):
    id: int
    report_id: str
    domain: Optional[str] = None
    reported_domain: Optional[str] = None
    source_email: Optional[str] = None
    feedback_type: Optional[str] = None
    user_agent: Optional[str] = None
    version: Optional[str] = None
    source_ip: Optional[str] = None
    auth_failure: Optional[str] = None
    delivery_result: Optional[str] = None
    arrival_date: Optional[str] = None
    authentication_results: Optional[str] = None
    original_mail_from: Optional[str] = None
    original_from: Optional[str] = None
    original_to: Optional[str] = None
    original_subject: Optional[str] = None
    original_message_id: Optional[str] = None
    original_date: Optional[str] = None
    feedback_headers: Dict[str, Any] = Field(default_factory=dict)
    processed_at: Optional[str] = None
    analysis: Optional[ForensicSampleAnalysisResponse] = None


class ForensicListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    total_pages: int
    reports: List[ForensicReportResponse]


class ForensicUploadResponse(BaseModel):
    success: bool
    report_id: str
    domain: Optional[str] = None
    message: str
    duplicate: bool = False


def _validate_upload(file: UploadFile, content: bytes) -> None:
    filename = file.filename or ""
    if not filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Filename is required")
    if len(content) == 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is empty")
    if len(content) > MAX_FORENSIC_REPORT_SIZE:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="File too large"
        )
    if not filename.lower().endswith((".eml", ".txt")):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file type. Upload a forensic report email as .eml or .txt.",
        )


def _authorized_reports_workspace(auth_context: Dict[str, Any], db: Session, permission: str):
    """Authorize report access before running legacy workspace repair writes."""
    workspace = get_default_workspace(db) or get_or_create_default_workspace(db)
    require_workspace_permission(auth_context, permission, db, workspace)
    return assign_default_workspace_to_unscoped_rows(db)


def _filtered_forensic_query(
    db: Session,
    *,
    domain: Optional[str] = None,
    source_ip: Optional[str] = None,
    auth_failure: Optional[str] = None,
    delivery_result: Optional[str] = None,
    workspace_id: Optional[int] = None,
):
    query = db.query(ForensicReport).options(selectinload(ForensicReport.domain))
    if workspace_id is not None or domain:
        query = query.outerjoin(Domain)
    if workspace_id is not None:
        query = query.filter(Domain.workspace_id == workspace_id)
    if domain:
        normalized = domain.lower()
        query = query.filter(
            (Domain.name == normalized) | (ForensicReport.reported_domain == normalized)
        )
    if source_ip:
        query = query.filter(ForensicReport.source_ip == source_ip.strip())
    if auth_failure:
        query = query.filter(ForensicReport.auth_failure == auth_failure.strip().lower())
    if delivery_result:
        query = query.filter(ForensicReport.delivery_result == delivery_result.strip().lower())
    return query


def _response_for_row(row: ForensicReport, redaction_policy) -> ForensicReportResponse:
    data = forensic_report_to_dict(row, redaction_policy=redaction_policy)
    data["analysis"] = analyze_forensic_report(row)
    return ForensicReportResponse(**data)


@router.post("/upload", response_model=ForensicUploadResponse)
async def upload_forensic_report(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Upload and store a DMARC forensic/failure report email."""
    _authorized_reports_workspace(_auth, db, PERMISSION_REPORTS_WRITE)
    try:
        content = await file.read()
        _validate_upload(file, content)
        redaction_policy = get_forensic_redaction_policy(db)
        parsed = ForensicParser.parse_bytes(content, redaction_policy=redaction_policy)
        if forensic_report_exists(db, parsed["report_id"]):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Forensic report has already been uploaded.",
            )

        row, created = save_forensic_report(db, parsed)
        if not created:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Forensic report has already been uploaded.",
            )
        db.commit()
        db.refresh(row)
        return ForensicUploadResponse(
            success=True,
            report_id=row.report_id,
            domain=row.reported_domain,
            message="Forensic report processed successfully.",
        )
    except HTTPException:
        raise
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid forensic report format.",
        ) from exc
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error("Unexpected forensic upload failure for %s: %s", file.filename, exc)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error processing forensic report.",
        ) from exc


@router.get("", response_model=ForensicListResponse)
async def list_forensic_reports(
    domain: Optional[str] = Query(default=None),
    source_ip: Optional[str] = Query(default=None),
    auth_failure: Optional[str] = Query(default=None),
    delivery_result: Optional[str] = Query(default=None),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """List stored forensic reports, newest first."""
    workspace = _authorized_reports_workspace(_auth, db, PERMISSION_REPORTS_READ)
    if get_settings().DEMO_MODE:
        return ForensicListResponse(
            **list_demo_forensic_reports(
                domain=domain,
                source_ip=source_ip,
                auth_failure=auth_failure,
                delivery_result=delivery_result,
                page=page,
                page_size=page_size,
            )
        )

    query = _filtered_forensic_query(
        db,
        domain=domain,
        source_ip=source_ip,
        auth_failure=auth_failure,
        delivery_result=delivery_result,
        workspace_id=workspace.id,
    )
    total = query.count()
    rows = (
        query.order_by(ForensicReport.arrival_date.desc().nullslast(), ForensicReport.id.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    total_pages = (total + page_size - 1) // page_size if total else 0
    redaction_policy = get_forensic_redaction_policy(db)
    return ForensicListResponse(
        total=total,
        page=page,
        page_size=page_size,
        total_pages=total_pages,
        reports=[_response_for_row(row, redaction_policy) for row in rows],
    )


@router.get("/analysis", response_model=ForensicAnalysisResponse)
async def analyze_forensic_reports(
    domain: Optional[str] = Query(default=None),
    source_ip: Optional[str] = Query(default=None),
    auth_failure: Optional[str] = Query(default=None),
    delivery_result: Optional[str] = Query(default=None),
    page_size: int = Query(default=200, ge=1, le=500),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Summarize stored forensic samples into operator investigation groups."""
    workspace = _authorized_reports_workspace(_auth, db, PERMISSION_REPORTS_READ)
    if get_settings().DEMO_MODE:
        return ForensicAnalysisResponse(
            **analyze_demo_forensic_reports(
                domain=domain,
                source_ip=source_ip,
                auth_failure=auth_failure,
                delivery_result=delivery_result,
                page_size=page_size,
            )
        )

    query = _filtered_forensic_query(
        db,
        domain=domain,
        source_ip=source_ip,
        auth_failure=auth_failure,
        delivery_result=delivery_result,
        workspace_id=workspace.id,
    )
    rows = (
        query.order_by(ForensicReport.arrival_date.desc().nullslast(), ForensicReport.id.desc())
        .limit(page_size)
        .all()
    )
    return ForensicAnalysisResponse(**summarize_forensic_samples(rows))


@router.get("/{report_id}", response_model=ForensicReportResponse)
async def get_forensic_report(
    report_id: int,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Return one stored forensic report by numeric ID."""
    workspace = _authorized_reports_workspace(_auth, db, PERMISSION_REPORTS_READ)
    if get_settings().DEMO_MODE:
        row = get_demo_forensic_report(report_id)
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND, detail="Forensic report not found"
            )
        return ForensicReportResponse(**row)

    row = (
        db.query(ForensicReport)
        .options(selectinload(ForensicReport.domain))
        .join(Domain, ForensicReport.domain_id == Domain.id)
        .filter(ForensicReport.id == report_id)
        .filter(Domain.workspace_id == workspace.id)
        .first()
    )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Forensic report not found"
        )
    redaction_policy = get_forensic_redaction_policy(db)
    return _response_for_row(row, redaction_policy)
