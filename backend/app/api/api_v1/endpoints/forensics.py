import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, HTTPException, Query, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session, selectinload

from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.domain import Domain
from app.models.report import ForensicReport
from app.services.forensic_parser import ForensicParser, MAX_FORENSIC_REPORT_SIZE
from app.services.forensic_persistence import (
    forensic_report_exists,
    forensic_report_to_dict,
    save_forensic_report,
)
from app.services.forensic_redaction import get_forensic_redaction_policy

logger = logging.getLogger(__name__)

router = APIRouter()


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


@router.post("/upload", response_model=ForensicUploadResponse)
async def upload_forensic_report(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Upload and store a DMARC forensic/failure report email."""
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
    query = db.query(ForensicReport).options(selectinload(ForensicReport.domain))
    if domain:
        normalized = domain.lower()
        query = query.outerjoin(Domain).filter(
            (Domain.name == normalized) | (ForensicReport.reported_domain == normalized)
        )
    if source_ip:
        query = query.filter(ForensicReport.source_ip == source_ip.strip())
    if auth_failure:
        query = query.filter(ForensicReport.auth_failure == auth_failure.strip().lower())
    if delivery_result:
        query = query.filter(ForensicReport.delivery_result == delivery_result.strip().lower())

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
        reports=[
            ForensicReportResponse(
                **forensic_report_to_dict(row, redaction_policy=redaction_policy)
            )
            for row in rows
        ],
    )


@router.get("/{report_id}", response_model=ForensicReportResponse)
async def get_forensic_report(
    report_id: int,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
):
    """Return one stored forensic report by numeric ID."""
    row = (
        db.query(ForensicReport)
        .options(selectinload(ForensicReport.domain))
        .filter(ForensicReport.id == report_id)
        .first()
    )
    if row is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Forensic report not found"
        )
    redaction_policy = get_forensic_redaction_policy(db)
    return ForensicReportResponse(**forensic_report_to_dict(row, redaction_policy=redaction_policy))
