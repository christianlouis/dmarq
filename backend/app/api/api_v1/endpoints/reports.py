import asyncio
import ipaddress
import logging
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, File, Header, HTTPException, Query, UploadFile, status
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import require_admin_auth
from app.models.domain import Domain
from app.services.dmarc_parser import DMARCParser
from app.services.dns_resolver import get_default_provider
from app.services.organizations import OrganizationPlanLimitError
from app.services.report_persistence import (
    delete_persisted_report,
    hydrate_report_store_from_db,
    report_exists,
    save_parsed_report,
)
from app.services.report_store import ReportStore
from app.services.sender_intelligence import identify_sender, source_geo_for
from app.services.source_network import (
    SourceNetworkIntelligence,
    lookup_sources_network_cached,
    merge_network_into_geo,
)
from app.services.source_reputation import (
    DomainReputation,
    SourceReputation,
    build_source_reputation_cached,
    reputation_presentation,
    source_reputation_by_ip,
)
from app.services.workspace_access import (
    PERMISSION_REPORTS_READ,
    PERMISSION_REPORTS_WRITE,
    parse_selected_workspace_id,
    resolve_authorized_workspace,
)
from app.utils.domain_validator import DomainValidationError, normalize_domain_name, validate_domain

logger = logging.getLogger(__name__)

# Try to import python-magic for MIME type detection
try:
    import magic

    HAS_MAGIC = True
except ImportError:
    HAS_MAGIC = False
    logger.warning("python-magic not installed. MIME type validation will be skipped.")

router = APIRouter()

# Security: Allowed MIME types for DMARC report uploads
ALLOWED_MIME_TYPES = {
    "text/xml",
    "application/xml",
    "application/zip",
    "application/x-zip-compressed",
    "application/gzip",
    "application/x-gzip",
    "application/octet-stream",  # Sometimes zip/gzip are detected as this
}

# Security: Allowed file extensions
ALLOWED_EXTENSIONS = {".xml", ".zip", ".gz", ".gzip"}


def _authorized_reports_workspace(
    auth_context: Dict[str, Any],
    db: Session,
    permission: str,
    selected_workspace_id: Optional[int] = None,
):
    """Authorize report access before running legacy workspace repair writes."""
    return resolve_authorized_workspace(
        db,
        auth_context,
        permission,
        selected_workspace_id=selected_workspace_id,
    )


def _selected_workspace_id(selected_workspace: Optional[str]) -> Optional[int]:
    return parse_selected_workspace_id(selected_workspace)


def _domain_workspace_conflict(domain: str) -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_409_CONFLICT,
        detail=(
            f"Domain '{domain}' already belongs to another workspace. "
            "Move or rename the domain before uploading reports for this workspace."
        ),
    )


def _raise_if_domain_owned_by_other_workspace(db: Session, domain: str, workspace_id: int) -> None:
    existing_domain = db.query(Domain).filter(Domain.name == domain).first()
    if existing_domain is not None and existing_domain.workspace_id != workspace_id:
        raise _domain_workspace_conflict(domain)


def _raise_plan_limit_payment_required(db: Session, exc: OrganizationPlanLimitError) -> None:
    db.rollback()
    raise HTTPException(
        status_code=status.HTTP_402_PAYMENT_REQUIRED,
        detail=exc.to_detail(),
    ) from exc


def _save_uploaded_report(
    db: Session, report: Dict[str, Any], domain: str, workspace_id: int
) -> None:
    try:
        save_parsed_report(db, report, workspace_id=workspace_id)
        db.commit()
    except OrganizationPlanLimitError as exc:
        _raise_plan_limit_payment_required(db, exc)
    except IntegrityError as exc:
        db.rollback()
        try:
            _raise_if_domain_owned_by_other_workspace(db, domain, workspace_id)
        except HTTPException as conflict:
            raise conflict from exc
        try:
            save_parsed_report(db, report, workspace_id=workspace_id)
            db.commit()
        except OrganizationPlanLimitError as plan_exc:
            _raise_plan_limit_payment_required(db, plan_exc)


def _hydrated_report_store(db: Session, workspace) -> ReportStore:
    store = ReportStore()
    hydrate_report_store_from_db(db, store, workspace_id=workspace.id)
    return store


def _validate_mime_type(file_content: bytes) -> None:
    """Validate the MIME type of the uploaded file using python-magic.

    No-ops silently when python-magic is unavailable.
    Raises HTTPException on a disallowed MIME type.
    """
    if not HAS_MAGIC:
        logger.debug("MIME type validation skipped (python-magic not available)")
        return
    try:
        mime_type = magic.from_buffer(file_content, mime=True)
        if mime_type not in ALLOWED_MIME_TYPES:
            logger.warning("Rejected file with MIME type: %s", mime_type)
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Invalid file type. File must be XML, ZIP, or GZIP format.",
            )
    except HTTPException:
        raise
    except Exception as e:  # pylint: disable=broad-exception-caught
        # If magic fails, log but continue (fallback to extension check)
        logger.warning("MIME type detection failed: %s", str(e))


def _validate_upload_file(file: UploadFile, file_content: bytes) -> None:
    """Run all pre-parse validation checks on an uploaded file.

    Raises HTTPException for any validation failure.
    """
    # Security: Validate filename is provided
    if not file.filename:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Filename is required")

    # Security: Validate file extension
    file_ext = "." + file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if file_ext not in ALLOWED_EXTENSIONS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid file type. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}",
        )

    # Security: Validate file is not empty
    if len(file_content) == 0:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is empty")

    # Security: Validate MIME type (if python-magic is available)
    _validate_mime_type(file_content)


def _handle_upload_value_error(filename: str, error_message: str) -> None:
    """Translate a parser ValueError into a sanitized HTTPException.

    Always raises — never returns.
    """
    logger.error("ValueError processing report %s: %s", filename, error_message)
    if "too large" in error_message.lower():
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="File too large"
        )
    if "zip bomb" in error_message.lower():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid archive file")
    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid report format")


class UploadResponse(BaseModel):
    """Response model for report upload"""

    success: bool
    domain: str
    message: str
    processed_records: int = 0  # Added this field to track processed records


class DomainSummary(BaseModel):
    """Domain summary response model"""

    domain: str
    total_count: int
    passed_count: int
    failed_count: int
    reports_processed: int
    compliance_rate: float


class ReportSummary(BaseModel):
    """DMARC report summary model"""

    report_id: str
    org_name: str
    begin_date: str
    end_date: str
    total_count: int
    passed_count: int
    failed_count: int


class AllReportsItem(BaseModel):
    """Single report item for the cross-domain reports list"""

    report_id: str
    domain: str
    org_name: str
    begin_date: str
    end_date: str
    total_count: int
    passed_count: int
    failed_count: int
    pass_rate: float


class PaginatedReportResponse(BaseModel):
    """Paginated reports response model"""

    total: int
    page: int
    page_size: int
    total_pages: int
    reports: List[ReportSummary]


@router.post("/upload", response_model=UploadResponse)
async def upload_report(
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
):
    """
    Upload and process a DMARC aggregate report file (XML, ZIP, or GZIP)

    Security:
    - File type validation (extension and MIME type)
    - File size limits enforced in parser
    - Zip bomb protection
    - Sanitized error messages
    """
    workspace = _authorized_reports_workspace(
        _auth,
        db,
        PERMISSION_REPORTS_WRITE,
        _selected_workspace_id(selected_workspace),
    )
    try:
        # Read content first so validators can inspect it
        file_content = await file.read()
        _validate_upload_file(file, file_content)

        # Parse the report
        parser = DMARCParser()
        report = parser.parse_file(file_content, file.filename)

        # Security: Validate domain from report
        domain = report.get("domain", "")
        if not domain:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Report does not contain a valid domain",
            )
        domain = normalize_domain_name(domain)
        report["domain"] = domain

        # Validate domain format (not DNS resolution to avoid external calls)
        is_valid, error_msg, error_code = validate_domain(domain, check_dns=False)
        if not is_valid and error_code != DomainValidationError.DNS_RESOLUTION_FAILED:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid domain in report: {error_msg}",
            )

        # Check for duplicate report before storing
        report_id = report.get("report_id", "")
        if report_id and report_exists(db, domain, report_id, workspace_id=workspace.id):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=(
                    f"Report '{report_id}' for domain '{domain}' has already been uploaded. "
                    "Duplicate reports are not stored to keep statistics accurate."
                ),
            )

        _raise_if_domain_owned_by_other_workspace(db, domain, workspace.id)

        # Store the report
        _save_uploaded_report(db, report, domain, workspace.id)

        processed_records = report.get("summary", {}).get("total_count", 0)

        return UploadResponse(
            success=True,
            domain=domain,
            message=f"Report processed successfully for domain {domain}",
            processed_records=processed_records,
        )

    except HTTPException:
        raise
    except ValueError as e:
        # Security: Sanitize error messages from parser
        _handle_upload_value_error(file.filename, str(e))
    except Exception as e:  # pylint: disable=broad-exception-caught
        # Security: Don't expose internal errors to client
        logger.error("Unexpected error processing report %s: %s", file.filename, str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error processing report. Please contact support if this persists.",
        ) from e


@router.get("", response_model=List[AllReportsItem])
async def get_all_reports(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
):
    """
    Get all DMARC reports across all domains, sorted by end_date descending.
    """
    workspace = _authorized_reports_workspace(
        _auth,
        db,
        PERMISSION_REPORTS_READ,
        _selected_workspace_id(selected_workspace),
    )
    store = _hydrated_report_store(db, workspace)
    domains = store.get_domains()

    all_reports: List[AllReportsItem] = []
    for domain in domains:
        domain_reports = store.get_domain_reports(domain)
        for report in domain_reports:
            summary = report.get("summary", {})
            total = summary.get("total_count", 0)
            passed = summary.get("passed_count", 0)
            pass_rate = round(passed / total * 100, 1) if total > 0 else 0.0
            all_reports.append(
                AllReportsItem(
                    report_id=report.get("report_id", ""),
                    domain=domain,
                    org_name=report.get("org_name", ""),
                    begin_date=str(report.get("begin_date", "")),
                    end_date=str(report.get("end_date", "")),
                    total_count=total,
                    passed_count=passed,
                    failed_count=summary.get("failed_count", 0),
                    pass_rate=pass_rate,
                )
            )

    # end_date is stored in ISO 8601 format (YYYY-MM-DDTHH:MM:SS), so lexicographic
    # sorting produces correct chronological order.
    all_reports.sort(key=lambda r: r.end_date, reverse=True)
    return all_reports


@router.get("/domains", response_model=List[str])
async def get_domains(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
):
    """
    Get list of all domains with reports
    """
    workspace = _authorized_reports_workspace(
        _auth,
        db,
        PERMISSION_REPORTS_READ,
        _selected_workspace_id(selected_workspace),
    )
    store = _hydrated_report_store(db, workspace)
    return store.get_domains()


@router.get("/domain/{domain}/summary", response_model=DomainSummary)
async def get_domain_summary(
    domain: str,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
):
    """
    Get summary statistics for a specific domain
    """
    workspace = _authorized_reports_workspace(
        _auth,
        db,
        PERMISSION_REPORTS_READ,
        _selected_workspace_id(selected_workspace),
    )
    store = _hydrated_report_store(db, workspace)
    summary = store.get_domain_summary(domain)

    if not summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"No reports found for domain {domain}"
        )

    return DomainSummary(domain=domain, **summary)


@router.get("/summary", response_model=List[DomainSummary])
async def get_all_summaries(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
):
    """
    Get summary statistics for all domains
    """
    workspace = _authorized_reports_workspace(
        _auth,
        db,
        PERMISSION_REPORTS_READ,
        _selected_workspace_id(selected_workspace),
    )
    store = _hydrated_report_store(db, workspace)
    all_summaries = store.get_all_domain_summaries()

    return [DomainSummary(domain=domain, **summary) for domain, summary in all_summaries.items()]


@router.get("/domain/{domain}/reports", response_model=List[ReportSummary])
async def get_domain_reports(
    domain: str,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
):
    """
    Get all reports for a specific domain
    """
    workspace = _authorized_reports_workspace(
        _auth,
        db,
        PERMISSION_REPORTS_READ,
        _selected_workspace_id(selected_workspace),
    )
    store = _hydrated_report_store(db, workspace)
    reports = store.get_domain_reports(domain)

    if not reports:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"No reports found for domain {domain}"
        )

    return [
        ReportSummary(
            report_id=report.get("report_id", ""),
            org_name=report.get("org_name", ""),
            begin_date=report.get("begin_date", ""),
            end_date=report.get("end_date", ""),
            total_count=report.get("summary", {}).get("total_count", 0),
            passed_count=report.get("summary", {}).get("passed_count", 0),
            failed_count=report.get("summary", {}).get("failed_count", 0),
        )
        for report in reports
    ]


@router.get("/domain/{domain}/reports/paginated", response_model=PaginatedReportResponse)
async def get_domain_reports_paginated(
    domain: str,
    page: int = 1,
    page_size: int = 10,
    sort_by: str = "end_date",
    sort_order: str = "desc",
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
):
    """
    Get paginated reports for a specific domain with sorting options

    Args:
        domain: Domain name
        page: Page number (1-based)
        page_size: Number of reports per page
        sort_by: Field to sort by (report_id, org_name, begin_date, end_date, total_count)
        sort_order: Sort order (asc or desc)
    """
    workspace = _authorized_reports_workspace(
        _auth,
        db,
        PERMISSION_REPORTS_READ,
        _selected_workspace_id(selected_workspace),
    )
    store = _hydrated_report_store(db, workspace)
    all_reports = store.get_domain_reports(domain)

    if not all_reports:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"No reports found for domain {domain}"
        )

    # Apply sorting
    valid_sort_fields = ["report_id", "org_name", "begin_date", "end_date", "total_count"]
    sort_field = sort_by if sort_by in valid_sort_fields else "end_date"

    if sort_field == "total_count":
        all_reports.sort(
            key=lambda r: r.get("summary", {}).get("total_count", 0),
            reverse=sort_order == "desc",
        )
    else:
        all_reports.sort(key=lambda r: r.get(sort_field, ""), reverse=sort_order == "desc")

    # Apply pagination
    total = len(all_reports)
    total_pages = (total + page_size - 1) // page_size
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    paginated_reports = all_reports[start_idx:end_idx]

    # Format reports
    report_entries = [
        ReportSummary(
            report_id=report.get("report_id", ""),
            org_name=report.get("org_name", ""),
            begin_date=report.get("begin_date", ""),
            end_date=report.get("end_date", ""),
            total_count=report.get("summary", {}).get("total_count", 0),
            passed_count=report.get("summary", {}).get("passed_count", 0),
            failed_count=report.get("summary", {}).get("failed_count", 0),
        )
        for report in paginated_reports
    ]

    return PaginatedReportResponse(
        total=total, page=page, page_size=page_size, total_pages=total_pages, reports=report_entries
    )


class DeleteReportResponse(BaseModel):
    """Response model for report deletion"""

    success: bool
    message: str


@router.delete(
    "/domain/{domain}/reports/{report_id}",
    response_model=DeleteReportResponse,
)
async def delete_report(
    domain: str,
    report_id: str,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
):
    """
    Delete a single DMARC report for a domain.

    Removes the report from the store and recomputes all domain statistics so
    that aggregated numbers remain accurate after deletion.
    """
    workspace = _authorized_reports_workspace(
        _auth,
        db,
        PERMISSION_REPORTS_WRITE,
        _selected_workspace_id(selected_workspace),
    )
    deleted_from_db = delete_persisted_report(db, domain, report_id, workspace_id=workspace.id)
    if deleted_from_db:
        db.commit()
    deleted = deleted_from_db

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report '{report_id}' not found for domain '{domain}'.",
        )

    return DeleteReportResponse(
        success=True,
        message=f"Report '{report_id}' for domain '{domain}' deleted successfully.",
    )


class ReportRecordDetail(BaseModel):
    """Detailed record from a DMARC report"""

    source_ip: str
    count: int
    disposition: str
    dkim_result: str
    spf_result: str
    header_from: str
    spf: Optional[List[Dict[str, Any]]] = None
    dkim: Optional[List[Dict[str, Any]]] = None
    review_status: str = "pass"
    failure_reasons: List[str] = Field(default_factory=list)
    next_steps: List[str] = Field(default_factory=list)
    source_details: Dict[str, Any] = Field(default_factory=dict)
    reputation: Optional[Dict[str, Any]] = None


class ReportPolicyDetail(BaseModel):
    """Published policy from a DMARC report"""

    p: str
    sp: str = ""
    pct: str = "100"


class ReportSummaryDetail(BaseModel):
    """Summary statistics for a DMARC report"""

    total_count: int
    passed_count: int
    failed_count: int
    pass_rate: float


class ReportEnrichmentStatus(BaseModel):
    """Bounded enrichment outcome for report-detail progressive hydration."""

    status: str = "complete"
    pending: bool = False
    ptr: str = "complete"
    network: str = "complete"
    reputation: str = "complete"
    unique_source_ips: int = 0
    record_count: int = 0


class ReportDetail(BaseModel):
    """Full detail of a single DMARC report"""

    report_id: str
    org_name: str
    email: str
    domain: str
    begin_date: str
    end_date: str
    begin_timestamp: int
    end_timestamp: int
    policy: ReportPolicyDetail
    records: List[ReportRecordDetail]
    summary: ReportSummaryDetail
    reputation_summary: Dict[str, Any] = Field(default_factory=dict)
    enrichment: ReportEnrichmentStatus = Field(default_factory=ReportEnrichmentStatus)


def _record_review_guidance(record: Dict[str, Any]) -> Dict[str, Any]:
    """Return evidence-first operator guidance for one aggregate report row."""
    disposition = str(record.get("disposition") or "none").lower()
    dkim_result = str(record.get("dkim_result") or "").lower()
    spf_result = str(record.get("spf_result") or "").lower()
    header_from = str(record.get("header_from") or "").lower()
    source_ip = str(record.get("source_ip") or "this source")

    reasons: List[str] = []
    steps: List[str] = []
    if disposition in {"reject", "quarantine"}:
        reasons.append(f"Receiver applied DMARC disposition '{disposition}'.")
        steps.append(
            "Check Header From alignment against the authenticated DKIM/SPF domains before changing DNS."
        )
    if dkim_result and dkim_result != "pass":
        reasons.append("DKIM did not pass for this source.")
        steps.append("Check the DKIM selector in this report against the sender's DNS record.")
    if spf_result and spf_result != "pass":
        reasons.append("SPF did not pass for this source.")
        steps.append("Confirm whether this IP is authorized by the domain's SPF policy.")
    if header_from and "." in header_from:
        steps.append(f"Confirm that {header_from} is an intended Header From domain.")

    if not reasons:
        return {
            "review_status": "pass",
            "failure_reasons": [],
            "next_steps": [],
        }

    steps.append(f"Open the domain sending-source view and review {source_ip} across reports.")
    steps.append("Only change DNS after confirming whether this is a legitimate sender.")
    return {
        "review_status": "needs_review",
        "failure_reasons": reasons,
        "next_steps": list(dict.fromkeys(steps)),
    }


async def _safe_ptr_lookup(provider: Any, ip: str, timeout: float = 3.0) -> Optional[str]:
    """Return reverse DNS for an IP without letting enrichment break report loading."""
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None
    try:
        return await asyncio.wait_for(provider.lookup_ptr(ip), timeout=timeout)
    except Exception:
        return None


def _unique_source_ips(ips: List[str]) -> List[str]:
    """Preserve first-seen order while collapsing duplicate report-row IPs."""
    return list(dict.fromkeys(ips))


async def _ptr_lookups_by_ip(
    provider: Any,
    unique_ips: List[str],
    *,
    concurrency: int = 20,
) -> Dict[str, Optional[str]]:
    """Resolve PTR hostnames once per unique IP with bounded concurrency."""
    semaphore = asyncio.Semaphore(max(1, concurrency))

    async def _lookup(ip: str) -> tuple[str, Optional[str]]:
        async with semaphore:
            return ip, await _safe_ptr_lookup(provider, ip)

    pairs = await asyncio.gather(*[_lookup(ip) for ip in unique_ips])
    return dict(pairs)


async def _report_networks_by_ip(
    db: Session,
    provider: Any,
    unique_ips: List[str],
    settings: Any,
) -> tuple[Dict[str, SourceNetworkIntelligence], str]:
    """Batch network enrichment with a hard detail-path timeout."""
    if not settings.SOURCE_NETWORK_ENRICHMENT_ENABLED:
        return {}, "disabled"
    try:
        networks = await asyncio.wait_for(
            lookup_sources_network_cached(
                db,
                provider,
                unique_ips,
                ttl_seconds=settings.SOURCE_NETWORK_ENRICHMENT_CACHE_SECONDS,
                max_ips=settings.SOURCE_NETWORK_ENRICHMENT_MAX_IPS,
            ),
            timeout=max(
                0.5,
                float(settings.SOURCE_NETWORK_ENRICHMENT_DETAIL_TIMEOUT_SECONDS),
            ),
        )
        return networks, "complete"
    except asyncio.TimeoutError:
        logger.info("Report source network enrichment timed out for report detail")
        return {}, "timed_out"
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.info(
            "Report source network enrichment failed for report detail: %s",
            type(exc).__name__,
        )
        return {}, "failed"


async def _report_reputations_by_ip(
    db: Session,
    domain_name: str,
    report: Dict[str, Any],
    source_rows: List[Dict[str, Any]],
    sender_by_ip: Dict[str, Dict[str, Any]],
    *,
    refresh: bool,
    settings: Any,
) -> tuple[Optional[DomainReputation], Dict[str, SourceReputation], str]:
    """Build reputation evidence with a hard detail-path timeout."""
    try:
        reputation_result, _, _ = await asyncio.wait_for(
            build_source_reputation_cached(
                db,
                domain_name,
                [report],
                source_rows,
                senders_by_ip=sender_by_ip,
                anomalies_by_ip={},
                days=1,
                refresh=refresh,
            ),
            timeout=max(
                0.5,
                float(settings.SOURCE_REPUTATION_DETAIL_TIMEOUT_SECONDS) * (2 if refresh else 1),
            ),
        )
        return reputation_result, source_reputation_by_ip(reputation_result), "complete"
    except asyncio.TimeoutError:
        logger.info("Report source reputation enrichment timed out for report detail")
        return None, {}, "timed_out"
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.info(
            "Report source reputation enrichment failed for report detail: %s",
            type(exc).__name__,
        )
        _raise_refresh_reputation_failure(refresh, exc)
        return None, {}, "failed"


def _report_enrichment_status(
    *,
    ptr_status: str,
    network_status: str,
    reputation_status: str,
    unique_source_ips: int,
    record_count: int,
) -> ReportEnrichmentStatus:
    pending_states = {"timed_out", "pending"}
    pending = network_status in pending_states or reputation_status in pending_states
    if pending:
        overall = "partial"
    elif "failed" in {network_status, reputation_status, ptr_status}:
        overall = "partial"
    elif network_status == "disabled" and reputation_status == "complete":
        overall = "complete"
    else:
        overall = "complete"
    return ReportEnrichmentStatus(
        status=overall,
        pending=pending,
        ptr=ptr_status,
        network=network_status,
        reputation=reputation_status,
        unique_source_ips=unique_source_ips,
        record_count=record_count,
    )


def _raise_refresh_reputation_failure(refresh_reputation: bool, exc: Exception) -> None:
    if not refresh_reputation:
        return
    raise HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail="Source reputation could not be refreshed.",
    ) from exc


def _source_row_from_report_record(record: Dict[str, Any]) -> Dict[str, Any]:
    """Convert one report record into the source-row shape used by reputation scoring."""
    count = int(record.get("count") or 0)
    spf_result = str(record.get("spf_result") or "unknown").lower()
    dkim_result = str(record.get("dkim_result") or "unknown").lower()
    dmarc_pass = spf_result == "pass" or dkim_result == "pass"
    row = dict(record)
    row.update(
        {
            "source_ip": str(record.get("source_ip") or "unknown"),
            "count": count,
            "spf_result": spf_result,
            "dkim_result": dkim_result,
            "dmarc_result": "pass" if dmarc_pass else "fail",
            "spf_pass_count": count if spf_result == "pass" else 0,
            "spf_fail_count": count if spf_result == "fail" else 0,
            "dkim_pass_count": count if dkim_result == "pass" else 0,
            "dkim_fail_count": count if dkim_result == "fail" else 0,
            "dmarc_pass_count": count if dmarc_pass else 0,
            "dmarc_fail_count": 0 if dmarc_pass else count,
        }
    )
    return row


def _source_reputation_dict(item: SourceReputation) -> Dict[str, Any]:
    """Return a template-friendly reputation payload."""
    presentation = reputation_presentation(item)
    return {
        "ip": item.ip,
        "status": item.status,
        "status_label": presentation.status_label,
        "status_detail": presentation.status_detail,
        "risk_score": item.risk_score,
        "summary": item.summary,
        "evidence_summary": presentation.evidence_summary,
        "feed_status": presentation.feed_status,
        "feed_summary": presentation.feed_summary,
        "listings": item.listings,
        "evidence": [
            {"label": evidence.label, "value": evidence.value, "source": evidence.source}
            for evidence in item.evidence
        ],
        "recommendations": item.recommendations,
        "checked_at": item.checked_at,
    }


def _empty_report_reputation_summary() -> Dict[str, Any]:
    return {
        "status": "unavailable",
        "status_label": "Reputation unavailable",
        "status_detail": "Sender reputation could not be calculated for this report.",
        "total_sources": 0,
        "listed_sources": 0,
        "sources_needing_review": 0,
        "clean_sources": 0,
        "unknown_sources": 0,
        "highest_risk_score": None,
        "feed_status": "unavailable",
        "feed_summary": "No reputation evidence is available.",
        "checked_at": "",
        "worst_source": None,
        "recommendations": [],
    }


def _report_reputation_status(
    sources: List[SourceReputation], listed_sources: int, review_sources: int
) -> Dict[str, str]:
    if listed_sources:
        return {
            "status": "listed",
            "status_label": "Listed sender detected",
            "status_detail": "At least one sending IP has reputation listing evidence.",
        }
    if review_sources:
        return {
            "status": "attention",
            "status_label": "Sender review needed",
            "status_detail": "At least one sending IP has risk signals that need review.",
        }
    if sources:
        return {
            "status": "clean",
            "status_label": "No reputation findings",
            "status_detail": "No configured reputation feed or local signal flagged these sources.",
        }
    return {
        "status": "unknown",
        "status_label": "No sending sources",
        "status_detail": "This report does not contain sending-source records.",
    }


def _report_feed_summary(sources: List[SourceReputation]) -> Dict[str, str]:
    feed_statuses = [reputation_presentation(item).feed_status for item in sources]
    if "listed" in feed_statuses:
        return {
            "feed_status": "listed",
            "feed_summary": "At least one reputation feed returned a listing.",
        }
    if "error" in feed_statuses:
        return {
            "feed_status": "error",
            "feed_summary": "One or more reputation lookups returned errors.",
        }
    if "checked" in feed_statuses:
        return {
            "feed_status": "checked",
            "feed_summary": "External reputation feeds checked without listings.",
        }
    if "not_configured" in feed_statuses:
        return {
            "feed_status": "not_configured",
            "feed_summary": "External reputation feeds are not configured.",
        }
    if "local_only" in feed_statuses:
        return {
            "feed_status": "local_only",
            "feed_summary": "Using local DMARC evidence only; external feeds are not enabled.",
        }
    return {"feed_status": "unknown", "feed_summary": "No reputation feed evidence is available."}


def _report_reputation_recommendations(sources: List[SourceReputation]) -> List[str]:
    recommendations: List[str] = []
    for source in sources:
        for recommendation in source.recommendations:
            if recommendation not in recommendations:
                recommendations.append(recommendation)
            if len(recommendations) >= 3:
                break
        if len(recommendations) >= 3:
            break
    return recommendations


def _report_worst_source(worst: Optional[SourceReputation]) -> Optional[Dict[str, Any]]:
    if not worst:
        return None
    worst_view = reputation_presentation(worst)
    return {
        "ip": worst.ip,
        "status": worst.status,
        "status_label": worst_view.status_label,
        "risk_score": worst.risk_score,
        "summary": worst.summary,
        "listings": worst.listings,
    }


def _report_reputation_summary(result: Optional[DomainReputation]) -> Dict[str, Any]:
    """Return a report-level sender reputation summary for the detail page."""
    if result is None:
        return _empty_report_reputation_summary()

    sources = list(result.sources or [])
    summary = dict(result.summary or {})
    listed_sources = int(summary.get("listed") or 0)
    review_sources = int(summary.get("suspicious") or 0)
    highest_risk_score = summary.get("highest_risk_score")
    if highest_risk_score is None and sources:
        highest_risk_score = max(source.risk_score for source in sources)
    status_view = _report_reputation_status(sources, listed_sources, review_sources)

    return {
        **status_view,
        "total_sources": int(summary.get("total_sources") or len(sources)),
        "listed_sources": listed_sources,
        "sources_needing_review": review_sources,
        "clean_sources": int(summary.get("clean") or 0),
        "unknown_sources": int(summary.get("unknown") or 0),
        "highest_risk_score": highest_risk_score,
        **_report_feed_summary(sources),
        "checked_at": result.checked_at,
        "worst_source": _report_worst_source(sources[0] if sources else None),
        "recommendations": _report_reputation_recommendations(sources),
    }


def _source_details(
    ip: str,
    record: Dict[str, Any],
    hostname: Optional[str],
    sender: Dict[str, Any],
    network: Optional[SourceNetworkIntelligence] = None,
) -> Dict[str, Any]:
    geo = merge_network_into_geo(source_geo_for(ip, record), network)
    return {
        "hostname": hostname,
        "sender": sender,
        "country": geo.get("country"),
        "country_code": geo.get("country_code"),
        "region": geo.get("region"),
        "asn": geo.get("asn"),
        "network": geo.get("network"),
        "bgp_prefix": geo.get("bgp_prefix"),
        "city": geo.get("city"),
        "latitude": geo.get("latitude"),
        "longitude": geo.get("longitude"),
        "registry": geo.get("registry"),
        "allocated": geo.get("allocated"),
        "organization": geo.get("organization"),
        "domain": geo.get("domain"),
        "cloudflare_location": geo.get("cloudflare_location"),
        "cloudflare_asn_name": geo.get("cloudflare_asn_name"),
        "cloudflare_asn_org_name": geo.get("cloudflare_asn_org_name"),
        "radar_url": geo.get("radar_url"),
        "network_source": geo.get("network_source"),
        "network_checked_at": geo.get("network_checked_at"),
        "network_error": geo.get("network_error"),
        "geo_source": geo.get("source"),
    }


@router.get("/{report_id}", response_model=ReportDetail)
async def get_report_by_id(
    report_id: str,
    refresh_reputation: bool = Query(False, title="Refresh cached source reputation evidence"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
):
    """
    Get full details for a single DMARC report by its report ID.
    """
    workspace = _authorized_reports_workspace(
        _auth,
        db,
        PERMISSION_REPORTS_READ,
        _selected_workspace_id(selected_workspace),
    )
    store = _hydrated_report_store(db, workspace)
    report = store.get_report_by_id(report_id)

    if report is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report '{report_id}' not found.",
        )

    # Normalize the policy field
    policy_val = report.get("policy", {})
    if isinstance(policy_val, str):
        policy_val = {"p": policy_val, "sp": "", "pct": "100"}
    policy_detail = ReportPolicyDetail(
        p=policy_val.get("p", "none"),
        sp=policy_val.get("sp", ""),
        pct=str(policy_val.get("pct", "100")),
    )

    raw_records = list(report.get("records", []))
    source_rows = [_source_row_from_report_record(rec) for rec in raw_records]
    provider = get_default_provider(db)
    settings = get_settings()
    ips = [str(row.get("source_ip") or "unknown") for row in source_rows]
    unique_ips = _unique_source_ips(ips)

    # Evidence first: PTR and network enrichment run in parallel, each bounded.
    # PTR is deduped to one lookup per unique IP (not per report row).
    ptr_task = asyncio.create_task(_ptr_lookups_by_ip(provider, unique_ips))
    network_task = asyncio.create_task(
        _report_networks_by_ip(db, provider, unique_ips, settings)
    )
    hostnames_by_ip, (networks_by_ip, network_status) = await asyncio.gather(
        ptr_task, network_task
    )
    hostnames = [hostnames_by_ip.get(ip) for ip in ips]
    ptr_status = "complete"

    sender_by_ip = {
        ip: identify_sender(ip, row, hostname=hostname, domain=report.get("domain", ""))
        for ip, row, hostname in zip(ips, source_rows, hostnames, strict=True)
    }
    reputation_result, reputations_by_ip, reputation_status = await _report_reputations_by_ip(
        db,
        str(report.get("domain", "")),
        report,
        source_rows,
        sender_by_ip,
        refresh=refresh_reputation,
        settings=settings,
    )

    # Normalize records
    record_details = []
    for rec, row, hostname in zip(raw_records, source_rows, hostnames, strict=True):
        ip = str(row.get("source_ip") or "unknown")
        guidance = _record_review_guidance(rec)
        reputation = reputations_by_ip.get(ip)
        record_details.append(
            ReportRecordDetail(
                source_ip=rec.get("source_ip", ""),
                count=rec.get("count", 0),
                disposition=rec.get("disposition", "none"),
                dkim_result=rec.get("dkim_result", ""),
                spf_result=rec.get("spf_result", ""),
                header_from=rec.get("header_from", ""),
                spf=rec.get("spf") if isinstance(rec.get("spf"), list) else None,
                dkim=rec.get("dkim") if isinstance(rec.get("dkim"), list) else None,
                source_details=_source_details(
                    ip,
                    rec,
                    hostname,
                    sender_by_ip.get(ip, {}),
                    networks_by_ip.get(ip),
                ),
                reputation=_source_reputation_dict(reputation) if reputation else None,
                **guidance,
            )
        )

    raw_summary = report.get("summary", {})
    summary_detail = ReportSummaryDetail(
        total_count=raw_summary.get("total_count", 0),
        passed_count=raw_summary.get("passed_count", 0),
        failed_count=raw_summary.get("failed_count", 0),
        pass_rate=raw_summary.get("pass_rate", 0.0),
    )
    enrichment = _report_enrichment_status(
        ptr_status=ptr_status,
        network_status=network_status,
        reputation_status=reputation_status,
        unique_source_ips=len(unique_ips),
        record_count=len(raw_records),
    )

    return ReportDetail(
        report_id=report.get("report_id", ""),
        org_name=report.get("org_name", ""),
        email=report.get("email", ""),
        domain=report.get("domain", ""),
        begin_date=str(report.get("begin_date", "")),
        end_date=str(report.get("end_date", "")),
        begin_timestamp=report.get("begin_timestamp", 0),
        end_timestamp=report.get("end_timestamp", 0),
        policy=policy_detail,
        records=record_details,
        summary=summary_detail,
        reputation_summary=_report_reputation_summary(reputation_result),
        enrichment=enrichment,
    )
