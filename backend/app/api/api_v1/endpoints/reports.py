import logging
from typing import List

from app.services.dmarc_parser import DMARCParser
from app.services.report_store import ReportStore
from app.utils.domain_validator import DomainValidationError, validate_domain
from fastapi import APIRouter, File, HTTPException, UploadFile, status
from pydantic import BaseModel

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


class PaginatedReportResponse(BaseModel):
    """Paginated reports response model"""

    total: int
    page: int
    page_size: int
    total_pages: int
    reports: List[ReportSummary]


@router.post("/upload", response_model=UploadResponse)
async def upload_report(file: UploadFile = File(...)):
    """
    Upload and process a DMARC aggregate report file (XML, ZIP, or GZIP)

    Security:
    - File type validation (extension and MIME type)
    - File size limits enforced in parser
    - Zip bomb protection
    - Sanitized error messages
    """
    try:
        # Security: Validate filename is provided
        if not file.filename:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Filename is required"
            )

        # Security: Validate file extension
        file_ext = "." + file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
        if file_ext not in ALLOWED_EXTENSIONS:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid file type. Allowed types: {', '.join(ALLOWED_EXTENSIONS)}",
            )

        # Read the file content
        file_content = await file.read()

        # Security: Validate file is not empty
        if len(file_content) == 0:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="File is empty")

        # Security: Validate MIME type using python-magic (if available)
        if HAS_MAGIC:
            try:
                mime_type = magic.from_buffer(file_content, mime=True)
                if mime_type not in ALLOWED_MIME_TYPES:
                    logger.warning(f"Rejected file with MIME type: {mime_type}")
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Invalid file type. File must be XML, ZIP, or GZIP format.",
                    )
            except Exception as e:
                # If magic fails, log but continue (fallback to extension check)
                logger.warning(f"MIME type detection failed: {str(e)}")
        else:
            logger.debug("MIME type validation skipped (python-magic not available)")

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

        # Validate domain format (not DNS resolution to avoid external calls)
        is_valid, error_msg, error_code = validate_domain(domain, check_dns=False)
        if not is_valid and error_code != DomainValidationError.DNS_RESOLUTION_FAILED:
            # Allow domains that fail DNS resolution but have valid format
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid domain in report: {error_msg}",
            )

        # Store the report
        store = ReportStore.get_instance()
        store.add_report(report)

        processed_records = report.get("summary", {}).get("total_count", 0)

        return UploadResponse(
            success=True,
            domain=domain,
            message=f"Report processed successfully for domain {domain}",
            processed_records=processed_records,
        )

    except HTTPException:
        # Re-raise HTTP exceptions as-is
        raise
    except ValueError as e:
        # Security: Sanitize error messages from parser
        error_message = str(e)
        # Log full error for debugging
        logger.error(f"ValueError processing report {file.filename}: {error_message}")
        # Return sanitized message
        if "too large" in error_message.lower():
            raise HTTPException(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE, detail="File too large"
            )
        elif "zip bomb" in error_message.lower():
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid archive file"
            )
        else:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid report format"
            )
    except Exception as e:
        # Security: Don't expose internal errors to client
        logger.error(f"Unexpected error processing report {file.filename}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Error processing report. Please contact support if this persists.",
        )


@router.get("/domains", response_model=List[str])
async def get_domains():
    """
    Get list of all domains with reports
    """
    store = ReportStore.get_instance()
    return store.get_domains()


@router.get("/domain/{domain}/summary", response_model=DomainSummary)
async def get_domain_summary(domain: str):
    """
    Get summary statistics for a specific domain
    """
    store = ReportStore.get_instance()
    summary = store.get_domain_summary(domain)

    if not summary:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail=f"No reports found for domain {domain}"
        )

    return DomainSummary(domain=domain, **summary)


@router.get("/summary", response_model=List[DomainSummary])
async def get_all_summaries():
    """
    Get summary statistics for all domains
    """
    store = ReportStore.get_instance()
    all_summaries = store.get_all_domain_summaries()

    return [DomainSummary(domain=domain, **summary) for domain, summary in all_summaries.items()]


@router.get("/domain/{domain}/reports", response_model=List[ReportSummary])
async def get_domain_reports(domain: str):
    """
    Get all reports for a specific domain
    """
    store = ReportStore.get_instance()
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
    store = ReportStore.get_instance()
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
            key=lambda r: r.get("summary", {}).get("total_count", 0), reverse=(sort_order == "desc")
        )
    else:
        all_reports.sort(key=lambda r: r.get(sort_field, ""), reverse=(sort_order == "desc"))

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
