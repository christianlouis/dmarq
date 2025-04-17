from typing import Dict, List, Any
from fastapi import APIRouter, File, HTTPException, UploadFile, status
from pydantic import BaseModel

from app.services.dmarc_parser import DMARCParser
from app.services.report_store import ReportStore

router = APIRouter()

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

@router.post("/upload", response_model=UploadResponse)
async def upload_report(file: UploadFile = File(...)):
    """
    Upload and process a DMARC aggregate report file (XML, ZIP, or GZIP)
    """
    try:
        # Read the file content
        file_content = await file.read()
        filename = file.filename
        
        # Parse the report
        parser = DMARCParser()
        report = parser.parse_file(file_content, filename)
        
        # Store the report
        store = ReportStore.get_instance()
        store.add_report(report)
        
        domain = report.get("domain", "unknown")
        processed_records = report.get("summary", {}).get("total_count", 0)
        
        return UploadResponse(
            success=True,
            domain=domain,
            message=f"Report processed successfully for domain {domain}",
            processed_records=processed_records
        )
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Error processing report: {str(e)}"
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
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No reports found for domain {domain}"
        )
    
    return DomainSummary(
        domain=domain,
        **summary
    )

@router.get("/summary", response_model=List[DomainSummary])
async def get_all_summaries():
    """
    Get summary statistics for all domains
    """
    store = ReportStore.get_instance()
    all_summaries = store.get_all_domain_summaries()
    
    return [
        DomainSummary(domain=domain, **summary)
        for domain, summary in all_summaries.items()
    ]

@router.get("/domain/{domain}/reports", response_model=List[ReportSummary])
async def get_domain_reports(domain: str):
    """
    Get all reports for a specific domain
    """
    store = ReportStore.get_instance()
    reports = store.get_domain_reports(domain)
    
    if not reports:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No reports found for domain {domain}"
        )
    
    return [
        ReportSummary(
            report_id=report.get("report_id", ""),
            org_name=report.get("org_name", ""),
            begin_date=report.get("begin_date", ""),
            end_date=report.get("end_date", ""),
            total_count=report.get("summary", {}).get("total_count", 0),
            passed_count=report.get("summary", {}).get("passed_count", 0),
            failed_count=report.get("summary", {}).get("failed_count", 0)
        )
        for report in reports
    ]