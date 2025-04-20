from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from fastapi import APIRouter, HTTPException, status, Path, Query
from pydantic import BaseModel

from app.services.report_store import ReportStore

router = APIRouter()

class DomainBase(BaseModel):
    """Base Domain schema"""
    name: str
    description: Optional[str] = None
    policy: Optional[str] = None

class DomainResponse(DomainBase):
    """Domain response schema"""
    reports_count: int = 0
    emails_count: int = 0
    compliance_rate: float = 0.0

class DomainStatsResponse(BaseModel):
    """Domain statistics for the domain details page"""
    complianceRate: float
    totalEmails: int
    failedEmails: int
    reportCount: int

class DNSRecordResponse(BaseModel):
    """DNS record information for a domain"""
    dmarc: bool
    dmarcRecord: Optional[str] = None
    spf: bool
    spfRecord: Optional[str] = None
    dkim: bool
    dkimSelectors: Optional[str] = None

class TimelinePoint(BaseModel):
    """Data point for compliance timeline"""
    date: str
    compliance_rate: float

class ReportEntry(BaseModel):
    """Summary of a DMARC report"""
    id: str
    org_name: str
    begin_date: int
    end_date: int
    total_emails: int
    pass_rate: float
    policy: str

class SourceEntry(BaseModel):
    """Summary of a sending source"""
    ip: str
    count: int
    spf: str
    dkim: str
    dmarc: str
    disposition: str

class DomainReportsResponse(BaseModel):
    """Domain reports with compliance timeline"""
    reports: List[ReportEntry]
    compliance_timeline: List[TimelinePoint]

class DomainSourcesResponse(BaseModel):
    """Domain sending sources"""
    sources: List[SourceEntry]

class DomainSummaryResponse(BaseModel):
    """Domain summary for dashboard"""
    total_domains: int
    total_emails: int
    overall_pass_rate: float
    reports_processed: int
    domains: List[Dict[str, Any]]

@router.get("/summary", response_model=DomainSummaryResponse)
async def get_domains_summary():
    """
    Get summary statistics for all domains, formatted for the dashboard.
    """
    store = ReportStore.get_instance()
    domains = store.get_domains()
    summaries = store.get_all_domain_summaries()
    
    # Calculate overall statistics
    total_domains = len(domains)
    total_emails = 0
    total_passed = 0
    total_reports = 0
    
    domains_list = []
    
    for domain_name in domains:
        summary = summaries.get(domain_name, {})
        total_emails += summary.get("total_count", 0)
        total_passed += summary.get("passed_count", 0)
        total_reports += summary.get("reports_processed", 0)
        
        # Format domain data for frontend
        domains_list.append({
            "id": domain_name,  # Using the domain name as ID for now
            "domain_name": domain_name,
            "total_emails": summary.get("total_count", 0),
            "passed_count": summary.get("passed_count", 0),
            "failed_count": summary.get("failed_count", 0),
            "pass_rate": summary.get("compliance_rate", 0),
            "report_count": summary.get("reports_processed", 0)
        })
    
    # Calculate overall pass rate
    overall_pass_rate = 0
    if total_emails > 0:
        overall_pass_rate = round((total_passed / total_emails) * 100, 1)
    
    return DomainSummaryResponse(
        total_domains=total_domains,
        total_emails=total_emails,
        overall_pass_rate=overall_pass_rate,
        reports_processed=total_reports,
        domains=domains_list
    )

@router.get("/domains", response_model=List[DomainResponse])
async def read_domains():
    """
    Retrieve domains with their statistics.
    For Milestone 1, this simply returns domains from the in-memory store.
    """
    store = ReportStore.get_instance()
    domains = store.get_domains()
    summaries = store.get_all_domain_summaries()
    
    result = []
    for domain_name in domains:
        summary = summaries.get(domain_name, {})
        domain_response = DomainResponse(
            name=domain_name,
            policy=summary.get("policy", "unknown"),
            reports_count=summary.get("reports_processed", 0),
            emails_count=summary.get("total_count", 0),
            compliance_rate=summary.get("compliance_rate", 0.0)
        )
        result.append(domain_response)
    
    return result

@router.get("/domains/{domain_name}", response_model=DomainResponse)
async def read_domain(domain_name: str):
    """
    Get statistics for a specific domain.
    """
    store = ReportStore.get_instance()
    domains = store.get_domains()
    
    if domain_name not in domains:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )
    
    summary = store.get_domain_summary(domain_name)
    
    return DomainResponse(
        name=domain_name,
        policy=summary.get("policy", "unknown"),
        reports_count=summary.get("reports_processed", 0),
        emails_count=summary.get("total_count", 0),
        compliance_rate=summary.get("compliance_rate", 0.0)
    )

# New endpoints for domain details page

@router.get("/{domain_id}/stats", response_model=DomainStatsResponse)
async def get_domain_stats(domain_id: str = Path(..., title="The domain ID or name")):
    """
    Get detailed statistics for a specific domain
    """
    store = ReportStore.get_instance()
    domains = store.get_domains()
    
    # For Milestone 1, domain_id is simply the domain name
    if domain_id not in domains:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )
    
    summary = store.get_domain_summary(domain_id)
    total_count = summary.get("total_count", 0)
    passed_count = summary.get("passed_count", 0)
    failed_count = total_count - passed_count
    compliance_rate = summary.get("compliance_rate", 0.0)
    reports_processed = summary.get("reports_processed", 0)
    
    return DomainStatsResponse(
        complianceRate=compliance_rate,
        totalEmails=total_count,
        failedEmails=failed_count,
        reportCount=reports_processed
    )

@router.get("/{domain_id}/dns", response_model=DNSRecordResponse)
async def get_domain_dns_records(domain_id: str = Path(..., title="The domain ID or name")):
    """
    Get DNS records for a specific domain. For Milestone 1, 
    this returns mock data since DNS integration is part of a future milestone.
    """
    store = ReportStore.get_instance()
    domains = store.get_domains()
    
    if domain_id not in domains:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )
    
    # For Milestone 1, return mock DNS record data
    # In a future milestone, this will be replaced with actual DNS lookups
    return DNSRecordResponse(
        dmarc=True,
        dmarcRecord="v=DMARC1; p=none; rua=mailto:dmarc@example.com; ruf=mailto:forensic@example.com; pct=100",
        spf=True,
        spfRecord="v=spf1 include:_spf.google.com include:spf.protection.outlook.com -all",
        dkim=True,
        dkimSelectors="selector1, selector2"
    )

@router.get("/{domain_id}/reports", response_model=DomainReportsResponse)
async def get_domain_reports(
    domain_id: str = Path(..., title="The domain ID or name"),
    limit: int = Query(10, title="Maximum number of reports to return")
):
    """
    Get recent DMARC reports for a specific domain, along with compliance timeline
    """
    store = ReportStore.get_instance()
    domains = store.get_domains()
    
    if domain_id not in domains:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )
    
    # Get reports for this domain
    reports = store.get_domain_reports(domain_id, limit=limit)
    
    # Generate report entries
    report_entries = []
    for report in reports:
        report_entries.append(ReportEntry(
            id=report.get("report_id", "unknown"),
            org_name=report.get("org_name", "Unknown Organization"),
            begin_date=report.get("begin_date", 0),
            end_date=report.get("end_date", 0),
            total_emails=report.get("total_count", 0),
            pass_rate=report.get("pass_rate", 0.0),
            policy=report.get("policy", "none")
        ))
    
    # Generate compliance timeline (last 30 days)
    timeline = []
    for i in range(30, 0, -1):
        date = datetime.now() - timedelta(days=i)
        date_str = date.strftime("%Y-%m-%d")
        
        # For Milestone 1, generate some mock data with variation
        # In future milestone, this will use actual historical data
        import random
        compliance_rate = random.uniform(80, 100)
        
        timeline.append(TimelinePoint(
            date=date_str,
            compliance_rate=round(compliance_rate, 1)
        ))
    
    return DomainReportsResponse(
        reports=report_entries,
        compliance_timeline=timeline
    )

@router.get("/{domain_id}/sources", response_model=DomainSourcesResponse)
async def get_domain_sources(
    domain_id: str = Path(..., title="The domain ID or name"),
    days: int = Query(30, title="Number of days to look back")
):
    """
    Get sending sources for a specific domain
    """
    store = ReportStore.get_instance()
    domains = store.get_domains()
    
    if domain_id not in domains:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )
    
    # Get sending sources for this domain
    sources = store.get_domain_sources(domain_id, days=days)
    
    source_entries = []
    for source in sources:
        source_entries.append(SourceEntry(
            ip=source.get("source_ip", "unknown"),
            count=source.get("count", 0),
            spf=source.get("spf_result", "unknown"),
            dkim=source.get("dkim_result", "unknown"),
            dmarc="pass" if source.get("spf_result") == "pass" or source.get("dkim_result") == "pass" else "fail",
            disposition=source.get("disposition", "none")
        ))
    
    return DomainSourcesResponse(
        sources=source_entries
    )