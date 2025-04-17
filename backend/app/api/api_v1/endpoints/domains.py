from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, status
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