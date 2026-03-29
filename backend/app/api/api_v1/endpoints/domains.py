import asyncio
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.domain import Domain
from app.services.dns_resolver import (
    DomainDNSResult,
    extract_dmarc_policy,
    get_default_provider,
)
from app.services.report_store import ReportStore

logger = logging.getLogger(__name__)

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


class SelectorRequest(BaseModel):
    """Request body for adding a DKIM selector"""

    selector: str = Field(..., min_length=1, description="DKIM selector name")


def _get_selectors_from_reports(store: "ReportStore", domain: str) -> List[str]:
    """Extract DKIM selectors seen in stored DMARC reports for *domain*.

    DMARC aggregate report records include DKIM auth results that carry the
    selector used by the sending server.  Collecting these gives us a set of
    real-world selectors to verify against live DNS, in addition to any
    manually configured selectors.
    """
    selectors: List[str] = []
    for report in store.get_domain_reports(domain):
        for record in report.get("records", []):
            for dkim_entry in record.get("dkim", []):
                sel = dkim_entry.get("selector", "").strip()
                if sel and sel not in selectors:
                    selectors.append(sel)
    return selectors


def _get_domain_selectors_from_db(db: Session, domain_name: str) -> List[str]:
    """Return the manually configured DKIM selectors for *domain_name* from the DB."""
    domain_db = db.query(Domain).filter(Domain.name == domain_name).first()
    if domain_db and domain_db.dkim_selectors:
        return [s.strip() for s in domain_db.dkim_selectors.split(",") if s.strip()]
    return []


@router.get("/summary", response_model=DomainSummaryResponse)
async def get_domains_summary(db: Session = Depends(get_db)):
    """
    Get summary statistics for all domains, formatted for the dashboard.

    Performs live DNS lookups for each domain concurrently and includes the
    results (DMARC/SPF/DKIM status and live DMARC policy) in the per-domain
    entries.  A per-domain timeout of 10 s prevents slow DNS responses from
    blocking the page load.
    """
    store = ReportStore.get_instance()
    domains = store.get_domains()
    summaries = store.get_all_domain_summaries()

    # Perform DNS checks concurrently for all domains
    provider = get_default_provider()

    async def _dns_for_domain(domain_name: str) -> DomainDNSResult:
        manual_selectors = _get_domain_selectors_from_db(db, domain_name)
        report_selectors = _get_selectors_from_reports(store, domain_name)
        combined = list(dict.fromkeys(manual_selectors + report_selectors))
        try:
            return await asyncio.wait_for(
                provider.check_domain(domain_name, selectors=combined),
                timeout=10.0,
            )
        except (asyncio.TimeoutError, LookupError, OSError) as exc:
            logger.warning("DNS check failed for %s: %s", domain_name, exc)
            return DomainDNSResult()

    dns_results = await asyncio.gather(*[_dns_for_domain(d) for d in domains])

    # Calculate overall statistics
    total_domains = len(domains)
    total_emails = 0
    total_passed = 0
    total_reports = 0

    domains_list = []

    for domain_name, dns in zip(domains, dns_results):
        summary = summaries.get(domain_name, {})
        total_emails += summary.get("total_count", 0)
        total_passed += summary.get("passed_count", 0)
        total_reports += summary.get("reports_processed", 0)

        # Prefer live DNS policy; fall back to policy seen in reports
        live_policy = extract_dmarc_policy(dns.dmarc_record)
        reported_policy = summary.get("policy", {})
        if isinstance(reported_policy, dict):
            reported_policy = reported_policy.get("p")
        dmarc_policy = live_policy or reported_policy or "none"

        # Format domain data for frontend
        domains_list.append(
            {
                "id": domain_name,
                "domain_name": domain_name,
                "total_emails": summary.get("total_count", 0),
                "passed_count": summary.get("passed_count", 0),
                "failed_count": summary.get("failed_count", 0),
                "pass_rate": summary.get("compliance_rate", 0),
                "report_count": summary.get("reports_processed", 0),
                # Real DNS status
                "dmarc_status": dns.dmarc,
                "dmarc_policy": dmarc_policy,
                "spf_status": dns.spf,
                "dkim_status": dns.dkim,
            }
        )

    # Calculate overall pass rate
    overall_pass_rate = 0
    if total_emails > 0:
        overall_pass_rate = round((total_passed / total_emails) * 100, 1)

    return DomainSummaryResponse(
        total_domains=total_domains,
        total_emails=total_emails,
        overall_pass_rate=overall_pass_rate,
        reports_processed=total_reports,
        domains=domains_list,
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
            compliance_rate=summary.get("compliance_rate", 0.0),
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
        compliance_rate=summary.get("compliance_rate", 0.0),
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
        reportCount=reports_processed,
    )


@router.get("/{domain_id}/dns", response_model=DNSRecordResponse)
async def get_domain_dns_records(
    domain_id: str = Path(..., title="The domain ID or name"),
    db: Session = Depends(get_db),
):
    """
    Get DNS records for a specific domain using live DNS lookups.

    Manual selectors (stored in the database) are checked first, followed by
    selectors observed in stored DMARC reports, with common well-known
    selectors used as a final fallback.
    """
    store = ReportStore.get_instance()
    domains = store.get_domains()

    if domain_id not in domains:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )

    manual_selectors = _get_domain_selectors_from_db(db, domain_id)
    report_selectors = _get_selectors_from_reports(store, domain_id)
    combined_selectors = list(dict.fromkeys(manual_selectors + report_selectors))

    provider = get_default_provider()
    result = await provider.check_domain(domain_id, selectors=combined_selectors)

    return DNSRecordResponse(
        dmarc=result.dmarc,
        dmarcRecord=result.dmarc_record,
        spf=result.spf,
        spfRecord=result.spf_record,
        dkim=result.dkim,
        dkimSelectors=result.dkim_selector,
    )


@router.get("/{domain_id}/reports", response_model=DomainReportsResponse)
async def get_domain_reports(
    domain_id: str = Path(..., title="The domain ID or name"),
    limit: int = Query(10, title="Maximum number of reports to return"),
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
        policy_val = report.get("policy", "none")
        if isinstance(policy_val, dict):
            policy_val = policy_val.get("p", "none")
        report_entries.append(
            ReportEntry(
                id=report.get("report_id", "unknown"),
                org_name=report.get("org_name", "Unknown Organization"),
                begin_date=report.get("begin_timestamp", 0),
                end_date=report.get("end_timestamp", 0),
                total_emails=report.get("total_count", 0),
                pass_rate=report.get("pass_rate", 0.0),
                policy=policy_val,
            )
        )

    # Build compliance timeline from actual report data
    timeline = _build_compliance_timeline(store, domain_id)

    return DomainReportsResponse(reports=report_entries, compliance_timeline=timeline)


def _build_compliance_timeline(store: ReportStore, domain: str) -> List[TimelinePoint]:
    """
    Build a compliance timeline from actual report data stored in ReportStore.

    Groups reports by date and calculates the pass rate per day to provide
    real historical trend data for the compliance chart.
    """
    all_reports = store.get_domain_reports(domain)

    # Aggregate report data by date
    daily_data: Dict[str, Dict[str, int]] = {}
    for report in all_reports:
        # Use begin_date to determine the day of this report
        begin = report.get("begin_date", 0)
        if isinstance(begin, (int, float)) and begin > 0:
            date_str = datetime.fromtimestamp(begin, tz=timezone.utc).strftime("%Y-%m-%d")
        elif isinstance(begin, str):
            # Handle ISO-format strings
            try:
                date_str = datetime.fromisoformat(begin).strftime("%Y-%m-%d")
            except (ValueError, TypeError):
                continue
        else:
            continue

        if date_str not in daily_data:
            daily_data[date_str] = {"total": 0, "passed": 0}

        summary = report.get("summary", {})
        daily_data[date_str]["total"] += summary.get("total_count", 0)
        daily_data[date_str]["passed"] += summary.get("passed_count", 0)

    # Convert to timeline points sorted by date
    timeline = []
    for date_str in sorted(daily_data.keys()):
        data = daily_data[date_str]
        rate = round((data["passed"] / data["total"]) * 100, 1) if data["total"] > 0 else 0.0
        timeline.append(TimelinePoint(date=date_str, compliance_rate=rate))

    return timeline


@router.get("/{domain_id}/sources", response_model=DomainSourcesResponse)
async def get_domain_sources(
    domain_id: str = Path(..., title="The domain ID or name"),
    days: int = Query(30, title="Number of days to look back"),
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
        source_entries.append(
            SourceEntry(
                ip=source.get("source_ip", "unknown"),
                count=source.get("count", 0),
                spf=source.get("spf_result", "unknown"),
                dkim=source.get("dkim_result", "unknown"),
                dmarc=(
                    "pass"
                    if source.get("spf_result") == "pass" or source.get("dkim_result") == "pass"
                    else "fail"
                ),
                disposition=source.get("disposition", "none"),
            )
        )

    return DomainSourcesResponse(sources=source_entries)


@router.get("/{domain_id}/selectors")
async def get_domain_selectors(
    domain_id: str = Path(..., title="The domain ID or name"),
    db: Session = Depends(get_db),
):
    """Return the manually configured DKIM selectors for a domain."""
    store = ReportStore.get_instance()
    if domain_id not in store.get_domains():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )
    selectors = _get_domain_selectors_from_db(db, domain_id)
    return {"selectors": selectors}


@router.post("/{domain_id}/selectors", status_code=status.HTTP_201_CREATED)
async def add_domain_selector(
    selector_data: SelectorRequest,
    domain_id: str = Path(..., title="The domain ID or name"),
    db: Session = Depends(get_db),
):
    """Add a DKIM selector to the manual list for a domain.

    The selector is persisted in the ``Domain`` database row so that it will
    be used in all subsequent DNS checks, even if it has not yet appeared in
    any received DMARC report.
    """
    store = ReportStore.get_instance()
    if domain_id not in store.get_domains():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )

    selector = selector_data.selector.strip()
    if not selector:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Selector must not be empty",
        )

    domain_db = db.query(Domain).filter(Domain.name == domain_id).first()
    if not domain_db:
        domain_db = Domain(name=domain_id)
        db.add(domain_db)

    existing = [s.strip() for s in (domain_db.dkim_selectors or "").split(",") if s.strip()]
    if selector not in existing:
        existing.append(selector)
        domain_db.dkim_selectors = ",".join(existing)
        db.commit()

    return {"selectors": existing}


@router.delete("/{domain_id}/selectors/{selector}", status_code=status.HTTP_200_OK)
async def delete_domain_selector(
    domain_id: str = Path(..., title="The domain ID or name"),
    selector: str = Path(..., title="The DKIM selector to remove"),
    db: Session = Depends(get_db),
):
    """Remove a manually configured DKIM selector from a domain."""
    domain_db = db.query(Domain).filter(Domain.name == domain_id).first()
    if not domain_db:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )

    existing = [s.strip() for s in (domain_db.dkim_selectors or "").split(",") if s.strip()]
    if selector not in existing:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Selector '{selector}' not found",
        )

    existing.remove(selector)
    domain_db.dkim_selectors = ",".join(existing)
    db.commit()

    return {"selectors": existing}


@router.delete("/{domain_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_domain(domain_id: str = Path(..., title="The domain ID or name")):
    """
    Delete a domain and all associated data.
    This performs a full cleanup of all reports and records related to this domain.
    """
    store = ReportStore.get_instance()
    domains = store.get_domains()

    if domain_id not in domains:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )

    # Perform deletion with cleanup
    deleted = store.delete_domain_with_cleanup(domain_id)

    if not deleted:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete domain",
        )

    # Return 204 No Content on success
    return None


@router.get("/search", response_model=List[DomainResponse])
async def search_domains(
    q: Optional[str] = Query(None, title="Search query for domain name or description"),
    policy: Optional[str] = Query(None, title="Filter by DMARC policy"),
    page: int = Query(1, title="Page number", ge=1),
    limit: int = Query(10, title="Number of domains per page", ge=1, le=100),
):
    """
    Search domains with filtering and pagination.
    This supports searching by domain name/description and filtering by DMARC policy.

    Args:
        q: Optional search query for domain name or description
        policy: Optional filter by DMARC policy (none, quarantine, reject)
        page: Page number (1-based)
        limit: Number of domains per page (max 100)
    """
    store = ReportStore.get_instance()
    domains = store.get_domains()
    summaries = store.get_all_domain_summaries()

    # Apply search filter if provided
    filtered_domains = []
    for domain_name in domains:
        summary = summaries.get(domain_name, {})

        # Skip domain if it doesn't match the search query
        if q and q.lower() not in domain_name.lower():
            continue

        # Skip domain if it doesn't match the policy filter
        if policy and summary.get("policy") != policy:
            continue

        # Domain passed all filters
        filtered_domains.append(
            {
                "name": domain_name,
                "description": "",  # No description in in-memory store
                "policy": summary.get("policy", "unknown"),
                "reports_count": summary.get("reports_processed", 0),
                "emails_count": summary.get("total_count", 0),
                "compliance_rate": summary.get("compliance_rate", 0.0),
            }
        )

    # Apply pagination
    start_idx = (page - 1) * limit
    end_idx = start_idx + limit
    paginated_domains = filtered_domains[start_idx:end_idx]

    return [DomainResponse(**domain) for domain in paginated_domains]
