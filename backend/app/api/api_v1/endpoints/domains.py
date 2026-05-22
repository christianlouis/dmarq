import asyncio
import csv
import io
import ipaddress
import logging
from datetime import date, datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Query, status
from fastapi.responses import Response
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.models.domain import Domain
from app.services.dns_resolver import (
    DomainDNSResult,
    extract_dmarc_policy,
    get_default_provider,
)
from app.services.report_persistence import (
    delete_persisted_domain,
    hydrate_report_store_from_db,
)
from app.services.report_store import ReportStore

logger = logging.getLogger(__name__)

router = APIRouter()
DOMAIN_SELECTOR_LOOKUP_CHUNK_SIZE = 500


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
    dkimSelectors: List[str] = []


class TimelinePoint(BaseModel):
    """Data point for compliance timeline"""

    date: str
    total: int
    volume: int
    passed: int
    failed: int
    compliance_rate: float
    failure_rate: float


class ReportEntry(BaseModel):
    """Summary of a DMARC report"""

    id: str
    org_name: str
    begin_date: int
    end_date: int
    total_emails: int
    pass_rate: float
    policy: str


class SourceRecommendation(BaseModel):
    """Actionable recommendation for a sending source"""

    type: str
    severity: str
    title: str
    detail: str
    action: str


class SourceEntry(BaseModel):
    """Summary of a sending source"""

    ip: str
    count: int
    spf: str
    dkim: str
    dmarc: str
    disposition: str
    spf_pass_count: int = 0
    spf_fail_count: int = 0
    dkim_pass_count: int = 0
    dkim_fail_count: int = 0
    dmarc_pass_count: int = 0
    dmarc_fail_count: int = 0
    disposition_counts: Dict[str, int] = Field(default_factory=dict)
    hostname: Optional[str] = None
    spf_fix_hint: Optional[str] = None
    recommendations: List[SourceRecommendation] = Field(default_factory=list)


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
            dkim_entries = record.get("dkim") or []
            for dkim_entry in dkim_entries:
                if not isinstance(dkim_entry, dict):
                    continue
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


def _get_domain_selectors_map_from_db(db: Session, domain_names: List[str]) -> Dict[str, List[str]]:
    """Return manually configured DKIM selectors for all requested domains."""
    if not domain_names:
        return {}

    unique_names = list(dict.fromkeys(domain_names))
    selectors_by_domain: Dict[str, List[str]] = {}
    for index in range(0, len(unique_names), DOMAIN_SELECTOR_LOOKUP_CHUNK_SIZE):
        chunk = unique_names[index : index + DOMAIN_SELECTOR_LOOKUP_CHUNK_SIZE]
        rows = db.query(Domain.name, Domain.dkim_selectors).filter(Domain.name.in_(chunk)).all()
        for name, selectors in rows:
            selectors_by_domain[name] = [
                selector.strip() for selector in (selectors or "").split(",") if selector.strip()
            ]
    return selectors_by_domain


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
    hydrate_report_store_from_db(db, store)
    domains = store.get_domains()
    summaries = store.get_all_domain_summaries()

    # Perform DNS checks concurrently for all domains
    provider = get_default_provider()
    manual_selectors_by_domain = _get_domain_selectors_map_from_db(db, domains)

    async def _dns_for_domain(domain_name: str) -> DomainDNSResult:
        manual_selectors = manual_selectors_by_domain.get(domain_name, [])
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
async def read_domains(db: Session = Depends(get_db)):
    """
    Retrieve domains with their statistics.
    For Milestone 1, this simply returns domains from the in-memory store.
    """
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store)
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
async def read_domain(domain_name: str, db: Session = Depends(get_db)):
    """
    Get statistics for a specific domain.
    """
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store)
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
async def get_domain_stats(
    domain_id: str = Path(..., title="The domain ID or name"),
    db: Session = Depends(get_db),
):
    """
    Get detailed statistics for a specific domain
    """
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store)
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
    hydrate_report_store_from_db(db, store)
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
        dkimSelectors=result.dkim_selectors,
    )


@router.get("/{domain_id}/reports", response_model=DomainReportsResponse)
async def get_domain_reports(
    domain_id: str = Path(..., title="The domain ID or name"),
    limit: int = Query(10, title="Maximum number of reports to return"),
    db: Session = Depends(get_db),
):
    """
    Get recent DMARC reports for a specific domain, along with compliance timeline
    """
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store)
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


@router.get("/{domain_id}/reports/export")
async def export_domain_reports(
    domain_id: str = Path(..., title="The domain ID or name"),
    start_date: Optional[date] = Query(None, title="Start date for exported reports"),
    end_date: Optional[date] = Query(None, title="End date for exported reports"),
    db: Session = Depends(get_db),
):
    """
    Export DMARC report summaries for a specific domain as CSV.
    """
    if start_date and end_date and start_date > end_date:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="start_date must be on or before end_date",
        )

    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store)

    if domain_id not in store.get_domains():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )

    reports = [
        report
        for report in store.get_domain_reports(domain_id, limit=10000)
        if _report_in_export_range(report, start_date, end_date)
    ]

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "domain",
            "report_id",
            "org_name",
            "begin_date",
            "end_date",
            "total_emails",
            "passed",
            "failed",
            "pass_rate",
            "policy",
        ]
    )

    for report in reports:
        summary = report.get("summary", {})
        total = int(summary.get("total_count", report.get("total_count", 0)) or 0)
        passed = int(summary.get("passed_count", report.get("passed_count", 0)) or 0)
        failed = int(summary.get("failed_count", report.get("failed_count", 0)) or 0)
        policy = report.get("policy", "none")
        if isinstance(policy, dict):
            policy = policy.get("p", "none")
        writer.writerow(
            [
                domain_id,
                report.get("report_id", "unknown"),
                report.get("org_name", "Unknown Organization"),
                _format_report_date(report.get("begin_timestamp") or report.get("begin_date")),
                _format_report_date(report.get("end_timestamp") or report.get("end_date")),
                total,
                passed,
                failed,
                report.get("pass_rate", 0.0),
                policy,
            ]
        )

    filename = f"{domain_id.replace('/', '_')}-dmarc-reports.csv"
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


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
            daily_data[date_str] = {"total": 0, "passed": 0, "failed": 0}

        summary = report.get("summary", {})
        total = summary.get("total_count", 0)
        passed = summary.get("passed_count", 0)
        failed = summary.get("failed_count", max(0, total - passed))
        daily_data[date_str]["total"] += total
        daily_data[date_str]["passed"] += passed
        daily_data[date_str]["failed"] += failed

    # Convert to timeline points sorted by date
    timeline = []
    for date_str in sorted(daily_data.keys()):
        data = daily_data[date_str]
        total = data["total"]
        compliance_rate = round((data["passed"] / total) * 100, 1) if total > 0 else 0.0
        failure_rate = round((data["failed"] / total) * 100, 1) if total > 0 else 0.0
        timeline.append(
            TimelinePoint(
                date=date_str,
                total=total,
                volume=total,
                passed=data["passed"],
                failed=data["failed"],
                compliance_rate=compliance_rate,
                failure_rate=failure_rate,
            )
        )

    return timeline


def _report_in_export_range(
    report: Dict[str, Any], start_date: Optional[date], end_date: Optional[date]
) -> bool:
    report_date = _report_date(report.get("begin_timestamp") or report.get("begin_date"))
    if report_date is None:
        return False
    if start_date and report_date < start_date:
        return False
    if end_date and report_date > end_date:
        return False
    return True


def _report_date(value: Any) -> Optional[date]:
    if isinstance(value, (int, float)) and value > 0:
        return datetime.fromtimestamp(value, tz=timezone.utc).date()
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value).date()
        except (ValueError, TypeError):
            return None
    return None


def _format_report_date(value: Any) -> str:
    report_date = _report_date(value)
    return report_date.isoformat() if report_date else ""


def _spf_fix_hint(ip: str, spf_result: str, failed_count: int = 0) -> Optional[str]:
    """Return a copy-paste SPF mechanism (e.g. ``ip4:1.2.3.4``) for a failing IP.

    Returns ``None`` when SPF did not fail or when *ip* is not a valid address.
    """
    if spf_result != "fail" and failed_count <= 0:
        return None
    try:
        addr = ipaddress.ip_address(ip)
        prefix = "ip6" if isinstance(addr, ipaddress.IPv6Address) else "ip4"
        return f"{prefix}:{ip}"
    except ValueError:
        return None


def _source_recommendations(
    ip: str,
    source: Dict[str, Any],
    hostname: Optional[str],
    spf_fix_hint: Optional[str],
) -> List[SourceRecommendation]:
    """Build clear next steps for common DMARC source patterns."""
    spf_result = source.get("spf_result", "unknown")
    dkim_result = source.get("dkim_result", "unknown")
    dmarc_result = source.get("dmarc_result") or (
        "pass" if spf_result == "pass" or dkim_result == "pass" else "fail"
    )
    disposition = source.get("disposition", "none")
    disposition_counts = source.get("disposition_counts", {}) or {}
    dmarc_failed = source.get("dmarc_fail_count", 0) > 0 or dmarc_result == "fail"
    dmarc_passed = source.get("dmarc_pass_count", 0) > 0 or dmarc_result == "pass"

    recommendations: List[SourceRecommendation] = []

    if not hostname and dmarc_failed:
        recommendations.append(
            SourceRecommendation(
                type="unknown_source",
                severity="warning",
                title="Unknown sending source",
                detail=(
                    "No reverse DNS name was found for this IP, so treat it as unrecognized "
                    "until you confirm who owns it."
                ),
                action=(
                    "Confirm whether this server should send mail for this domain before "
                    "authorizing it in SPF or DKIM."
                ),
            )
        )

    if spf_result == "pass" and dkim_result in {"fail", "mixed", "unknown", "none"} and dmarc_passed:
        recommendations.append(
            SourceRecommendation(
                type="spf_only_pass",
                severity="info",
                title="SPF-only DMARC pass",
                detail="DMARC is passing through SPF, but DKIM is not reliably passing for this source.",
                action=(
                    "Enable DKIM signing for this sending service so messages keep passing "
                    "if SPF alignment changes."
                ),
            )
        )

    if dkim_result == "pass" and spf_result in {"fail", "mixed", "unknown", "none"} and dmarc_passed:
        action = "Authorize this service in SPF, or confirm SPF is intentionally handled elsewhere."
        if spf_fix_hint:
            action = f"Add {spf_fix_hint} to your SPF record if this service is legitimate."
        recommendations.append(
            SourceRecommendation(
                type="dkim_only_pass",
                severity="info",
                title="DKIM-only DMARC pass",
                detail="DMARC is passing through DKIM, but SPF is not reliably passing for this source.",
                action=action,
            )
        )

    if spf_result == "fail" and dkim_result == "fail" and dmarc_failed:
        action = (
            "Do not authorize this source until you confirm it is legitimate; then configure "
            "both SPF authorization and DKIM signing."
        )
        if spf_fix_hint:
            action = (
                f"If legitimate, add {spf_fix_hint} to SPF and enable DKIM signing for this service."
            )
        recommendations.append(
            SourceRecommendation(
                type="full_fail",
                severity="error",
                title="Full DMARC failure",
                detail="Neither SPF nor DKIM is passing, so this mail fails DMARC.",
                action=action,
            )
        )

    if dmarc_failed and (disposition == "none" or disposition_counts.get("none", 0) > 0):
        recommendations.append(
            SourceRecommendation(
                type="policy_not_enforced",
                severity="warning",
                title="Policy not enforced",
                detail="Some failed mail was accepted because the applied DMARC disposition was none.",
                action=(
                    "After legitimate sources are passing consistently, move the domain policy "
                    "toward quarantine or reject."
                ),
            )
        )

    return recommendations


async def _safe_ptr_lookup(provider: Any, ip: str, timeout: float = 3.0) -> Optional[str]:
    """Perform a PTR lookup for *ip*, returning ``None`` on any error or timeout."""
    try:
        ipaddress.ip_address(ip)  # validate before making a DNS query
    except ValueError:
        return None
    try:
        return await asyncio.wait_for(provider.lookup_ptr(ip), timeout=timeout)
    except Exception:
        return None


@router.get("/{domain_id}/sources", response_model=DomainSourcesResponse)
async def get_domain_sources(
    domain_id: str = Path(..., title="The domain ID or name"),
    days: int = Query(30, title="Number of days to look back"),
    db: Session = Depends(get_db),
):
    """
    Get sending sources for a specific domain, including reverse-DNS hostnames
    and SPF fix hints for sources that fail authentication.
    """
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store)
    domains = store.get_domains()

    if domain_id not in domains:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )

    sources = store.get_domain_sources(domain_id, days=days)
    provider = get_default_provider()

    ips = [s.get("source_ip", "unknown") for s in sources]
    hostnames = await asyncio.gather(*[_safe_ptr_lookup(provider, ip) for ip in ips])

    source_entries = []
    for source, hostname in zip(sources, hostnames):
        ip = source.get("source_ip", "unknown")
        spf_result = source.get("spf_result", "unknown")
        dkim_result = source.get("dkim_result", "unknown")
        spf_fix_hint = _spf_fix_hint(ip, spf_result, source.get("spf_fail_count", 0))
        source_entries.append(
            SourceEntry(
                ip=ip,
                count=source.get("count", 0),
                spf=spf_result,
                dkim=dkim_result,
                dmarc=source.get("dmarc_result")
                or ("pass" if spf_result == "pass" or dkim_result == "pass" else "fail"),
                disposition=source.get("disposition", "none"),
                spf_pass_count=source.get("spf_pass_count", 0),
                spf_fail_count=source.get("spf_fail_count", 0),
                dkim_pass_count=source.get("dkim_pass_count", 0),
                dkim_fail_count=source.get("dkim_fail_count", 0),
                dmarc_pass_count=source.get("dmarc_pass_count", 0),
                dmarc_fail_count=source.get("dmarc_fail_count", 0),
                disposition_counts=source.get("disposition_counts", {}),
                hostname=hostname,
                spf_fix_hint=spf_fix_hint,
                recommendations=_source_recommendations(ip, source, hostname, spf_fix_hint),
            )
        )

    return DomainSourcesResponse(sources=source_entries)


@router.get("/{domain_id}/selectors")
async def get_domain_selectors(
    domain_id: str = Path(..., title="The domain ID or name"),
    db: Session = Depends(get_db),
):
    """Return the manually configured DKIM selectors for a domain.

    The response includes both ``selectors`` (manually configured, can be
    deleted) and ``report_selectors`` (automatically discovered from received
    DMARC reports, read-only).
    """
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store)
    if domain_id not in store.get_domains():
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )
    manual = _get_domain_selectors_from_db(db, domain_id)
    report = _get_selectors_from_reports(store, domain_id)
    # Only include in report_selectors those not already in the manual list
    auto = [s for s in report if s not in manual]
    return {"selectors": manual, "report_selectors": auto}


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
    hydrate_report_store_from_db(db, store)
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
async def delete_domain(
    domain_id: str = Path(..., title="The domain ID or name"),
    db: Session = Depends(get_db),
):
    """
    Delete a domain and all associated data.
    This performs a full cleanup of all reports and records related to this domain.
    """
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store)
    domains = store.get_domains()

    if domain_id not in domains:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Domain not found",
        )

    # Perform deletion with cleanup
    deleted_from_db = delete_persisted_domain(db, domain_id)
    if deleted_from_db:
        db.commit()
    deleted = store.delete_domain_with_cleanup(domain_id) or deleted_from_db

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
    db: Session = Depends(get_db),
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
    hydrate_report_store_from_db(db, store)
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
