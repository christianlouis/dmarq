"""Opt-in, idempotent acceptance data for report-detail load testing."""

from datetime import datetime, timedelta, timezone
from typing import Dict

from sqlalchemy.orm import Session

from app.models.domain import Domain
from app.models.report import DMARCReport, ReportRecord


SCENARIO_DOMAIN = "simon-load.example"
SCENARIO_PREFIX = "synthetic-811-"
SCENARIO_DAYS = 30
DAILY_RECORDS = 12
LARGE_REPORT_RECORDS = 360


def _source_ip(index: int) -> str:
    """Return documentation-only addresses without customer infrastructure."""
    return f"198.51.100.{(index % 240) + 1}"


def _ensure_domain(db: Session) -> Domain:
    domain = db.query(Domain).filter(Domain.name == SCENARIO_DOMAIN).first()
    if domain is None:
        domain = Domain(name=SCENARIO_DOMAIN)
        db.add(domain)
        db.flush()

    domain.description = "Synthetic acceptance scenario for report-detail load testing."
    domain.active = True
    domain.verified = False
    domain.dmarc_policy = "quarantine"
    domain.dmarc_report_mailbox = "reports@simon-load.example"
    domain.spf_record = "v=spf1 -all"
    domain.dkim_selectors = "synthetic"
    return domain


def _record(report: DMARCReport, index: int, *, large: bool) -> ReportRecord:
    failure = index % 7 == 0
    partial_failure = not failure and index % 11 == 0
    count = 1 + ((index * 17) % (120 if large else 30))
    dkim = "fail" if failure else "pass"
    spf = "fail" if failure or partial_failure else "pass"
    disposition = "quarantine" if failure else "none"
    return ReportRecord(
        report_id=report.id,
        source_ip=_source_ip(index),
        count=count,
        disposition=disposition,
        dkim=dkim,
        spf=spf,
        header_from=SCENARIO_DOMAIN,
        envelope_from="relay.simon-load.example" if failure else SCENARIO_DOMAIN,
        dkim_auth_details=(
            '[{"domain":"simon-load.example","selector":"synthetic","result":"'
            + dkim
            + '"}]'
        ),
        spf_auth_details=(
            '[{"domain":"simon-load.example","scope":"mfrom","result":"' + spf + '"}]'
        ),
    )


def seed_simon_811_scenario(db: Session) -> Dict[str, int]:
    """Create the documented #811-scale report set without external I/O."""
    domain = _ensure_domain(db)
    now = datetime.now(timezone.utc).replace(minute=0, second=0, microsecond=0)
    report_count = 0
    record_count = 0

    for day_offset in range(SCENARIO_DAYS):
        report_key = f"{SCENARIO_PREFIX}{day_offset:02d}"
        begin = now - timedelta(days=(SCENARIO_DAYS - day_offset))
        report = (
            db.query(DMARCReport)
            .filter(
                DMARCReport.domain_id == domain.id, DMARCReport.report_id == report_key
            )
            .first()
        )
        if report is None:
            report = DMARCReport(
                domain_id=domain.id,
                report_id=report_key,
                org_name="Synthetic Receiver",
            )
            db.add(report)

        report.org_name = "Synthetic Receiver"
        report.begin_date = int(begin.timestamp())
        report.end_date = int((begin + timedelta(days=1)).timestamp())
        report.source_email = "noreply@receiver.example"
        report.policy = "quarantine"
        report.subdomain_policy = "quarantine"
        report.adkim = "r"
        report.aspf = "r"
        report.percentage = 100
        report.processed_at = begin.replace(tzinfo=None)

        db.flush()
        db.query(ReportRecord).filter(ReportRecord.report_id == report.id).delete(
            synchronize_session=False
        )
        is_large_report = day_offset == SCENARIO_DAYS - 1
        records_for_report = LARGE_REPORT_RECORDS if is_large_report else DAILY_RECORDS
        db.add_all(
            _record(report, day_offset * DAILY_RECORDS + index, large=is_large_report)
            for index in range(records_for_report)
        )
        report_count += 1
        record_count += records_for_report

    db.commit()
    return {
        "domain": SCENARIO_DOMAIN,
        "reports": report_count,
        "records": record_count,
        "large_report_records": LARGE_REPORT_RECORDS,
    }
