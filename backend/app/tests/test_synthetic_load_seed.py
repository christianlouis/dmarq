"""Tests for the explicit #811-scale synthetic acceptance scenario."""

from app.models.domain import Domain
from app.models.report import DMARCReport, ReportRecord
from app.services.synthetic_load_seed import (
    LARGE_REPORT_RECORDS,
    SCENARIO_DAYS,
    SCENARIO_DOMAIN,
    seed_simon_811_scenario,
)


def test_simon_811_seed_is_idempotent_and_has_large_report(db_session):
    first = seed_simon_811_scenario(db_session)
    second = seed_simon_811_scenario(db_session)

    domain = db_session.query(Domain).filter(Domain.name == SCENARIO_DOMAIN).one()
    reports = (
        db_session.query(DMARCReport).filter(DMARCReport.domain_id == domain.id).all()
    )
    largest_report = max(reports, key=lambda item: len(item.records))

    assert first["reports"] == SCENARIO_DAYS
    assert second["reports"] == SCENARIO_DAYS
    assert len(reports) == SCENARIO_DAYS
    assert len(largest_report.records) == LARGE_REPORT_RECORDS
    assert (
        db_session.query(ReportRecord)
        .filter(ReportRecord.report_id == largest_report.id)
        .count()
        == LARGE_REPORT_RECORDS
    )
