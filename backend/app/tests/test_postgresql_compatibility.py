"""Smoke-test migrations and representative data behavior on real PostgreSQL."""

import os
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, delete, func, select
from sqlalchemy.orm import sessionmaker

from app.core.database import _make_sync_db_url
from app.models.domain import Domain
from app.models.report import DMARCReport, ReportRecord
from app.models.workspace import Workspace


@pytest.mark.skipif(
    not os.environ.get("TEST_POSTGRESQL_URL", "").startswith("postgresql"),
    reason="requires an explicit TEST_POSTGRESQL_URL",
)
def test_postgresql_migrated_schema_round_trips_report_data():
    """Exercise FK relationships, timestamps, text fields, and aggregation."""
    engine = create_engine(_make_sync_db_url(os.environ["TEST_POSTGRESQL_URL"]))
    session_factory = sessionmaker(bind=engine)
    slug = f"ci-{uuid4().hex}"
    workspace_id = domain_id = report_id = None

    try:
        with session_factory.begin() as session:
            workspace = Workspace(slug=slug, name="PostgreSQL CI")
            domain = Domain(name=f"{slug}.example", workspace=workspace)
            report = DMARCReport(
                domain=domain,
                report_id=slug,
                org_name="CI",
                begin_date=1_700_000_000,
                end_date=1_700_003_600,
                report_extensions='{"ci": true}',
            )
            report.records.append(
                ReportRecord(source_ip="192.0.2.1", count=3, disposition="none", spf="pass")
            )
            session.add(workspace)
            session.flush()
            workspace_id, domain_id, report_id = workspace.id, domain.id, report.id

        # Read after the write transaction has committed, proving persistence.
        with session_factory() as session:
            assert (
                session.scalar(
                    select(func.count(DMARCReport.id)).where(DMARCReport.report_id == slug)
                )
                == 1
            )
            assert (
                session.scalar(
                    select(func.sum(ReportRecord.count)).where(ReportRecord.report_id == report_id)
                )
                == 3
            )
    finally:
        if report_id is not None:
            with session_factory.begin() as session:
                session.execute(delete(ReportRecord).where(ReportRecord.report_id == report_id))
                session.execute(delete(DMARCReport).where(DMARCReport.id == report_id))
                session.execute(delete(Domain).where(Domain.id == domain_id))
                session.execute(delete(Workspace).where(Workspace.id == workspace_id))
        engine.dispose()
