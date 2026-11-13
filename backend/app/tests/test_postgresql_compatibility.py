"""Smoke-test migrations and representative data behavior on real PostgreSQL."""

import json
import os
from datetime import datetime
from uuid import uuid4

import pytest
from sqlalchemy import create_engine, delete, func, select
from sqlalchemy.orm import sessionmaker

from app.core.database import _make_sync_db_url
from app.models.domain import Domain
from app.models.report import DMARCReport, ReportRecord
from app.models.workspace import Workspace
from app.models.workspace_access import WorkspaceAuditLog
from app.services.sender_classifications import (
    SENDER_CLASSIFICATION_ACTION,
    SENDER_CLASSIFICATION_ENTITY,
    _scope_id,
    legitimate_sender_scopes,
)


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


@pytest.mark.skipif(
    not os.environ.get("TEST_POSTGRESQL_URL", "").startswith("postgresql"),
    reason="requires an explicit TEST_POSTGRESQL_URL",
)
def test_postgresql_trusted_sender_scopes_are_latest_and_workspace_scoped():
    """Exercise the bounded composite lookup against PostgreSQL semantics."""
    engine = create_engine(_make_sync_db_url(os.environ["TEST_POSTGRESQL_URL"]))
    session_factory = sessionmaker(bind=engine)
    slug = f"ci-trusted-{uuid4().hex}"
    workspace_ids = []
    try:
        with session_factory.begin() as session:
            first = Workspace(slug=f"{slug}-a", name="PostgreSQL trusted A")
            second = Workspace(slug=f"{slug}-b", name="PostgreSQL trusted B")
            session.add_all([first, second])
            session.flush()
            workspace_ids = [first.id, second.id]
            domain = f"{slug}.example"
            source_ip = "2001:db8::1"
            base = datetime.utcnow()

            def audit_row(workspace_id, classification):
                return WorkspaceAuditLog(
                    workspace_id=workspace_id,
                    actor_type="test",
                    action=SENDER_CLASSIFICATION_ACTION,
                    entity_type=SENDER_CLASSIFICATION_ENTITY,
                    entity_id=_scope_id(domain, source_ip),
                    entity_name=domain,
                    details=json.dumps(
                        {"domain": domain, "source_ip": source_ip, "classification": classification}
                    ),
                    created_at=base,
                )

            session.add(audit_row(first.id, "legitimate"))
            session.flush()
            session.add(audit_row(first.id, "unknown"))
            session.flush()
            session.add(audit_row(second.id, "legitimate"))
            session.flush()
            scopes = {(first.id, domain, "2001:db8::1")}
            assert legitimate_sender_scopes(session, scopes=scopes) == set()
            scopes.add((second.id, domain, "2001:db8::1"))
            assert legitimate_sender_scopes(session, scopes=scopes) == {
                (second.id, domain, "2001:db8::1")
            }
    finally:
        if workspace_ids:
            with session_factory.begin() as session:
                session.execute(
                    delete(WorkspaceAuditLog).where(
                        WorkspaceAuditLog.workspace_id.in_(workspace_ids)
                    )
                )
                session.execute(delete(Workspace).where(Workspace.id.in_(workspace_ids)))
        engine.dispose()
