from datetime import datetime, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.models.domain  # noqa: F401
import app.models.organization  # noqa: F401
import app.models.report  # noqa: F401
import app.models.user  # noqa: F401
import app.models.workspace  # noqa: F401
from app.core.database import Base
from app.models.domain import Domain
from app.models.report import DMARCReport, ReportRecord
from app.models.workspace import Workspace
from app.services.report_integrity import duplicate_report_inventory
from app.services.report_persistence import _iso_from_timestamp, save_parsed_report


def _db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine)()


def test_timestamp_serialization_is_utc_and_timezone_independent():
    assert _iso_from_timestamp(0) == ""
    assert _iso_from_timestamp(1_759_276_800).endswith("+00:00")
    assert datetime.fromisoformat(_iso_from_timestamp(1_759_276_800)).tzinfo == timezone.utc


def test_duplicate_inventory_separates_exact_and_conflicting_totals():
    engine, db = _db()
    try:
        workspace = Workspace(slug="test", name="Test")
        db.add(workspace)
        db.flush()
        domain = Domain(name="example.com", workspace_id=workspace.id)
        db.add(domain)
        db.flush()
        for report_id, count, org_name, policy, header_from in (
            ("exact", 3, "sender", "none", "example.com"),
            ("exact", 3, "sender", "none", "example.com"),
            ("conflict", 3, "sender", "none", "example.com"),
            # Same totals, but different persisted policy and record meaning.
            ("conflict", 3, "sender", "reject", "other.example.com"),
        ):
            report = DMARCReport(
                domain_id=domain.id,
                report_id=report_id,
                org_name=org_name,
                begin_date=100,
                end_date=200,
                policy=policy,
            )
            db.add(report)
            db.flush()
            db.add(
                ReportRecord(
                    report_id=report.id,
                    source_ip="192.0.2.1",
                    count=count,
                    disposition="none",
                    dkim="pass",
                    spf="pass",
                    header_from=header_from,
                )
            )
        db.commit()
        result = duplicate_report_inventory(db, workspace_id=workspace.id)
        assert [(item["report_id"], item["classification"]) for item in result] == [
            ("conflict", "conflict"),
            ("exact", "exact"),
        ]
        assert result[0]["row_count"] == 2
        assert [row["total_count"] for row in result[0]["rows"]] == [3, 3]
    finally:
        db.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_duplicate_import_returns_existing_row_without_second_persist(monkeypatch):
    engine, db = _db()
    try:
        workspace = Workspace(slug="import-test", name="Import Test")
        db.add(workspace)
        db.flush()
        monkeypatch.setattr(
            "app.services.report_persistence.materialize_source_projection",
            lambda *args, **kwargs: None,
        )
        monkeypatch.setattr(
            "app.services.report_persistence.request_dns_posture_refresh",
            lambda *args, **kwargs: None,
        )
        report = {
            "domain": "example.com",
            "report_id": "same-id",
            "org_name": "sender",
            "begin_timestamp": 100,
            "end_timestamp": 200,
            "policy": {"p": "none"},
            "records": [{"source_ip": "192.0.2.1", "count": 2}],
        }
        first, created = save_parsed_report(db, report, workspace_id=workspace.id)
        db.commit()
        second, created_again = save_parsed_report(db, report, workspace_id=workspace.id)
        assert created is True
        assert created_again is False
        assert second.id == first.id
        assert db.query(DMARCReport).count() == 1
    finally:
        db.close()
        Base.metadata.drop_all(engine)
        engine.dispose()
