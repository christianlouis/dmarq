import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

import app.models.domain  # noqa: E402, F401
import app.models.organization  # noqa: E402, F401
import app.models.report  # noqa: E402, F401
import app.models.user  # noqa: E402, F401
import app.models.workspace  # noqa: E402, F401
from app.cli.reconcile_dmarc_duplicates import reconcile, restore_backup  # noqa: E402
from app.core.database import Base  # noqa: E402
from app.models.domain import Domain  # noqa: E402
from app.models.report import DomainSourceDailyProjection, DMARCReport, ReportRecord  # noqa: E402
from app.models.workspace import Workspace  # noqa: E402
from app.services.report_integrity import duplicate_report_inventory  # noqa: E402
from app.services.report_persistence import _iso_from_timestamp, save_parsed_report  # noqa: E402
from app.services.source_read_projection import rebuild_source_projections  # noqa: E402


def _db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine)()


class _InventoryQuery:
    def __init__(self, reports):
        self.reports = reports

    def options(self, *args):
        return self

    def join(self, *args):
        return self

    def filter(self, *args):
        return self

    def order_by(self, *args):
        return self

    def all(self):
        return self.reports


class _InventoryDB:
    def __init__(self, reports):
        self.reports = reports

    def query(self, model):
        return _InventoryQuery(self.reports)


def _inventory_report(report_id, domain_id, workspace_id, domain_name):
    domain = SimpleNamespace(id=domain_id, workspace_id=workspace_id, name=domain_name)
    record = SimpleNamespace(
        source_ip="192.0.2.99",
        count=1,
        disposition="none",
        dkim="pass",
        spf="pass",
        header_from=domain_name,
        envelope_from=None,
        envelope_to=None,
        dkim_auth_details=None,
        spf_auth_details=None,
        policy_override_reasons=None,
        record_extensions=None,
        source_evidence=None,
    )
    return SimpleNamespace(
        id=domain_id * 10,
        domain_id=domain_id,
        domain=domain,
        report_id=report_id,
        org_name="sender",
        begin_date=100,
        end_date=200,
        source_email=None,
        extra_contact_info=None,
        generator=None,
        report_errors=None,
        policy="none",
        subdomain_policy=None,
        non_subdomain_policy=None,
        adkim=None,
        aspf=None,
        percentage=None,
        failure_options=None,
        testing=None,
        discovery_method=None,
        schema_version=None,
        report_variant=None,
        xml_namespace=None,
        report_extensions=None,
        raw_data="<same/>",
        records=[record],
    )


def test_duplicate_inventory_scopes_same_domain_name_by_owner_identity():
    reports = [
        _inventory_report("same", 1, 10, "shared.example"),
        _inventory_report("same", 2, 20, "shared.example"),
    ]
    assert duplicate_report_inventory(_InventoryDB(reports)) == []

    reports.append(_inventory_report("same", 1, 10, "shared.example"))
    result = duplicate_report_inventory(_InventoryDB(reports))
    assert len(result) == 1
    assert result[0]["domain_id"] == 1
    assert result[0]["workspace_id"] == 10
    assert result[0]["row_count"] == 2


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


def test_duplicate_inventory_handles_none_and_text_record_fields():
    engine, db = _db()
    try:
        workspace = Workspace(slug="stable-signature", name="Stable Signature")
        db.add(workspace)
        db.flush()
        domain = Domain(name="stable.example", workspace_id=workspace.id)
        db.add(domain)
        db.flush()
        records = (None, "stable.example")
        for header_from_values in (records, tuple(reversed(records))):
            report = DMARCReport(
                domain_id=domain.id,
                report_id="same",
                org_name="sender",
                begin_date=100,
                end_date=200,
            )
            db.add(report)
            db.flush()
            for header_from in header_from_values:
                db.add(
                    ReportRecord(
                        report_id=report.id,
                        source_ip="192.0.2.2",
                        count=1,
                        disposition="none",
                        dkim="pass",
                        spf="pass",
                        header_from=header_from,
                    )
                )
        db.commit()
        result = duplicate_report_inventory(db, workspace_id=workspace.id)
        assert result[0]["classification"] == "exact"
    finally:
        db.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_duplicate_inventory_compares_raw_data_and_source_evidence():
    engine, db = _db()
    try:
        workspace = Workspace(slug="payload-conflicts", name="Payload Conflicts")
        db.add(workspace)
        db.flush()
        domain = Domain(name="payload-conflicts.example", workspace_id=workspace.id)
        db.add(domain)
        db.flush()
        for report_id, raw_data, source_evidence in (
            ("raw", "<first/>", None),
            ("raw", "<second/>", None),
            ("evidence", "<same/>", '{"network":"first"}'),
            ("evidence", "<same/>", '{"network":"second"}'),
        ):
            report = DMARCReport(
                domain_id=domain.id,
                report_id=report_id,
                org_name="sender",
                begin_date=100,
                end_date=200,
                raw_data=raw_data,
            )
            db.add(report)
            db.flush()
            db.add(
                ReportRecord(
                    report_id=report.id,
                    source_ip="192.0.2.3",
                    count=1,
                    disposition="none",
                    dkim="pass",
                    spf="pass",
                    source_evidence=source_evidence,
                )
            )
        db.commit()
        result = duplicate_report_inventory(db, workspace_id=workspace.id)
        assert [(item["report_id"], item["classification"]) for item in result] == [
            ("evidence", "conflict"),
            ("raw", "conflict"),
        ]
    finally:
        db.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_duplicate_inventory_ignores_record_insertion_order():
    engine, db = _db()
    try:
        workspace = Workspace(slug="record-order", name="Record Order")
        db.add(workspace)
        db.flush()
        domain = Domain(name="record-order.example", workspace_id=workspace.id)
        db.add(domain)
        db.flush()
        records = [
            ("192.0.2.4", 1),
            ("192.0.2.5", 2),
        ]
        for values in (records, list(reversed(records))):
            report = DMARCReport(
                domain_id=domain.id,
                report_id="same",
                org_name="sender",
                begin_date=100,
                end_date=200,
            )
            db.add(report)
            db.flush()
            for source_ip, count in values:
                db.add(
                    ReportRecord(
                        report_id=report.id,
                        source_ip=source_ip,
                        count=count,
                        disposition="none",
                        dkim="pass",
                        spf="pass",
                    )
                )
        db.commit()
        result = duplicate_report_inventory(db, workspace_id=workspace.id)
        assert result[0]["classification"] == "exact"
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


def test_cleanup_dry_run_then_apply_backups_and_removes_only_exact(tmp_path):
    engine, db = _db()
    try:
        workspace = Workspace(slug="cleanup", name="Cleanup")
        db.add(workspace)
        db.flush()
        domain = Domain(name="cleanup.example", workspace_id=workspace.id)
        db.add(domain)
        db.flush()
        for report_id, policy in (
            ("same", "none"),
            ("same", "none"),
            ("blocked", "none"),
            ("blocked", "reject"),
        ):
            report = DMARCReport(
                domain_id=domain.id,
                report_id=report_id,
                org_name="sender",
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
                    count=2,
                    disposition="none",
                    dkim="pass",
                    spf="pass",
                )
            )
        db.commit()
        rebuild_source_projections(db, domain_ids=[domain.id])
        db.commit()
        assert db.query(DomainSourceDailyProjection).one().message_count == 8
        dry = reconcile(db, workspace_id=workspace.id, apply=False, backup=None)
        assert dry["mode"] == "dry-run"
        assert dry["plan"]["eligible_groups"] == 1
        assert db.query(DMARCReport).count() == 4

        backup = tmp_path / "dmarc-backup.json"
        applied = reconcile(db, workspace_id=workspace.id, apply=True, backup=str(backup))
        db.commit()
        assert applied["applied"]["reports"] == 1
        assert applied["applied"]["records"] == 1
        assert backup.exists()
        assert len(json.loads(backup.read_text())["reports"]) == 4
        assert db.query(DMARCReport).count() == 3
        assert db.query(ReportRecord).count() == 3
        assert db.query(DomainSourceDailyProjection).one().message_count == 6
        restored = restore_backup(db, str(backup))
        db.commit()
        assert restored["reports"] == 1
        assert restored["records"] == 1
        assert db.query(DMARCReport).count() == 4
        assert db.query(ReportRecord).count() == 4
        assert db.query(DomainSourceDailyProjection).one().message_count == 8
    finally:
        db.close()
        Base.metadata.drop_all(engine)
        engine.dispose()
