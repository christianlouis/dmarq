import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[3]))

from sqlalchemy import create_engine  # noqa: E402
from sqlalchemy.orm import sessionmaker  # noqa: E402

from app.cli import reconcile_dmarc_duplicates as duplicate_cli  # noqa: E402
from app.cli.reconcile_dmarc_duplicates import reconcile, restore_backup  # noqa: E402
from app.core.database import Base  # noqa: E402
from app.models.domain import Domain  # noqa: E402
from app.models.report import DMARCReport, DomainSourceDailyProjection, ReportRecord  # noqa: E402
from app.models.workspace import Workspace  # noqa: E402
from app.services.report_integrity import duplicate_report_inventory  # noqa: E402
from app.services.report_persistence import _iso_from_timestamp, save_parsed_report  # noqa: E402
from app.services.source_read_projection import rebuild_source_projections  # noqa: E402


def _db():
    engine = create_engine("sqlite://")
    Base.metadata.create_all(engine)
    return engine, sessionmaker(bind=engine)()


def _backup_payload(reports, records):
    return {
        "format": "dmarq-dmarc-duplicate-backup-v1",
        "reports": [
            {
                key: duplicate_cli._json_safe(value)
                for key, value in duplicate_cli._row_dict(row).items()
            }
            for row in reports
        ],
        "report_records": [
            {
                key: duplicate_cli._json_safe(value)
                for key, value in duplicate_cli._row_dict(row).items()
            }
            for row in records
        ],
    }


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
    assert duplicate_cli._comparison_value(datetime(2026, 1, 1, tzinfo=timezone.utc)) == datetime(
        2026, 1, 1
    )


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
        restored_again = restore_backup(db, str(backup))
        db.commit()
        assert restored_again == {
            "reports": 0,
            "records": 0,
            "already_present_reports": 4,
            "already_present_records": 4,
        }
    finally:
        db.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_restore_rejects_mismatched_existing_report_before_writes(tmp_path):
    engine, db = _db()
    try:
        workspace = Workspace(slug="restore-report", name="Restore Report")
        db.add(workspace)
        db.flush()
        domain = Domain(name="restore-report.example", workspace_id=workspace.id)
        other_domain = Domain(name="other.example", workspace_id=workspace.id)
        db.add_all([domain, other_domain])
        db.flush()
        report = DMARCReport(
            domain_id=domain.id,
            report_id="existing-id",
            org_name="existing-sender",
            begin_date=100,
            end_date=200,
            raw_data="<existing />",
        )
        db.add(report)
        db.commit()
        payload = _backup_payload([report], [])
        payload["reports"][0].update(
            {"domain_id": other_domain.id, "report_id": "archive-id", "raw_data": "<archive />"}
        )
        path = tmp_path / "report-collision.json"
        path.write_text(json.dumps(payload), encoding="utf-8")

        with pytest.raises(ValueError, match=r"report ID .*differs"):
            restore_backup(db, str(path))
        db.rollback()
        unchanged = db.query(DMARCReport).one()
        assert unchanged.domain_id == domain.id
        assert unchanged.report_id == "existing-id"
        assert unchanged.raw_data == "<existing />"
        assert db.query(ReportRecord).count() == 0
    finally:
        db.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_restore_rejects_mismatched_existing_record_before_writes(tmp_path):
    engine, db = _db()
    try:
        workspace = Workspace(slug="restore-record", name="Restore Record")
        db.add(workspace)
        db.flush()
        domain = Domain(name="restore-record.example", workspace_id=workspace.id)
        db.add(domain)
        db.flush()
        report = DMARCReport(
            domain_id=domain.id,
            report_id="record-report",
            org_name="sender",
            begin_date=100,
            end_date=200,
        )
        db.add(report)
        db.flush()
        record = ReportRecord(
            report_id=report.id,
            source_ip="192.0.2.10",
            count=1,
            disposition="none",
            dkim="pass",
            spf="pass",
        )
        db.add(record)
        db.commit()
        payload = _backup_payload([report], [record])
        payload["report_records"][0]["count"] = 9
        path = tmp_path / "record-collision.json"
        path.write_text(json.dumps(payload), encoding="utf-8")

        with pytest.raises(ValueError, match=r"record ID .*differs"):
            restore_backup(db, str(path))
        db.rollback()
        assert db.query(ReportRecord).one().count == 1
    finally:
        db.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_restore_matching_report_with_missing_records_is_idempotent(tmp_path):
    engine, db = _db()
    try:
        workspace = Workspace(slug="restore-partial", name="Restore Partial")
        db.add(workspace)
        db.flush()
        domain = Domain(name="restore-partial.example", workspace_id=workspace.id)
        db.add(domain)
        db.flush()
        report = DMARCReport(
            domain_id=domain.id,
            report_id="partial-report",
            org_name="sender",
            begin_date=100,
            end_date=200,
        )
        db.add(report)
        db.flush()
        records = [
            ReportRecord(
                report_id=report.id,
                source_ip=source_ip,
                count=count,
                disposition="none",
                dkim="pass",
                spf="pass",
            )
            for source_ip, count in (("192.0.2.20", 1), ("192.0.2.21", 2))
        ]
        db.add_all(records)
        db.flush()
        payload = _backup_payload([report], records)
        db.delete(records[1])
        db.commit()
        path = tmp_path / "partial.json"
        path.write_text(json.dumps(payload), encoding="utf-8")

        restored = restore_backup(db, str(path))
        db.commit()
        assert restored == {
            "reports": 0,
            "records": 1,
            "already_present_reports": 1,
            "already_present_records": 1,
        }
        assert db.query(ReportRecord).count() == 2
        restored_again = restore_backup(db, str(path))
        db.commit()
        assert restored_again == {
            "reports": 0,
            "records": 0,
            "already_present_reports": 1,
            "already_present_records": 2,
        }
        assert db.query(ReportRecord).count() == 2
    finally:
        db.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_cleanup_cli_entrypoint_uses_database_url_and_reports_dry_run(monkeypatch, capsys):
    engine, db = _db()
    try:
        workspace = Workspace(slug="cli", name="CLI")
        db.add(workspace)
        db.commit()
        monkeypatch.setenv("DATABASE_URL", "sqlite://")
        monkeypatch.setattr(duplicate_cli, "create_engine", lambda _: engine)
        monkeypatch.setattr(duplicate_cli, "sessionmaker", lambda bind: sessionmaker(bind=bind))
        monkeypatch.setattr(
            sys, "argv", ["reconcile_dmarc_duplicates", "--workspace-id", str(workspace.id)]
        )

        assert duplicate_cli.main() == 0
        receipt = json.loads(capsys.readouterr().out)
        assert receipt == {
            "mode": "dry-run",
            "plan": {
                "blocked": [],
                "blocked_groups": 0,
                "eligible": [],
                "eligible_groups": 0,
                "groups": 0,
            },
        }
    finally:
        db.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_cli_backup_write_guards_missing_rows_existing_paths_and_link_failures(
    tmp_path, monkeypatch
):
    engine, db = _db()
    try:
        workspace = Workspace(slug="backup-guards", name="Backup Guards")
        db.add(workspace)
        db.flush()
        domain = Domain(name="backup-guards.example", workspace_id=workspace.id)
        db.add(domain)
        db.flush()
        report = DMARCReport(
            domain_id=domain.id,
            report_id="backup-report",
            org_name="sender",
            begin_date=100,
            end_date=200,
        )
        db.add(report)
        db.commit()

        path = tmp_path / "backup.json"
        assert duplicate_cli._write_backup(db, [report.id], str(path))["reports"] == 1
        with pytest.raises(FileExistsError, match="backup already exists"):
            duplicate_cli._write_backup(db, [report.id], str(path))

        db.delete(report)
        db.commit()
        with pytest.raises(RuntimeError, match="removable report rows are missing"):
            duplicate_cli._write_backup(db, [report.id], str(tmp_path / "missing.json"))

        report_id = report.id
        report = DMARCReport(
            id=report_id,
            domain_id=domain.id,
            report_id="backup-report",
            org_name="sender",
            begin_date=100,
            end_date=200,
        )
        db.add(report)
        db.commit()
        failed_path = tmp_path / "link-failure.json"

        def fail_link(*args):
            raise OSError("link failed")

        monkeypatch.setattr(duplicate_cli.os, "link", fail_link)
        with pytest.raises(OSError, match="link failed"):
            duplicate_cli._write_backup(db, [report.id], str(failed_path))
        assert not failed_path.exists()
        assert not failed_path.with_name("link-failure.json.tmp").exists()

        with monkeypatch.context() as patch:
            patch.setattr(duplicate_cli.os, "link", fail_link)
            patch.setattr(
                duplicate_cli.os, "unlink", lambda _: (_ for _ in ()).throw(FileNotFoundError())
            )
            with pytest.raises(OSError, match="link failed"):
                duplicate_cli._write_backup(db, [report.id], str(tmp_path / "missing-temp.json"))
    finally:
        db.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_restore_rejects_duplicate_ids_and_missing_report_references(tmp_path):
    engine, db = _db()
    try:
        duplicate_path = tmp_path / "duplicate.json"
        duplicate_path.write_text(
            json.dumps(
                {
                    "reports": [{"id": 1}, {"id": 1}],
                    "report_records": [],
                }
            ),
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="duplicate report or record IDs"):
            restore_backup(db, str(duplicate_path))

        missing_path = tmp_path / "missing-reference.json"
        missing_path.write_text(
            json.dumps(
                {
                    "reports": [],
                    "report_records": [{"id": 1, "report_id": 404}],
                }
            ),
            encoding="utf-8",
        )
        with pytest.raises(ValueError, match="missing report IDs: 404"):
            restore_backup(db, str(missing_path))
    finally:
        db.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


def test_reconcile_apply_requires_backup_and_reports_noop():
    engine, db = _db()
    try:
        with pytest.raises(ValueError, match="--backup is required"):
            reconcile(db, workspace_id=None, apply=True, backup=None)
        result = reconcile(db, workspace_id=None, apply=True, backup="unused.json")
        assert result["applied"] == {"reports": 0, "records": 0}
    finally:
        db.close()
        Base.metadata.drop_all(engine)
        engine.dispose()


@pytest.mark.parametrize(
    ("argv", "message"),
    [
        (["reconcile_dmarc_duplicates"], "DATABASE_URL environment variable is required"),
        (
            ["reconcile_dmarc_duplicates", "--restore", "--apply", "--backup", "x.json"],
            "--restore and --apply are mutually exclusive",
        ),
        (["reconcile_dmarc_duplicates", "--restore"], "--backup is required with --restore"),
    ],
)
def test_cli_argument_guards(monkeypatch, argv, message, capsys):
    monkeypatch.setattr(sys, "argv", argv)
    if len(argv) > 1:
        monkeypatch.setenv("DATABASE_URL", "sqlite://")
    else:
        monkeypatch.delenv("DATABASE_URL", raising=False)
    with pytest.raises(SystemExit) as exc:
        duplicate_cli.main()
    assert exc.value.code == 2
    assert message in capsys.readouterr().err


def test_cli_restore_commits_and_reports_errors(monkeypatch, capsys):
    engine, db = _db()
    try:
        monkeypatch.setenv("DATABASE_URL", "sqlite://")
        monkeypatch.setattr(duplicate_cli, "create_engine", lambda _: engine)
        monkeypatch.setattr(duplicate_cli, "sessionmaker", lambda bind: sessionmaker(bind=bind))
        monkeypatch.setattr(
            sys, "argv", ["reconcile_dmarc_duplicates", "--restore", "--backup", "x"]
        )
        monkeypatch.setattr(
            duplicate_cli, "restore_backup", lambda _db, path: {"reports": 1, "records": 2}
        )
        assert duplicate_cli.main() == 0
        assert json.loads(capsys.readouterr().out) == {
            "mode": "restore",
            "restored": {"reports": 1, "records": 2},
        }

        monkeypatch.setattr(
            duplicate_cli,
            "restore_backup",
            lambda _db, path: (_ for _ in ()).throw(ValueError("bad archive")),
        )
        assert duplicate_cli.main() == 2
        assert json.loads(capsys.readouterr().err) == {"error": "bad archive", "status": "aborted"}
    finally:
        db.close()
        Base.metadata.drop_all(engine)
        engine.dispose()
