#!/usr/bin/env python3
"""Dry-run-first, backup-first reconciliation of identical DMARC reports.

The command never writes unless ``--apply`` is supplied.  Conflicting
duplicate identities are always reported and skipped.
"""

from __future__ import annotations

import argparse
import importlib
import json
import os
import pkgutil
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable

from sqlalchemy import create_engine, func
from sqlalchemy.orm import selectinload, sessionmaker

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / "backend"))

# Import every model module so SQLAlchemy can resolve all relationships in a
# production process, including relationships unrelated to DMARC reports.
import app.models  # noqa: E402

for module in pkgutil.iter_modules(app.models.__path__):
    importlib.import_module(f"app.models.{module.name}")

from app.models.domain import Domain  # noqa: E402
from app.models.report import DMARCReport, ReportRecord  # noqa: E402
from app.services.report_integrity import duplicate_report_inventory  # noqa: E402
from app.services.source_read_projection import rebuild_source_projections  # noqa: E402


def _plan(inventory: list[Dict[str, Any]]) -> Dict[str, Any]:
    eligible = []
    blocked = []
    for group in inventory:
        if group["classification"] != "exact":
            blocked.append(group)
            continue
        rows = sorted(group["rows"], key=lambda row: row["id"])
        eligible.append(
            {
                "domain": group["domain"],
                "report_id": group["report_id"],
                "survivor_id": rows[0]["id"],
                "remove_ids": [row["id"] for row in rows[1:]],
                "semantic_signature": rows[0]["semantic_signature"],
            }
        )
    return {
        "groups": len(inventory),
        "eligible": eligible,
        "blocked": blocked,
        "eligible_groups": len(eligible),
        "blocked_groups": len(blocked),
    }


def _scope_query(db, workspace_id: int | None):
    query = db.query(DMARCReport)
    if workspace_id is not None:
        query = query.join(Domain, DMARCReport.domain_id == Domain.id).filter(
            Domain.workspace_id == workspace_id
        )
    return query


def _row_dict(row: Any) -> Dict[str, Any]:
    return {column.name: getattr(row, column.name) for column in row.__table__.columns}


def _json_safe(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.isoformat()
    return value


def _write_backup(db, remove_ids: Iterable[int], path: str) -> Dict[str, Any]:
    ids = sorted(set(remove_ids))
    reports = (
        db.query(DMARCReport)
        .options(selectinload(DMARCReport.records))
        .filter(DMARCReport.id.in_(ids))
        .order_by(DMARCReport.id)
        .with_for_update()
        .all()
    )
    if [row.id for row in reports] != ids:
        raise RuntimeError("cleanup plan changed: removable report rows are missing")
    payload = {
        "format": "dmarq-dmarc-duplicate-backup-v1",
        "created_at": datetime.utcnow().isoformat() + "Z",
        "reports": [],
        "report_records": [],
    }
    for report in reports:
        payload["reports"].append(
            {key: _json_safe(value) for key, value in _row_dict(report).items()}
        )
        for record in report.records:
            payload["report_records"].append(
                {key: _json_safe(value) for key, value in _row_dict(record).items()}
            )
    destination = Path(path).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.exists():
        raise FileExistsError(f"backup already exists: {destination}")
    temporary = destination.with_name(destination.name + ".tmp")
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            os.chmod(temporary, 0o600)
            json.dump(payload, handle, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.link(temporary, destination)
        os.unlink(temporary)
    except Exception:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
    return {
        "path": str(destination),
        "reports": len(reports),
        "records": len(payload["report_records"]),
    }


def _totals(db, workspace_id: int | None) -> tuple[int, int]:
    query = db.query(
        func.count(ReportRecord.id), func.coalesce(func.sum(ReportRecord.count), 0)
    ).join(DMARCReport, ReportRecord.report_id == DMARCReport.id)
    if workspace_id is not None:
        query = query.join(Domain, DMARCReport.domain_id == Domain.id).filter(
            Domain.workspace_id == workspace_id
        )
    count, messages = query.one()
    return int(count or 0), int(messages or 0)


def reconcile(db, *, workspace_id: int | None, apply: bool, backup: str | None) -> Dict[str, Any]:
    inventory = duplicate_report_inventory(db, workspace_id=workspace_id)
    plan = _plan(inventory)
    result: Dict[str, Any] = {"mode": "apply" if apply else "dry-run", "plan": plan}
    if not apply:
        return result
    if not backup:
        raise ValueError("--backup is required with --apply")

    # Lock every candidate report and its parent domain, then recompute.  A
    # changed signature or newly introduced conflict aborts the transaction.
    remove_ids = [rid for item in plan["eligible"] for rid in item["remove_ids"]]
    if not remove_ids:
        result["applied"] = {"reports": 0, "records": 0}
        return result
    all_ids = [row["id"] for group in inventory for row in group["rows"]]
    domain_ids = [
        row[0]
        for row in db.query(DMARCReport.domain_id)
        .filter(DMARCReport.id.in_(all_ids))
        .distinct()
        .all()
    ]
    db.query(Domain).filter(Domain.id.in_(domain_ids)).order_by(Domain.id).with_for_update().all()
    locked = (
        _scope_query(db, workspace_id)
        .options(selectinload(DMARCReport.records))
        .filter(DMARCReport.id.in_(all_ids))
        .order_by(DMARCReport.id)
        .with_for_update()
        .all()
    )
    if len(locked) != len(all_ids):
        raise RuntimeError("cleanup plan changed: candidate rows no longer exist")
    report_domains = {report.id: report.domain_id for report in locked}
    # Reports reference mutable child rows. Lock them too so the semantic
    # preflight, backup and delete all observe the same payload.
    db.query(ReportRecord).filter(ReportRecord.report_id.in_(all_ids)).order_by(
        ReportRecord.id
    ).with_for_update().all()
    db.expire_all()
    refreshed = _plan(duplicate_report_inventory(db, workspace_id=workspace_id))
    if refreshed != plan:
        raise RuntimeError("cleanup plan changed while acquiring locks; aborting")
    before = _totals(db, workspace_id)
    backup_result = _write_backup(db, all_ids, backup)
    records = db.query(ReportRecord).filter(ReportRecord.report_id.in_(remove_ids)).all()
    for record in records:
        db.delete(record)
    remove_set = set(remove_ids)
    for report in locked:
        if report.id in remove_set:
            db.delete(report)
    db.flush()
    rebuild_source_projections(
        db,
        domain_ids=[report_domains[report_id] for report_id in remove_ids],
    )
    after = _totals(db, workspace_id)
    expected = (before[0] - len(records), before[1] - sum(int(r.count or 0) for r in records))
    if after != expected:
        raise RuntimeError(f"post-delete verification failed: expected {expected}, got {after}")
    result["backup"] = backup_result
    result["applied"] = {
        "reports": len(remove_ids),
        "records": len(records),
        "before": before,
        "after": after,
    }
    return result


def restore_backup(db, path: str) -> Dict[str, int]:
    """Restore a backup into an empty-ID slot; never overwrites rows."""
    payload = json.loads(Path(path).read_text(encoding="utf-8"))
    reports = payload.get("reports") or []
    records = payload.get("report_records") or []
    report_ids = [int(row["id"]) for row in reports]
    existing_report_ids = {
        row[0] for row in db.query(DMARCReport.id).filter(DMARCReport.id.in_(report_ids)).all()
    }
    missing_reports = [row for row in reports if int(row["id"]) not in existing_report_ids]
    report_domains = {int(row["id"]): int(row["domain_id"]) for row in reports}
    record_ids = [int(row["id"]) for row in records]
    existing_record_ids = {
        row[0] for row in db.query(ReportRecord.id).filter(ReportRecord.id.in_(record_ids)).all()
    }
    missing_records = [row for row in records if int(row["id"]) not in existing_record_ids]
    affected_domain_ids = {int(row["domain_id"]) for row in missing_reports} | {
        report_domains[int(row["report_id"])]
        for row in missing_records
        if int(row["report_id"]) in report_domains
    }
    if affected_domain_ids:
        db.query(Domain).filter(Domain.id.in_(affected_domain_ids)).order_by(
            Domain.id
        ).with_for_update().all()
    for row in reports:
        if int(row["id"]) in existing_report_ids:
            continue
        values = dict(row)
        for key in ("processed_at", "source_projection_at"):
            if values.get(key):
                values[key] = datetime.fromisoformat(values[key].replace("Z", "+00:00"))
        db.add(DMARCReport(**values))
    db.flush()
    for row in records:
        if int(row["id"]) not in existing_record_ids:
            db.add(ReportRecord(**row))
    db.flush()
    rebuild_source_projections(db, domain_ids=affected_domain_ids)
    return {
        "reports": len(reports) - len(existing_report_ids),
        "records": len(records) - len(existing_record_ids),
        "already_present_reports": len(existing_report_ids),
        "already_present_records": len(existing_record_ids),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--restore", action="store_true", help="restore a prior backup")
    parser.add_argument("--workspace-id", type=int)
    parser.add_argument("--apply", action="store_true", help="apply eligible exact duplicates")
    parser.add_argument("--backup", help="scoped JSON backup path; required with --apply")
    args = parser.parse_args()
    database_url = os.environ.get("DATABASE_URL")
    if not database_url:
        parser.error("DATABASE_URL environment variable is required")
    if args.restore and args.apply:
        parser.error("--restore and --apply are mutually exclusive")
    if args.restore and not args.backup:
        parser.error("--backup is required with --restore")
    engine = create_engine(database_url)
    Session = sessionmaker(bind=engine)
    db = Session()
    try:
        if args.restore:
            result = {"mode": "restore", "restored": restore_backup(db, args.backup)}
        else:
            result = reconcile(
                db, workspace_id=args.workspace_id, apply=args.apply, backup=args.backup
            )
        if args.apply or args.restore:
            db.commit()
        print(json.dumps(result, sort_keys=True, indent=2, default=str))
        return 0
    except Exception as exc:  # noqa: BLE001
        db.rollback()
        print(json.dumps({"status": "aborted", "error": str(exc)}, sort_keys=True), file=sys.stderr)
        return 2
    finally:
        db.close()


if __name__ == "__main__":
    raise SystemExit(main())
