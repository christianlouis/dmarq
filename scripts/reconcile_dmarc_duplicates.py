#!/usr/bin/env python3
"""Dry-run-first, backup-first reconciliation of identical DMARC reports.

The command never writes unless ``--apply`` is supplied.  Conflicting
duplicate identities are always reported and skipped.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable

from sqlalchemy import create_engine, func
from sqlalchemy.orm import joinedload, selectinload, sessionmaker

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

import app.models.domain  # noqa: F401,E402
import app.models.organization  # noqa: F401,E402
import app.models.report  # noqa: F401,E402
import app.models.user  # noqa: F401,E402
import app.models.workspace  # noqa: F401,E402
from app.core.database import Base  # noqa: E402
from app.models.report import DMARCReport, ReportRecord  # noqa: E402
from app.services.report_integrity import (  # noqa: E402
    _report_signature,
    duplicate_report_inventory,
)
from app.models.domain import Domain  # noqa: E402


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
        payload["reports"].append({key: _json_safe(value) for key, value in _row_dict(report).items()})
        for record in report.records:
            payload["report_records"].append(
                {key: _json_safe(value) for key, value in _row_dict(record).items()}
            )
    destination = Path(path).expanduser().resolve()
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, sort_keys=True, indent=2)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    temporary.replace(destination)
    return {"path": str(destination), "reports": len(reports), "records": len(payload["report_records"])}


def _totals(db, workspace_id: int | None) -> tuple[int, int]:
    query = db.query(func.count(ReportRecord.id), func.coalesce(func.sum(ReportRecord.count), 0)).join(
        DMARCReport, ReportRecord.report_id == DMARCReport.id
    )
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
    locked = (
        _scope_query(db, workspace_id)
        .options(joinedload(DMARCReport.domain), selectinload(DMARCReport.records))
        .filter(DMARCReport.id.in_(remove_ids))
        .with_for_update()
        .all()
    )
    if len(locked) != len(remove_ids):
        raise RuntimeError("cleanup plan changed: candidate rows no longer exist")
    refreshed = _plan(duplicate_report_inventory(db, workspace_id=workspace_id))
    if refreshed != plan:
        raise RuntimeError("cleanup plan changed while acquiring locks; aborting")
    before = _totals(db, workspace_id)
    backup_result = _write_backup(db, remove_ids, backup)
    records = db.query(ReportRecord).filter(ReportRecord.report_id.in_(remove_ids)).all()
    for record in records:
        db.delete(record)
    for report in locked:
        db.delete(report)
    db.flush()
    after = _totals(db, workspace_id)
    expected = (before[0] - len(records), before[1] - sum(int(r.count or 0) for r in records))
    if after != expected:
        raise RuntimeError(f"post-delete verification failed: expected {expected}, got {after}")
    result["backup"] = backup_result
    result["applied"] = {"reports": len(locked), "records": len(records), "before": before, "after": after}
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--database-url", required=True)
    parser.add_argument("--workspace-id", type=int)
    parser.add_argument("--apply", action="store_true", help="apply eligible exact duplicates")
    parser.add_argument("--backup", help="scoped JSON backup path; required with --apply")
    args = parser.parse_args()
    engine = create_engine(args.database_url)
    Session = sessionmaker(bind=engine)
    db = Session()
    try:
        result = reconcile(
            db, workspace_id=args.workspace_id, apply=args.apply, backup=args.backup
        )
        if args.apply:
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
