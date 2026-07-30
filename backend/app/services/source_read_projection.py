"""Ingestion-time sender facts used by fast domain read paths."""

from __future__ import annotations

import asyncio
import json
import logging
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from sqlalchemy import text
from sqlalchemy.orm import Session, selectinload

from app.core.config import get_settings
from app.core.database import SessionLocal
from app.models.report import DMARCReport, DomainSourceDailyProjection, ReportRecord

logger = logging.getLogger(__name__)

# The daily projection key spans reports, so locking individual report rows is
# insufficient when two workers handle reports for the same sender/day.
_SOURCE_PROJECTION_ADVISORY_LOCK_KEY = 1_144_591_954


def _acquire_source_projection_write_lock(db: Session) -> None:
    """Serialize PostgreSQL projection writers while preserving SQLite support."""
    bind = db.get_bind()
    if bind.dialect.name != "postgresql":
        return
    db.execute(
        text("SELECT pg_advisory_xact_lock(:lock_key)"),
        {"lock_key": _SOURCE_PROJECTION_ADVISORY_LOCK_KEY},
    )


def _int(value: Any) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _json_dict(value: str | None) -> Dict[str, Any]:
    if not value:
        return {}
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _json_list(value: str | None) -> List[Dict[str, Any]]:
    if not value:
        return []
    try:
        parsed = json.loads(value)
    except (TypeError, ValueError, json.JSONDecodeError):
        return []
    return [item for item in parsed if isinstance(item, dict)] if isinstance(parsed, list) else []


def _add_unique(values: List[str], value: Any) -> None:
    text = str(value or "").strip()
    if text and text not in values:
        values.append(text)


def _record_metadata(record: Dict[str, Any]) -> Dict[str, Any]:
    metadata: Dict[str, Any] = {
        "header_from_domains": [],
        "envelope_from_domains": [],
        "spf_domains": [],
        "dkim_domains": [],
        "dkim_selectors": [],
        "report_generators": [],
        "extensions": {},
    }
    _add_unique(metadata["header_from_domains"], record.get("header_from"))
    _add_unique(metadata["envelope_from_domains"], record.get("envelope_from"))
    for item in record.get("spf") or []:
        if isinstance(item, dict):
            _add_unique(metadata["spf_domains"], item.get("domain"))
    for item in record.get("dkim") or []:
        if isinstance(item, dict):
            _add_unique(metadata["dkim_domains"], item.get("domain"))
            _add_unique(metadata["dkim_selectors"], item.get("selector"))
    for key, value in (record.get("extensions") or {}).items():
        if value is not None:
            metadata["extensions"][str(key)] = str(value)
    return metadata


def _merge_metadata(current: Dict[str, Any], incoming: Dict[str, Any]) -> Dict[str, Any]:
    merged = {
        "header_from_domains": list(current.get("header_from_domains") or []),
        "envelope_from_domains": list(current.get("envelope_from_domains") or []),
        "spf_domains": list(current.get("spf_domains") or []),
        "dkim_domains": list(current.get("dkim_domains") or []),
        "dkim_selectors": list(current.get("dkim_selectors") or []),
        "report_generators": list(current.get("report_generators") or []),
        "extensions": dict(current.get("extensions") or {}),
    }
    for key in (
        "header_from_domains",
        "envelope_from_domains",
        "spf_domains",
        "dkim_domains",
        "dkim_selectors",
        "report_generators",
    ):
        for value in incoming.get(key) or []:
            _add_unique(merged[key], value)
    for key, value in (incoming.get("extensions") or {}).items():
        merged["extensions"].setdefault(str(key), str(value))
    return merged


def _projection_records(
    records: Iterable[Dict[str, Any]], *, report_generator: str | None = None
) -> Dict[str, Dict[str, Any]]:
    grouped: Dict[str, Dict[str, Any]] = {}
    for record in records:
        ip = str(record.get("source_ip") or "unknown")
        item = grouped.setdefault(
            ip,
            {
                "message_count": 0,
                "spf_pass_count": 0,
                "spf_fail_count": 0,
                "spf_unknown_count": 0,
                "dkim_pass_count": 0,
                "dkim_fail_count": 0,
                "dkim_unknown_count": 0,
                "dmarc_pass_count": 0,
                "dmarc_fail_count": 0,
                "disposition_counts": defaultdict(int),
                "metadata": _record_metadata({}),
                "source_evidence": {},
                "captured_at": "",
            },
        )
        count = _int(record.get("count"))
        _add_unique(item["metadata"]["report_generators"], report_generator)
        item["message_count"] += count
        spf = str(record.get("spf_result") or record.get("spf") or "unknown").lower()
        dkim = str(record.get("dkim_result") or record.get("dkim") or "unknown").lower()
        item[f"spf_{spf if spf in {'pass', 'fail'} else 'unknown'}_count"] += count
        item[f"dkim_{dkim if dkim in {'pass', 'fail'} else 'unknown'}_count"] += count
        item["dmarc_pass_count" if spf == "pass" or dkim == "pass" else "dmarc_fail_count"] += count
        item["disposition_counts"][str(record.get("disposition") or "none").lower()] += count
        item["metadata"] = _merge_metadata(item["metadata"], _record_metadata(record))
        evidence = record.get("source_evidence") or {}
        captured_at = str(evidence.get("captured_at") or "") if isinstance(evidence, dict) else ""
        if isinstance(evidence, dict) and evidence and captured_at >= item["captured_at"]:
            item["source_evidence"] = evidence
            item["captured_at"] = captured_at
    return grouped


def _observation_window(report: Dict[str, Any]) -> tuple[int, int, int]:
    begin = _int(report.get("begin_timestamp") or report.get("begin_date"))
    end = _int(report.get("end_timestamp") or report.get("end_date"))
    observed_at = end or begin
    return begin or observed_at, end or observed_at, observed_at - (observed_at % 86_400)


def materialize_source_projection(
    db: Session,
    report: Dict[str, Any],
    *,
    domain_id: int,
    db_report: DMARCReport,
) -> None:
    """Upsert sender facts for a newly persisted aggregate report."""
    _acquire_source_projection_write_lock(db)
    # Backfill batches can contain multiple reports for the same sender/day.
    # SessionLocal disables autoflush, so persist facts from the preceding
    # report before looking up the next daily aggregate.
    db.flush()
    first_seen, last_seen, observed_at = _observation_window(report)
    for source_ip, values in _projection_records(
        report.get("records") or [],
        report_generator=str(report.get("org_name") or report.get("email") or "") or None,
    ).items():
        projection = (
            db.query(DomainSourceDailyProjection)
            .filter(
                DomainSourceDailyProjection.domain_id == domain_id,
                DomainSourceDailyProjection.source_ip == source_ip,
                DomainSourceDailyProjection.observed_at == observed_at,
            )
            .first()
        )
        if projection is None:
            projection = DomainSourceDailyProjection(
                domain_id=domain_id,
                source_ip=source_ip,
                observed_at=observed_at,
                first_seen=first_seen,
                last_seen=last_seen,
            )
            db.add(projection)
        else:
            projection.first_seen = min(_int(projection.first_seen) or first_seen, first_seen)
            projection.last_seen = max(_int(projection.last_seen), last_seen)

        projection.message_count = _int(projection.message_count) + values["message_count"]
        projection.report_count = _int(projection.report_count) + 1
        for field in (
            "spf_pass_count",
            "spf_fail_count",
            "spf_unknown_count",
            "dkim_pass_count",
            "dkim_fail_count",
            "dkim_unknown_count",
            "dmarc_pass_count",
            "dmarc_fail_count",
        ):
            setattr(projection, field, _int(getattr(projection, field)) + values[field])
        dispositions = _json_dict(projection.disposition_counts)
        for name, count in values["disposition_counts"].items():
            dispositions[name] = _int(dispositions.get(name)) + count
        projection.disposition_counts = json.dumps(dispositions, sort_keys=True)
        projection.metadata_json = json.dumps(
            _merge_metadata(_json_dict(projection.metadata_json), values["metadata"]),
            sort_keys=True,
        )
        if values["source_evidence"]:
            projection.source_evidence = json.dumps(values["source_evidence"], sort_keys=True)

    db_report.source_projection_at = datetime.utcnow()


def _persisted_record_payload(record: ReportRecord) -> Dict[str, Any]:
    return {
        "source_ip": record.source_ip,
        "count": record.count,
        "disposition": record.disposition,
        "dkim_result": record.dkim,
        "spf_result": record.spf,
        "header_from": record.header_from,
        "envelope_from": record.envelope_from,
        "dkim": _json_list(record.dkim_auth_details),
        "spf": _json_list(record.spf_auth_details),
        "extensions": _json_dict(record.record_extensions),
        "source_evidence": _json_dict(record.source_evidence),
    }


def backfill_source_projections(db: Session, *, limit: int = 100) -> int:
    """Materialize a bounded batch of historic reports without UI read work."""
    reports = (
        db.query(DMARCReport)
        .options(selectinload(DMARCReport.records))
        .filter(DMARCReport.source_projection_at.is_(None))
        .order_by(DMARCReport.end_date.asc())
        .limit(max(1, limit))
        .with_for_update(skip_locked=True)
        .all()
    )
    for report in reports:
        materialize_source_projection(
            db,
            {
                "org_name": report.org_name,
                "email": report.source_email,
                "begin_timestamp": report.begin_date,
                "end_timestamp": report.end_date,
                "records": [_persisted_record_payload(record) for record in report.records],
            },
            domain_id=report.domain_id,
            db_report=report,
        )
    return len(reports)


def source_projection_is_complete(
    db: Session,
    *,
    domain_id: int,
    days: Optional[int],
) -> bool:
    """Return whether a selected source window has no unprojected reports."""
    query = db.query(DMARCReport.id).filter(DMARCReport.domain_id == domain_id)
    if days is not None:
        cutoff = int(datetime.now(timezone.utc).timestamp()) - max(1, int(days)) * 86_400
        query = query.filter(DMARCReport.end_date >= cutoff)
    return query.filter(DMARCReport.source_projection_at.is_(None)).first() is None


def _status(pass_count: int, fail_count: int, unknown_count: int = 0) -> str:
    if pass_count and fail_count:
        return "mixed"
    if pass_count:
        return "pass"
    if fail_count:
        return "fail"
    return "unknown" if unknown_count else "none"


def _dominant(counts: Dict[str, int]) -> str:
    return max(counts.items(), key=lambda item: item[1])[0] if counts else "none"


def load_domain_source_read_projection(
    db: Session,
    *,
    domain_id: int,
    domain_name: str,
    days: Optional[int],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """Return source rows and anomaly-ready daily evidence from stored facts."""
    query = db.query(DomainSourceDailyProjection).filter(
        DomainSourceDailyProjection.domain_id == domain_id
    )
    if days is not None:
        cutoff = int(datetime.now(timezone.utc).timestamp()) - max(1, int(days)) * 86_400
        query = query.filter(DomainSourceDailyProjection.last_seen >= cutoff)
    rows = query.order_by(DomainSourceDailyProjection.observed_at.asc()).all()
    sources: Dict[str, Dict[str, Any]] = {}
    daily_records: Dict[int, List[Dict[str, Any]]] = defaultdict(list)
    for row in rows:
        ip = str(row.source_ip)
        source = sources.setdefault(
            ip,
            {
                "source_ip": ip,
                "count": 0,
                "spf_pass_count": 0,
                "spf_fail_count": 0,
                "spf_unknown_count": 0,
                "dkim_pass_count": 0,
                "dkim_fail_count": 0,
                "dkim_unknown_count": 0,
                "dmarc_pass_count": 0,
                "dmarc_fail_count": 0,
                "disposition_counts": {},
                "first_seen": row.first_seen,
                "last_seen": row.last_seen,
                "active_days": 0,
                "report_count": 0,
                "volume_history": [],
                "source_evidence": {},
                "_metadata": _record_metadata({}),
                "_active_dates": set(),
                "_captured_at": "",
                "window_start": None,
                "window_end": None,
                "evidence_refs": [],
            },
        )
        source["count"] += _int(row.message_count)
        source["report_count"] += _int(row.report_count)
        source["first_seen"] = min(
            _int(source.get("first_seen")) or _int(row.first_seen),
            _int(row.first_seen) or _int(source.get("first_seen")),
        )
        source["last_seen"] = max(_int(source.get("last_seen")), _int(row.last_seen))
        source["window_start"] = (
            row.first_seen or row.observed_at
            if source["window_start"] is None
            else min(source["window_start"], row.first_seen or row.observed_at)
        )
        source["window_end"] = (
            row.last_seen or row.observed_at
            if source["window_end"] is None
            else max(source["window_end"], row.last_seen or row.observed_at)
        )
        source["evidence_refs"].append(f"domain_source_daily_projection:{row.id}")
        for field in (
            "spf_pass_count",
            "spf_fail_count",
            "spf_unknown_count",
            "dkim_pass_count",
            "dkim_fail_count",
            "dkim_unknown_count",
            "dmarc_pass_count",
            "dmarc_fail_count",
        ):
            source[field] += _int(getattr(row, field))
        for name, count in _json_dict(row.disposition_counts).items():
            source["disposition_counts"][name] = _int(
                source["disposition_counts"].get(name)
            ) + _int(count)
        source["_metadata"] = _merge_metadata(source["_metadata"], _json_dict(row.metadata_json))
        evidence = _json_dict(row.source_evidence)
        captured_at = str(evidence.get("captured_at") or "")
        if evidence and captured_at >= source["_captured_at"]:
            source["source_evidence"] = evidence
            source["_captured_at"] = captured_at
        bucket = datetime.fromtimestamp(row.observed_at, tz=timezone.utc).date().isoformat()
        source["_active_dates"].add(bucket)
        source["volume_history"].append(
            {
                "date": bucket,
                "count": _int(row.message_count),
                "passed": _int(row.dmarc_pass_count),
                "failed": _int(row.dmarc_fail_count),
            }
        )
        if _int(row.dmarc_pass_count):
            daily_records[row.observed_at].append(
                {
                    "source_ip": ip,
                    "count": _int(row.dmarc_pass_count),
                    "dkim_result": "pass",
                    "spf_result": "unknown",
                }
            )
        if _int(row.dmarc_fail_count):
            daily_records[row.observed_at].append(
                {
                    "source_ip": ip,
                    "count": _int(row.dmarc_fail_count),
                    "dkim_result": "fail",
                    "spf_result": "fail",
                }
            )

    source_rows = []
    for source in sources.values():
        source["active_days"] = len(source.pop("_active_dates"))
        source["spf_result"] = _status(
            source["spf_pass_count"], source["spf_fail_count"], source["spf_unknown_count"]
        )
        source["dkim_result"] = _status(
            source["dkim_pass_count"], source["dkim_fail_count"], source["dkim_unknown_count"]
        )
        source["dmarc_result"] = _status(source["dmarc_pass_count"], source["dmarc_fail_count"])
        source["disposition"] = _dominant(source["disposition_counts"])
        source.update(source.pop("_metadata"))
        source["captured_at"] = source.pop("_captured_at") or None
        source_rows.append(source)

    report_rows = [
        {
            "domain": domain_name,
            "report_id": f"source-projection-{observed_at}",
            "begin_timestamp": observed_at,
            "end_timestamp": observed_at + 86_399,
            "records": records,
        }
        for observed_at, records in daily_records.items()
    ]
    return source_rows, report_rows


def sync_source_projection_evidence(db: Session, records: Iterable[ReportRecord]) -> None:
    """Copy an imported record's point-in-time evidence into its daily fact."""
    record_ids = [record.id for record in records if record.id is not None]
    if not record_ids:
        return
    rows = (
        db.query(ReportRecord, DMARCReport.domain_id, DMARCReport.end_date)
        .join(DMARCReport, DMARCReport.id == ReportRecord.report_id)
        .filter(ReportRecord.id.in_(record_ids))
        .all()
    )
    for record, domain_id, end_date in rows:
        if not record.source_evidence:
            continue
        observed_at = _int(end_date) - (_int(end_date) % 86_400)
        projection = (
            db.query(DomainSourceDailyProjection)
            .filter(
                DomainSourceDailyProjection.domain_id == domain_id,
                DomainSourceDailyProjection.source_ip == record.source_ip,
                DomainSourceDailyProjection.observed_at == observed_at,
            )
            .first()
        )
        if projection is not None:
            projection.source_evidence = record.source_evidence


async def scheduled_source_projection_backfill() -> None:
    """Finish historic projection work outside operator-facing requests."""
    settings = get_settings()
    if not settings.SOURCE_READ_PROJECTION_BACKFILL_ENABLED:
        return
    await asyncio.sleep(5)
    while True:
        db = SessionLocal()
        try:
            projected = backfill_source_projections(
                db,
                limit=max(1, int(settings.SOURCE_READ_PROJECTION_BACKFILL_LIMIT)),
            )
            if projected:
                db.commit()
                logger.info("Materialized sender facts for %d historic report(s)", projected)
            else:
                db.rollback()
        except asyncio.CancelledError:
            db.rollback()
            raise
        except Exception as exc:  # pylint: disable=broad-exception-caught
            db.rollback()
            logger.warning("Sender projection backfill failed with %s", type(exc).__name__)
        finally:
            db.close()
        await asyncio.sleep(max(30, int(settings.SOURCE_READ_PROJECTION_BACKFILL_INTERVAL_SECONDS)))
