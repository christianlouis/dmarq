"""Build deterministic metadata for the persisted domain evidence projection."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterable, Mapping, Optional


def _timestamp(value: Any) -> int:
    try:
        return int(value or 0)
    except (TypeError, ValueError):
        return 0


def source_projection_version(rows: Iterable[Mapping[str, Any]], *, days: int) -> str:
    """Return a stable version for the persisted sender projection.

    Raw report rows and API source rows use different field names, so the
    fingerprint intentionally includes only shared persisted facts. Enrichment
    and presentation changes must not make the saved evidence appear newer.
    """
    normalized = []
    for row in rows:
        if hasattr(row, "model_dump"):
            row = row.model_dump()
        normalized.append(
            {
                "ip": row.get("ip") or row.get("source_ip") or "unknown",
                "count": int(row.get("count") or 0),
                "first_seen": _timestamp(row.get("first_seen")),
                "last_seen": _timestamp(row.get("last_seen")),
                "dmarc": row.get("dmarc") or row.get("dmarc_result") or "unknown",
                "spf": row.get("spf") or row.get("spf_result") or "unknown",
                "dkim": row.get("dkim") or row.get("dkim_result") or "unknown",
                "disposition": row.get("disposition") or "none",
            }
        )
    normalized.sort(key=lambda item: (str(item["ip"]), item["first_seen"], item["last_seen"]))
    encoded = json.dumps(
        {"days": int(days), "rows": normalized},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()[:16]


def build_domain_evidence_snapshot(
    health: Mapping[str, Any],
    source_rows: Iterable[Mapping[str, Any]],
    *,
    days: int,
    captured_at: Optional[Any] = None,
) -> Dict[str, Any]:
    """Return one identity shared by score, queue, and sender projections."""
    source_rows = list(source_rows)
    source_version = source_projection_version(source_rows, days=days)
    evidence_captured_at = str(health.get("evidence_captured_at") or captured_at or "") or None
    health_payload = {
        "assessment_version": str(health.get("assessment_version") or "1"),
        "evidence_captured_at": evidence_captured_at,
        "score": health.get("score"),
        "factors": health.get("factors") or {},
        "path_to_100": health.get("path_to_100") or {},
        "source_version": source_version,
        "period_days": int(days),
    }
    version = hashlib.sha256(
        json.dumps(health_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()[:16]
    return {
        "version": version,
        "health_version": str(health.get("assessment_version") or "1"),
        "source_version": source_version,
        "period_days": int(days),
        "captured_at": evidence_captured_at,
        "stale": not bool(evidence_captured_at),
        "source_rows": len(source_rows),
    }
