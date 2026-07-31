"""Tests for deterministic persisted evidence identities."""

from app.services.evidence_snapshot import (
    build_domain_evidence_snapshot,
    source_projection_version,
)


def test_source_projection_version_normalizes_report_and_api_field_names():
    report_row = {
        "source_ip": "192.0.2.20",
        "count": "4",
        "first_seen": "not-a-timestamp",
        "last_seen": None,
        "dmarc_result": "fail",
        "spf_result": "pass",
        "dkim_result": "fail",
        "disposition": None,
    }
    api_row = {
        "ip": "192.0.2.20",
        "count": 4,
        "first_seen": 0,
        "last_seen": 0,
        "dmarc": "fail",
        "spf": "pass",
        "dkim": "fail",
        "disposition": "none",
    }

    assert source_projection_version([report_row], days=30) == source_projection_version(
        [api_row], days=30
    )
    assert source_projection_version([api_row], days=30) != source_projection_version(
        [api_row], days=7
    )


def test_source_projection_version_accepts_model_dump_rows_and_is_order_independent():
    class Row:
        def model_dump(self):
            return {"ip": "192.0.2.10", "count": 1}

    rows = [{"ip": "192.0.2.11", "count": 2}, Row()]
    assert source_projection_version(rows, days=30) == source_projection_version(
        list(reversed(rows)), days=30
    )


def test_domain_evidence_snapshot_uses_health_capture_before_fallback():
    snapshot = build_domain_evidence_snapshot(
        {
            "assessment_version": 3,
            "evidence_captured_at": "2026-07-31T12:00:00Z",
            "score": 92,
            "factors": {"dmarc": 100},
            "path_to_100": {"remaining": 8},
        },
        [{"ip": "192.0.2.10", "count": 5}],
        days=30,
        captured_at="fallback",
    )

    assert snapshot["captured_at"] == "2026-07-31T12:00:00Z"
    assert snapshot["stale"] is False
    assert snapshot["health_version"] == "3"
    assert snapshot["source_rows"] == 1
    assert len(snapshot["version"]) == 16


def test_domain_evidence_snapshot_marks_missing_capture_stale():
    snapshot = build_domain_evidence_snapshot(
        {"score": None},
        [],
        days=30,
        captured_at="2026-07-31T12:00:00Z",
    )

    assert snapshot["captured_at"] == "2026-07-31T12:00:00Z"
    assert snapshot["stale"] is False
    assert snapshot["health_version"] == "1"

    stale = build_domain_evidence_snapshot({"score": None}, [], days=30)
    assert stale["captured_at"] is None
    assert stale["stale"] is True
