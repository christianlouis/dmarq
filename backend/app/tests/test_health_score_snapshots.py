from datetime import date

from app.services.health_score_snapshots import (
    aggregate_workspace_health_points,
    build_health_evidence_export_rows,
    build_health_score_history,
    build_workspace_health_score_history,
    list_health_score_snapshots,
    list_workspace_health_score_snapshots,
    snapshot_to_history_point,
    upsert_health_score_snapshot,
)
from app.services.workspaces import get_or_create_default_workspace


def test_health_score_snapshot_upsert_history_and_export(db_session):
    workspace = get_or_create_default_workspace(db_session)
    health = {
        "score": 82,
        "grade": "B-",
        "status": "attention",
        "factors": {
            "dns_posture": 90,
            "policy_strength": 88,
            "report_confidence": 78,
        },
        "actions": [
            {
                "type": "policy_none",
                "severity": "medium",
                "title": "Move out of monitoring mode",
                "score_impact": 14,
                "detail": "not exported",
            }
        ],
    }

    upsert_health_score_snapshot(
        db_session,
        workspace_id=workspace.id,
        domain_name="example.com",
        health=health,
        policy="quarantine",
        compliance_rate=91.2,
        total_emails=1000,
        failed_emails=88,
        report_count=7,
        snapshot_date=date(2026, 6, 1),
    )
    upsert_health_score_snapshot(
        db_session,
        workspace_id=workspace.id,
        domain_name="example.com",
        health={**health, "score": 86, "grade": "B"},
        policy="quarantine",
        compliance_rate=94,
        total_emails=1200,
        failed_emails=72,
        report_count=8,
        snapshot_date=date(2026, 6, 1),
    )
    upsert_health_score_snapshot(
        db_session,
        workspace_id=workspace.id,
        domain_name="example.com",
        health={**health, "score": 90, "grade": "A-"},
        policy="reject",
        compliance_rate=97,
        total_emails=1400,
        failed_emails=42,
        report_count=9,
        snapshot_date=date(2026, 6, 2),
    )

    snapshots = list_health_score_snapshots(
        db_session,
        workspace_id=workspace.id,
        domain_name="example.com",
    )
    assert [snapshot.snapshot_date for snapshot in snapshots] == [
        date(2026, 6, 1),
        date(2026, 6, 2),
    ]
    assert snapshots[0].score == 86

    history = build_health_score_history(domain_name="example.com", snapshots=snapshots)
    assert history["current_score"] == 90
    assert history["previous_score"] == 86
    assert history["score_delta"] == 4
    assert history["top_drivers"][0]["title"] == "Move out of monitoring mode"

    export_rows = build_health_evidence_export_rows(snapshots)
    assert export_rows[0]["domain"] == "example.com"
    assert export_rows[0]["top_actions"] == "medium:Move out of monitoring mode"
    assert "not exported" not in str(export_rows)


def test_health_score_snapshot_defensive_serialization(db_session):
    workspace = get_or_create_default_workspace(db_session)
    snapshot = upsert_health_score_snapshot(
        db_session,
        workspace_id=workspace.id,
        domain_name="defensive.example",
        health={
            "score": "not-a-number",
            "grade": "",
            "status": "",
            "factors": {"dns_posture": "also-bad"},
            "actions": [{"title": "Bad input", "score_impact": "bad"}],
        },
        compliance_rate="bad",
        total_emails="bad",
        failed_emails="bad",
        report_count="bad",
        snapshot_date=date(2026, 6, 4),
    )
    assert snapshot.score == 0
    assert snapshot.dns_posture_score == 0
    assert snapshot_to_history_point(snapshot)["top_actions"][0]["score_impact"] == 0

    snapshot.top_actions = ""
    assert snapshot_to_history_point(snapshot)["top_actions"] == []
    assert "HealthScoreSnapshot defensive.example 2026-06-04 0" in repr(snapshot)
    snapshot.top_actions = "{not-json"
    assert snapshot_to_history_point(snapshot)["top_actions"] == []
    snapshot.top_actions = '{"not": "a list"}'
    assert snapshot_to_history_point(snapshot)["top_actions"] == []
    snapshot.top_actions = '["not-a-dict", {"title": "kept"}]'
    assert snapshot_to_history_point(snapshot)["top_actions"] == [{"title": "kept"}]


def test_health_score_snapshot_filters_by_date_range(db_session):
    workspace = get_or_create_default_workspace(db_session)
    for day in range(1, 4):
        upsert_health_score_snapshot(
            db_session,
            workspace_id=workspace.id,
            domain_name="filtered.example",
            health={"score": 70 + day, "grade": "C", "status": "attention"},
            snapshot_date=date(2026, 6, day),
        )

    snapshots = list_health_score_snapshots(
        db_session,
        workspace_id=workspace.id,
        domain_name="filtered.example",
        start_date=date(2026, 6, 2),
        end_date=date(2026, 6, 3),
        limit=10,
    )

    assert [snapshot.snapshot_date for snapshot in snapshots] == [
        date(2026, 6, 2),
        date(2026, 6, 3),
    ]


def test_workspace_health_score_history_aggregates_domain_snapshots(db_session):
    workspace = get_or_create_default_workspace(db_session)
    for domain_name, score, total_emails, failed_emails, action_title in [
        ("example.com", 90, 1000, 20, "Keep reject policy"),
        ("example.net", 70, 100, 30, "Fix DKIM selector coverage"),
    ]:
        upsert_health_score_snapshot(
            db_session,
            workspace_id=workspace.id,
            domain_name=domain_name,
            health={
                "score": score,
                "grade": "A-" if score >= 90 else "C",
                "status": "healthy" if score >= 90 else "attention",
                "factors": {
                    "dns_posture": score,
                    "policy_strength": 88,
                    "report_confidence": 90,
                },
                "actions": [
                    {
                        "type": "demo",
                        "severity": "high",
                        "title": action_title,
                        "score_impact": 12 if score < 90 else 2,
                    }
                ],
            },
            policy="quarantine",
            compliance_rate=score,
            total_emails=total_emails,
            failed_emails=failed_emails,
            report_count=4,
            snapshot_date=date(2026, 6, 5),
        )

    snapshots = list_workspace_health_score_snapshots(
        db_session,
        workspace_id=workspace.id,
        start_date=date(2026, 6, 1),
        end_date=date(2026, 6, 30),
    )
    history = build_workspace_health_score_history(snapshots)

    assert history["scope"] == "workspace"
    assert history["current_score"] == 88
    assert history["points"][0]["domain_count"] == 2
    assert history["points"][0]["total_emails"] == 1100
    assert history["points"][0]["failed_emails"] == 50
    assert history["top_drivers"][0]["domain"] == "example.net"


def test_aggregate_workspace_health_points_handles_demo_points():
    points = aggregate_workspace_health_points(
        {
            "dmarq.org": [
                {
                    "date": "2026-06-01",
                    "score": 94,
                    "grade": "A",
                    "status": "healthy",
                    "policy": "reject",
                    "compliance_rate": 98,
                    "total_emails": 1000,
                    "failed_emails": 20,
                    "report_count": 10,
                    "dns_posture_score": 99,
                    "policy_strength_score": 100,
                    "report_confidence_score": 100,
                    "top_actions": [],
                }
            ],
            "dmarq.com": [
                {
                    "date": "2026-06-01",
                    "score": 70,
                    "grade": "C",
                    "status": "attention",
                    "policy": "none",
                    "compliance_rate": 75,
                    "total_emails": 1000,
                    "failed_emails": 250,
                    "report_count": 8,
                    "dns_posture_score": 80,
                    "policy_strength_score": 55,
                    "report_confidence_score": 90,
                    "top_actions": [{"title": "Move out of monitoring mode", "score_impact": 14}],
                }
            ],
        }
    )

    assert points[0]["score"] == 82
    assert points[0]["grade"] == "B-"
    assert points[0]["domain_count"] == 2
    assert points[0]["top_actions"][0]["domain"] == "dmarq.com"
