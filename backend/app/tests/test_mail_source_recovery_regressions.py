"""Focused regressions for import-history recovery lifecycle behavior."""

import json
from datetime import datetime, timedelta
from unittest.mock import patch

from app.api.api_v1.endpoints import mail_sources as mail_sources_endpoint
from app.models.mail_source import MailSource
from app.models.mail_source_import import MailSourceImport
from app.services.import_history import _latest_recovery_dispositions, _recovery_case_key
from app.services.mail_source_recovery import recovery_binding
from app.services.workspaces import get_or_create_default_workspace


def _source_and_rows(db_session):
    workspace = get_or_create_default_workspace(db_session)
    source = MailSource(
        workspace_id=workspace.id,
        name="Recovery regression source",
        method="GMAIL_API",
        gmail_email="reports@example.com",
    )
    db_session.add(source)
    db_session.flush()
    binding = recovery_binding(source)
    return workspace, source, binding


def _item(source, binding, message_id, disposition="pending", **extra):
    return {
        "message_id": message_id,
        "source_id": source.id,
        "workspace_id": source.workspace_id,
        "disposition": disposition,
        "supported": True,
        **binding,
        **extra,
    }


def test_history_keeps_older_real_failure_when_newer_cache_skip_is_seen(authed_client, db_session):
    workspace, source, binding = _source_and_rows(db_session)
    old = MailSourceImport(
        mail_source_id=source.id,
        status="warning",
        recovery_metadata=json.dumps([_item(source, binding, "m-1")]),
        started_at=datetime.utcnow() - timedelta(days=1),
    )
    recent = MailSourceImport(
        mail_source_id=source.id,
        status="success",
        recovery_metadata=json.dumps(
            [_item(source, binding, "m-1", reason="already_ingested_message")]
        ),
        started_at=datetime.utcnow(),
    )
    db_session.add_all([old, recent])
    db_session.commit()

    response = authed_client.get(
        f"/api/v1/mail-sources/{source.id}/imports?limit=1",
        headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
    )

    assert response.status_code == 200
    items = [item for row in response.json() for item in row["recovery_items"]]
    assert [(item["message_id"], item["disposition"]) for item in items] == [
        ("m-1", "settled"),
        ("m-1", "pending"),
    ]

    second = authed_client.get(
        f"/api/v1/mail-sources/{source.id}/imports?limit=1",
        headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
    )
    second_items = [item for row in second.json() for item in row["recovery_items"]]
    assert [(item["message_id"], item["disposition"]) for item in second_items] == [
        ("m-1", "settled"),
        ("m-1", "pending"),
    ]


def test_history_exposes_latest_duplicate_pending_and_supersedes_older(authed_client, db_session):
    workspace, source, binding = _source_and_rows(db_session)
    old = MailSourceImport(
        mail_source_id=source.id,
        status="warning",
        recovery_metadata=json.dumps([_item(source, binding, "m-2")]),
        started_at=datetime.utcnow() - timedelta(days=1),
    )
    recent = MailSourceImport(
        mail_source_id=source.id,
        status="warning",
        recovery_metadata=json.dumps([_item(source, binding, "m-2")]),
        started_at=datetime.utcnow(),
    )
    db_session.add_all([old, recent])
    db_session.commit()

    response = authed_client.get(
        f"/api/v1/mail-sources/{source.id}/imports?limit=1",
        headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
    )

    assert response.status_code == 200
    rows = response.json()
    assert rows[0]["recovery_items"][0]["disposition"] == "pending"
    assert len(rows) == 1
    assert (
        json.loads(db_session.get(MailSourceImport, old.id).recovery_metadata)[0]["disposition"]
        == "superseded"
    )


def test_retry_claim_blocks_second_request_before_provider_call(authed_client, db_session):
    workspace, source, binding = _source_and_rows(db_session)
    row = MailSourceImport(
        mail_source_id=source.id,
        status="warning",
        recovery_metadata=json.dumps([_item(source, binding, "m-3")]),
    )
    db_session.add(row)
    db_session.commit()
    mail_sources_endpoint._claim_recovery_item(db_session, source, row.id, "m-3")

    with patch.object(mail_sources_endpoint, "_retry_history_item") as provider:
        response = authed_client.post(
            f"/api/v1/mail-sources/{source.id}/imports/{row.id}/retry",
            headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
            json={"message_id": "m-3"},
        )

    assert response.status_code == 409
    provider.assert_not_called()


def test_cache_skip_does_not_overwrite_explicit_ignore_disposition(db_session):
    _, source, binding = _source_and_rows(db_session)
    ignored = MailSourceImport(
        mail_source_id=source.id,
        status="warning",
        recovery_metadata=json.dumps([_item(source, binding, "m-4", disposition="ignored")]),
    )
    cache_skip = MailSourceImport(
        mail_source_id=source.id,
        status="success",
        recovery_metadata=json.dumps(
            [
                _item(
                    source,
                    binding,
                    "m-4",
                    disposition="settled",
                    reason="already_ingested_message",
                )
            ]
        ),
    )
    db_session.add_all([ignored, cache_skip])
    db_session.commit()

    key = _recovery_case_key(_item(source, binding, "m-4"))
    assert _latest_recovery_dispositions(db_session, source)[key] == "ignored"
