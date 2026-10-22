"""Focused regressions for import-history recovery lifecycle behavior."""

import fcntl
import json
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from sqlalchemy.orm import sessionmaker

from app.api.api_v1.endpoints import mail_sources as mail_sources_endpoint
from app.models.mail_source import MailSource
from app.models.mail_source_import import MailSourceImport
from app.services import import_history as import_history_service
from app.services.import_history import (
    _json_recovery_metadata,
    _latest_recovery_dispositions,
    _recovery_case_key,
    _suppress_ignored_recovery_cases,
    record_import_attempt,
)
from app.services.mail_source_recovery import ignore_message, recovery_binding
from app.services.mail_source_recovery_lock import RecoveryLockBusy, source_recovery_lock
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


def test_imap_recovery_keys_namespace_uid_generation_and_mailbox_identity():
    common = {
        "message_id": "10",
        "method": "IMAP",
        "folder": "INBOX",
        "account": "reports@example.com",
    }
    sequence = _recovery_case_key({**common, "identifier_type": "sequence"})
    uid_42 = _recovery_case_key(
        {
            **common,
            "identifier_type": "uid",
            "uid_validity": "42",
            "server": "imap-a.example.com",
            "port": 993,
            "use_ssl": True,
        }
    )
    uid_43 = {**common, "identifier_type": "uid", "uid_validity": "43"}
    uid_other_server = {
        **common,
        "identifier_type": "uid",
        "uid_validity": "42",
        "server": "imap-b.example.com",
        "port": 993,
        "use_ssl": True,
    }

    assert sequence != uid_42
    assert uid_42 != _recovery_case_key(uid_43)
    assert uid_42 != _recovery_case_key(uid_other_server)
    assert uid_42 != _recovery_case_key({**common, "identifier_type": "uid"})


def test_imap_metadata_canonicalizes_legacy_sequence_and_preserves_uid_namespace():
    source = SimpleNamespace(
        id=1,
        workspace_id=2,
        method="IMAP",
        folder="INBOX",
        server="imap.example.com",
        port=993,
        username="reports@example.com",
        use_ssl=True,
    )
    metadata = json.loads(
        _json_recovery_metadata(
            source,
            [
                {"status": "error", "message_id": "10"},
                {
                    "status": "error",
                    "message_id": "11",
                    "identifier_type": "uid",
                    "uid_validity": 42,
                    "server": "imap.example.com",
                    "port": 993,
                    "use_ssl": True,
                    "account": "reports@example.com",
                },
            ],
        )
    )
    assert metadata[0]["identifier_type"] == "sequence"
    assert metadata[1]["identifier_type"] == "uid"
    assert metadata[1]["uid_validity"] == "42"
    assert metadata[1]["server"] == "imap.example.com"


def test_imap_ignored_sequence_does_not_suppress_uid_recovery_case():
    legacy_sequence = {
        "message_id": "10",
        "method": "IMAP",
        "folder": "INBOX",
        "account": "reports@example.com",
        "disposition": "ignored",
    }
    uid_case = {
        **legacy_sequence,
        "identifier_type": "uid",
        "uid_validity": "42",
        "server": "imap.example.com",
        "port": 993,
        "use_ssl": True,
        "disposition": "pending",
    }
    metadata = _suppress_ignored_recovery_cases(
        json.dumps([uid_case]), {_recovery_case_key(legacy_sequence)}
    )
    assert json.loads(metadata)[0]["disposition"] == "pending"

    uid_ignored = {**uid_case, "disposition": "ignored"}
    metadata = _suppress_ignored_recovery_cases(
        json.dumps([uid_case]), {_recovery_case_key(uid_ignored)}
    )
    assert json.loads(metadata)[0]["disposition"] == "ignored"


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


def test_retry_claim_blocks_second_request_before_provider_call(authed_client, db_session):
    workspace, source, binding = _source_and_rows(db_session)
    row = MailSourceImport(
        mail_source_id=source.id,
        status="warning",
        recovery_metadata=json.dumps([_item(source, binding, "m-3")]),
    )
    db_session.add(row)
    db_session.commit()
    with source_recovery_lock(db_session, source.id):
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


def test_durable_ignore_wins_over_poll_race_for_get_and_retry(authed_client, db_session):
    workspace, source, binding = _source_and_rows(db_session)
    row = MailSourceImport(
        mail_source_id=source.id,
        status="warning",
        recovery_metadata=json.dumps([_item(source, binding, "race-1")]),
    )
    db_session.add(row)
    db_session.commit()

    poll_session = sessionmaker(bind=db_session.get_bind())()
    ignore_session = sessionmaker(bind=db_session.get_bind())()
    try:
        poll_source = poll_session.get(MailSource, source.id)
        ignore_source = ignore_session.get(MailSource, source.id)
        registry_read = False
        original_registry_read = import_history_service.ignored_message_ids

        def read_registry_then_commit_ignore(db, current_source):
            nonlocal registry_read
            result = original_registry_read(db, current_source)
            if current_source.id == source.id and not registry_read:
                registry_read = True
                ignore_message(ignore_session, ignore_source, "race-1")
                ignore_session.commit()
            return result

        # Pause exactly after polling's final durable-ignore read and commit
        # the independent ignore before polling inserts its stale failure row.
        with patch.object(
            import_history_service,
            "ignored_message_ids",
            side_effect=read_registry_then_commit_ignore,
        ):
            record_import_attempt(
                poll_session,
                poll_source,
                {
                    "success": False,
                    "errors": ["provider failed"],
                    "details": [{"status": "error", "message_id": "race-1"}],
                },
                started_at=datetime.utcnow(),
                trigger="scheduled",
            )
        poll_session.commit()
        assert registry_read
    finally:
        poll_session.close()
        ignore_session.close()

    response = authed_client.get(
        f"/api/v1/mail-sources/{source.id}/imports?limit=1",
        headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
    )
    assert response.status_code == 200
    item = response.json()[0]["recovery_items"][0]
    assert item["message_id"] == "race-1"
    assert item["disposition"] == "ignored"

    with patch.object(mail_sources_endpoint, "_retry_history_item") as provider:
        retry = authed_client.post(
            f"/api/v1/mail-sources/{source.id}/imports/{row.id}/retry",
            headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
            json={"message_id": "race-1"},
        )
    assert retry.status_code == 409
    provider.assert_not_called()


def test_durable_ignore_is_binding_scoped(authed_client, db_session):
    workspace, source, binding = _source_and_rows(db_session)
    other = MailSource(
        workspace_id=workspace.id,
        name="Other binding",
        method="GMAIL_API",
        gmail_email="other@example.com",
    )
    db_session.add(other)
    db_session.flush()
    first = MailSourceImport(
        mail_source_id=source.id,
        status="warning",
        recovery_metadata=json.dumps([_item(source, binding, "same-id")]),
    )
    other_row = MailSourceImport(
        mail_source_id=other.id,
        status="warning",
        recovery_metadata=json.dumps([_item(other, recovery_binding(other), "same-id")]),
    )
    db_session.add_all([first, other_row])
    ignore_message(db_session, source, "same-id")
    db_session.commit()

    response = authed_client.get(
        f"/api/v1/mail-sources/{other.id}/imports?limit=1",
        headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
    )
    assert response.status_code == 200
    assert response.json()[0]["recovery_items"][0]["disposition"] == "pending"


def test_get_uses_id_authority_when_started_at_order_is_reversed(authed_client, db_session):
    workspace, source, binding = _source_and_rows(db_session)
    pending = MailSourceImport(
        mail_source_id=source.id,
        status="warning",
        recovery_metadata=json.dumps([_item(source, binding, "order-1")]),
        started_at=datetime.utcnow() + timedelta(days=1),
    )
    db_session.add(pending)
    db_session.commit()
    ignored = MailSourceImport(
        mail_source_id=source.id,
        status="warning",
        recovery_metadata=json.dumps([_item(source, binding, "order-1", disposition="ignored")]),
        started_at=datetime.utcnow() - timedelta(days=1),
    )
    db_session.add(ignored)
    db_session.commit()

    response = authed_client.get(
        f"/api/v1/mail-sources/{source.id}/imports?limit=1",
        headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
    )
    assert response.status_code == 200
    assert response.json()[0]["id"] == pending.id
    assert response.json()[0]["recovery_items"][0]["disposition"] == "ignored"


def test_get_resolves_recent_case_before_candidate_quota(authed_client, db_session):
    workspace, source, binding = _source_and_rows(db_session)
    recent_pending = MailSourceImport(
        mail_source_id=source.id,
        status="warning",
        recovery_metadata=json.dumps([_item(source, binding, "case-a")]),
        started_at=datetime.utcnow() + timedelta(days=2),
    )
    db_session.add(recent_pending)
    db_session.commit()
    older_ignored = MailSourceImport(
        mail_source_id=source.id,
        status="warning",
        recovery_metadata=json.dumps([_item(source, binding, "case-a", disposition="ignored")]),
        started_at=datetime.utcnow() - timedelta(days=2),
    )
    older_independent = MailSourceImport(
        mail_source_id=source.id,
        status="warning",
        recovery_metadata=json.dumps([_item(source, binding, "case-b")]),
        started_at=datetime.utcnow() - timedelta(days=3),
    )
    db_session.add_all([older_ignored, older_independent])
    db_session.commit()

    response = authed_client.get(
        f"/api/v1/mail-sources/{source.id}/imports?limit=1",
        headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
    )
    assert response.status_code == 200
    assert response.json()[0]["id"] == recent_pending.id
    assert response.json()[0]["recovery_items"][0]["disposition"] == "ignored"


def test_get_does_not_project_newer_pending_onto_older_terminal_row(authed_client, db_session):
    workspace, source, binding = _source_and_rows(db_session)
    older_terminal = MailSourceImport(
        mail_source_id=source.id,
        status="warning",
        recovery_metadata=json.dumps(
            [_item(source, binding, "pending-projection", disposition="ignored")]
        ),
        started_at=datetime.utcnow() + timedelta(days=1),
    )
    db_session.add(older_terminal)
    db_session.commit()
    newer_pending = MailSourceImport(
        mail_source_id=source.id,
        status="warning",
        recovery_metadata=json.dumps([_item(source, binding, "pending-projection")]),
        started_at=datetime.utcnow() - timedelta(days=1),
    )
    db_session.add(newer_pending)
    db_session.commit()

    response = authed_client.get(
        f"/api/v1/mail-sources/{source.id}/imports?limit=2",
        headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
    )

    assert response.status_code == 200
    by_id = {row["id"]: row["recovery_items"][0] for row in response.json()}
    assert by_id[older_terminal.id]["disposition"] == "ignored"
    assert by_id[newer_pending.id]["disposition"] == "pending"


def test_error_beyond_stored_recovery_details_keeps_prior_case_pending(db_session):
    _, source, binding = _source_and_rows(db_session)
    old = MailSourceImport(
        mail_source_id=source.id,
        status="failed",
        recovery_metadata=json.dumps([_item(source, binding, "error-51")]),
    )
    db_session.add(old)
    db_session.commit()

    details = [{"status": "error", "message_id": f"error-{index}"} for index in range(1, 51)]
    details.append({"status": "error", "message_id": "error-51"})
    attempt = record_import_attempt(
        db_session,
        source,
        {"success": False, "errors": ["provider failed"], "details": details},
        started_at=datetime.utcnow(),
        trigger="scheduled",
    )
    db_session.commit()

    old_item = mail_sources_endpoint._decode_recovery_metadata(old.recovery_metadata)[0]
    new_items = mail_sources_endpoint._decode_recovery_metadata(attempt.recovery_metadata)
    assert old_item["disposition"] == "pending"
    assert "error-51" not in {item["message_id"] for item in new_items}


def test_omitted_error_wins_over_later_imported_detail(db_session):
    _, source, binding = _source_and_rows(db_session)
    old = MailSourceImport(
        mail_source_id=source.id,
        status="failed",
        recovery_metadata=json.dumps([_item(source, binding, "mixed-51")]),
    )
    db_session.add(old)
    db_session.commit()

    details = [{"status": "error", "message_id": f"error-{index}"} for index in range(1, 51)]
    details.extend(
        [
            {"status": "error", "message_id": "mixed-51"},
            {"status": "imported", "message_id": "mixed-51"},
        ]
    )
    record_import_attempt(
        db_session,
        source,
        {"success": False, "errors": ["provider failed"], "details": details},
        started_at=datetime.utcnow(),
        trigger="scheduled",
    )
    db_session.commit()

    assert (
        mail_sources_endpoint._decode_recovery_metadata(old.recovery_metadata)[0]["disposition"]
        == "pending"
    )


def test_legacy_retried_failure_and_reasonless_skip_are_normalized_safely(
    authed_client, db_session
):
    workspace, source, binding = _source_and_rows(db_session)

    def legacy(message_id, details, disposition="pending", **extra):
        item = {
            **_item(source, binding, message_id, disposition=disposition),
            **extra,
        }
        row = MailSourceImport(
            mail_source_id=source.id,
            status="warning",
            details=json.dumps(details),
            recovery_metadata=json.dumps([item]),
        )
        db_session.add(row)
        db_session.flush()
        return row

    retry_failed = legacy(
        "legacy-retry",
        [{"status": "error", "message_id": "legacy-retry"}],
        disposition="retried",
        last_status="failed",
    )
    skip_only = legacy(
        "legacy-skip",
        [{"status": "skipped", "message_id": "legacy-skip"}],
    )
    explicit_skip = legacy(
        "legacy-explicit-skip",
        [
            {
                "status": "skipped",
                "reason": "already_ingested_message",
                "message_id": "legacy-explicit-skip",
            }
        ],
    )
    failed_skip = legacy(
        "legacy-failed-skip",
        [{"status": "skipped", "message_id": "legacy-failed-skip"}],
        last_status="failed",
    )
    mixed = legacy(
        "legacy-mixed",
        [
            {"status": "skipped", "message_id": "legacy-mixed"},
            {"status": "error", "message_id": "legacy-mixed"},
        ],
    )
    unrelated = legacy(
        "legacy-unrelated",
        [{"status": "skipped", "message_id": "different-message"}],
    )
    db_session.commit()

    response = authed_client.get(
        f"/api/v1/mail-sources/{source.id}/imports?limit=20",
        headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
    )
    assert response.status_code == 200
    by_id = {row["id"]: row["recovery_items"][0] for row in response.json()}
    assert by_id[retry_failed.id]["disposition"] == "pending"
    assert by_id[skip_only.id]["disposition"] == "pending"
    assert by_id[explicit_skip.id]["disposition"] == "settled"
    assert by_id[failed_skip.id]["disposition"] == "pending"
    assert by_id[mixed.id]["disposition"] == "pending"
    assert by_id[unrelated.id]["disposition"] == "pending"

    with patch.object(
        mail_sources_endpoint,
        "_retry_history_item",
        return_value=({"success": True, "details": []}, None),
    ) as provider:
        retry = authed_client.post(
            f"/api/v1/mail-sources/{source.id}/imports/{retry_failed.id}/retry",
            headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
            json={"message_id": "legacy-retry"},
        )
    assert retry.status_code == 200
    provider.assert_called_once()


@pytest.mark.parametrize("metadata_reason", [True, False])
def test_known_failure_survives_cache_skip_on_get_and_direct_retry(
    authed_client, db_session, metadata_reason
):
    workspace, source, binding = _source_and_rows(db_session)

    def make_row(message_id):
        item = _item(source, binding, message_id, last_status="failed")
        if metadata_reason:
            item["reason"] = "already_ingested_message"
        return MailSourceImport(
            mail_source_id=source.id,
            status="warning",
            details=json.dumps(
                [
                    {
                        "status": "skipped",
                        "reason": "already_ingested_message",
                        "message_id": message_id,
                    }
                ]
            ),
            recovery_metadata=json.dumps([item]),
        )

    direct = make_row("direct-failed")
    visible = make_row("visible-failed")
    db_session.add_all([direct, visible])
    db_session.commit()
    headers = {"X-DMARQ-Workspace-ID": str(workspace.id)}
    with patch.object(
        mail_sources_endpoint,
        "_retry_history_item",
        return_value=({"success": True, "details": []}, None),
    ) as provider:
        retry = authed_client.post(
            f"/api/v1/mail-sources/{source.id}/imports/{direct.id}/retry",
            headers=headers,
            json={"message_id": "direct-failed"},
        )
    assert retry.status_code == 200
    provider.assert_called_once()
    response = authed_client.get(
        f"/api/v1/mail-sources/{source.id}/imports?limit=20", headers=headers
    )
    assert response.status_code == 200
    visible_row = next(row for row in response.json() if row["id"] == visible.id)
    assert visible_row["recovery_items"][0]["disposition"] == "pending"


def test_legacy_failed_retry_outside_recent_window_is_visible_and_actionable(
    authed_client, db_session
):
    workspace, source, binding = _source_and_rows(db_session)
    old = MailSourceImport(
        mail_source_id=source.id,
        status="warning",
        recovery_metadata=json.dumps(
            [_item(source, binding, "legacy-old", disposition="retried", last_status="failed")]
        ),
    )
    db_session.add(old)
    db_session.flush()
    db_session.add(
        MailSourceImport(
            mail_source_id=source.id,
            status="success",
            recovery_metadata="[]",
        )
    )
    db_session.commit()

    response = authed_client.get(
        f"/api/v1/mail-sources/{source.id}/imports?limit=1",
        headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
    )
    assert response.status_code == 200
    assert any(
        item["message_id"] == "legacy-old" and item["disposition"] == "pending"
        for row in response.json()
        for item in row["recovery_items"]
    )


def test_legacy_failed_retry_can_be_retried_without_get(authed_client, db_session):
    workspace, source, binding = _source_and_rows(db_session)
    row = MailSourceImport(
        mail_source_id=source.id,
        status="warning",
        recovery_metadata=json.dumps(
            [_item(source, binding, "legacy-direct", disposition="retried", last_status="failed")]
        ),
    )
    db_session.add(row)
    db_session.commit()

    with patch.object(
        mail_sources_endpoint,
        "_retry_history_item",
        return_value=({"success": True, "details": []}, None),
    ) as provider:
        response = authed_client.post(
            f"/api/v1/mail-sources/{source.id}/imports/{row.id}/retry",
            headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
            json={"message_id": "legacy-direct"},
        )
    assert response.status_code == 200
    provider.assert_called_once()


def test_ambiguous_batch_success_without_matching_detail_keeps_failure_pending(db_session):
    _, source, binding = _source_and_rows(db_session)
    row = MailSourceImport(
        mail_source_id=source.id,
        status="failed",
        details=json.dumps([{"status": "error", "message_id": "failed-message"}]),
        recovery_metadata=json.dumps([_item(source, binding, "failed-message")]),
    )
    db_session.add(row)
    db_session.commit()

    record_import_attempt(
        db_session,
        source,
        {
            "success": True,
            "new_ingested_ids": ["failed-message"],
            "errors": ["failed outside retained window"],
            "details": [],
        },
        started_at=datetime.utcnow(),
        trigger="scheduled",
    )
    db_session.commit()

    items = mail_sources_endpoint._decode_recovery_metadata(row.recovery_metadata)
    assert items[0]["disposition"] == "pending"


def test_recovery_lock_releases_after_provider_failure(db_session):
    _, source, _ = _source_and_rows(db_session)

    try:
        with source_recovery_lock(db_session, source.id):
            raise RuntimeError("provider failed")
    except RuntimeError:
        pass

    with source_recovery_lock(db_session, source.id):
        pass


class _FakePgResult:
    def __init__(self, acquired):
        self.acquired = acquired

    def scalar(self):
        return self.acquired


class _FakePgConnection:
    def __init__(self, acquired=True, unlock_error=False):
        self.acquired = acquired
        self.unlock_error = unlock_error
        self.closed = 0
        self.invalidated = 0
        self.statements = []

    def execute(self, statement, params):
        self.statements.append((str(statement), params))
        if len(self.statements) == 2 and self.unlock_error:
            raise RuntimeError("unlock failed")
        return _FakePgResult(self.acquired if len(self.statements) == 1 else True)

    def close(self):
        self.closed += 1

    def invalidate(self):
        self.invalidated += 1


class _FakePgBind:
    class _Dialect:
        name = "postgresql"

    dialect = _Dialect()

    def __init__(self, connection):
        self.connection = connection

    def connect(self):
        return self.connection


class _FakePgSession:
    def __init__(self, bind):
        self.bind = bind

    def get_bind(self):
        return self.bind


def test_postgres_recovery_lock_uses_dedicated_connection_and_unlocks():
    connection = _FakePgConnection()
    with source_recovery_lock(_FakePgSession(_FakePgBind(connection)), 42):
        assert connection.closed == 0
    assert connection.closed == 1
    assert "pg_try_advisory_lock" in connection.statements[0][0]
    assert "pg_advisory_unlock" in connection.statements[1][0]


def test_postgres_recovery_lock_reports_busy_without_entering():
    connection = _FakePgConnection(acquired=False)
    try:
        with source_recovery_lock(_FakePgSession(_FakePgBind(connection)), 42):
            raise AssertionError("lock body must not run")
    except RecoveryLockBusy:
        pass
    assert connection.closed == 1


def test_postgres_recovery_lock_invalidates_connection_when_unlock_fails():
    connection = _FakePgConnection(unlock_error=True)
    try:
        with source_recovery_lock(_FakePgSession(_FakePgBind(connection)), 42):
            pass
    except RuntimeError:
        pass
    assert connection.invalidated == 1
    assert connection.closed == 1


def test_sqlite_recovery_lock_releases_file_and_mutex_when_unlock_fails(tmp_path, monkeypatch):
    database = tmp_path / "dmarq.db"
    bind = SimpleNamespace(
        dialect=SimpleNamespace(name="sqlite"),
        url=SimpleNamespace(database=str(database)),
    )
    session = _FakePgSession(bind)
    original_flock = fcntl.flock
    calls = []

    def fail_unlock(fd, operation):
        calls.append(operation)
        if operation == fcntl.LOCK_UN:
            raise OSError("unlock failed")
        return original_flock(fd, operation)

    monkeypatch.setattr(fcntl, "flock", fail_unlock)
    try:
        with source_recovery_lock(session, 43):
            pass
    except OSError:
        pass
    assert calls == [fcntl.LOCK_EX | fcntl.LOCK_NB, fcntl.LOCK_UN]

    monkeypatch.setattr(fcntl, "flock", original_flock)
    with source_recovery_lock(session, 43):
        pass


def test_retry_rejects_older_pending_case_after_newer_ignore(authed_client, db_session):
    workspace, source, binding = _source_and_rows(db_session)
    older = MailSourceImport(
        mail_source_id=source.id,
        status="warning",
        recovery_metadata=json.dumps([_item(source, binding, "m-5")]),
    )
    newer = MailSourceImport(
        mail_source_id=source.id,
        status="warning",
        recovery_metadata=json.dumps([_item(source, binding, "m-5", disposition="ignored")]),
    )
    db_session.add_all([older, newer])
    db_session.commit()

    with patch.object(mail_sources_endpoint, "_retry_history_item") as provider:
        response = authed_client.post(
            f"/api/v1/mail-sources/{source.id}/imports/{older.id}/retry",
            headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
            json={"message_id": "m-5"},
        )

    assert response.status_code == 409
    provider.assert_not_called()


def test_history_skips_older_pending_when_newer_terminal_is_outside_recent_window(
    authed_client, db_session
):
    workspace, source, binding = _source_and_rows(db_session)
    old_pending = MailSourceImport(
        mail_source_id=source.id,
        status="warning",
        recovery_metadata=json.dumps([_item(source, binding, "m-6")]),
    )
    newer_ignored = MailSourceImport(
        mail_source_id=source.id,
        status="warning",
        recovery_metadata=json.dumps([_item(source, binding, "m-6", disposition="ignored")]),
    )
    clean = MailSourceImport(mail_source_id=source.id, status="success", recovery_metadata="[]")
    db_session.add_all([old_pending, newer_ignored, clean])
    db_session.commit()

    response = authed_client.get(
        f"/api/v1/mail-sources/{source.id}/imports?limit=1",
        headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
    )
    assert response.status_code == 200
    assert all(
        item["message_id"] != "m-6" for row in response.json() for item in row["recovery_items"]
    )


def test_history_deduplicates_candidates_before_finding_older_independent_case(
    authed_client, db_session
):
    workspace, source, binding = _source_and_rows(db_session)
    rows = [
        MailSourceImport(
            mail_source_id=source.id,
            status="warning",
            recovery_metadata=json.dumps([_item(source, binding, "m-7")]),
        ),
        MailSourceImport(
            mail_source_id=source.id,
            status="warning",
            recovery_metadata=json.dumps([_item(source, binding, "m-7")]),
        ),
        MailSourceImport(
            mail_source_id=source.id,
            status="warning",
            recovery_metadata=json.dumps([_item(source, binding, "m-8")]),
        ),
    ]
    db_session.add_all(rows)
    db_session.commit()

    response = authed_client.get(
        f"/api/v1/mail-sources/{source.id}/imports?limit=2",
        headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
    )
    messages = {
        item["message_id"]
        for row in response.json()
        for item in row["recovery_items"]
        if item["disposition"] == "pending"
    }
    assert messages == {"m-7", "m-8"}


@pytest.mark.parametrize("outcome, expected", [("imported", "settled"), ("error", "superseded")])
def test_normal_poll_reconciles_legacy_failed_retry_before_history_get(
    authed_client, db_session, outcome, expected
):
    workspace, source, binding = _source_and_rows(db_session)
    old = MailSourceImport(
        mail_source_id=source.id,
        status="warning",
        error_count=1,
        errors=json.dumps(["Original failure"]),
        details=json.dumps([{"status": "error", "message_id": "legacy-poll"}]),
        recovery_metadata=json.dumps(
            [_item(source, binding, "legacy-poll", disposition="retried", last_status="failed")]
        ),
    )
    db_session.add(old)
    db_session.commit()
    diagnostics = (old.status, old.error_count, old.errors, old.details)

    record_import_attempt(
        db_session,
        source,
        {
            "success": outcome == "imported",
            "errors": [] if outcome == "imported" else ["New failure"],
            "details": [{"status": outcome, "message_id": "legacy-poll"}],
        },
        started_at=datetime.utcnow(),
        trigger="scheduled",
    )
    db_session.commit()
    db_session.refresh(old)
    item = json.loads(old.recovery_metadata)[0]
    assert item["disposition"] == expected
    assert item["last_status"] == ("success" if outcome == "imported" else "failed")
    assert (old.status, old.error_count, old.errors, old.details) == diagnostics

    response = authed_client.get(
        f"/api/v1/mail-sources/{source.id}/imports",
        headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
    )
    assert response.status_code == 200
    rows = response.json()
    previous = next(row for row in rows if row["id"] == old.id)
    assert previous["recovery_items"][0]["disposition"] == expected
    pending = [
        item for row in rows for item in row["recovery_items"] if item["disposition"] == "pending"
    ]
    assert len(pending) == (0 if outcome == "imported" else 1)
