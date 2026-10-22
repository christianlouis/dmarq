"""Focused regressions for import-history recovery lifecycle behavior."""

import json
import fcntl
from datetime import datetime, timedelta
from types import SimpleNamespace
from unittest.mock import patch
from sqlalchemy.orm import sessionmaker

from app.api.api_v1.endpoints import mail_sources as mail_sources_endpoint
from app.services import import_history as import_history_service
from app.models.mail_source import MailSource
from app.models.mail_source_import import MailSourceImport
from app.services.import_history import (
    _latest_recovery_dispositions,
    _recovery_case_key,
    record_import_attempt,
)
from app.services.mail_source_recovery import ignore_message, recovery_binding
from app.services.mail_source_recovery_lock import source_recovery_lock
from app.services.mail_source_recovery_lock import RecoveryLockBusy
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
        ("m-1", "pending"),
        ("m-1", "pending"),
    ]

    second = authed_client.get(
        f"/api/v1/mail-sources/{source.id}/imports?limit=1",
        headers={"X-DMARQ-Workspace-ID": str(workspace.id)},
    )
    second_items = [item for row in second.json() for item in row["recovery_items"]]
    assert [(item["message_id"], item["disposition"]) for item in second_items] == [
        ("m-1", "pending"),
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
