import json
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.services import import_history
from app.services.mail_source_recovery_lock import RecoveryLockBusy, source_recovery_lock


class _CasQuery:
    def __init__(self, db, mode):
        self.db = db
        self.mode = mode

    def filter(self, *args, **kwargs):  # noqa: ARG002
        return self

    def all(self):
        return [(self.db.row_id, self.db.original)]

    def update(self, values, synchronize_session=False):  # noqa: ARG002
        if self.mode == "compare_and_swap":
            self.db.cas_attempts += 1
            return 0
        self.db.retry_values = values
        return 1

    def scalar(self):
        return self.db.current


class _CasDatabase:
    def __init__(self, original, current):
        self.row_id = 17
        self.original = original
        self.current = current
        self.cas_attempts = 0
        self.query_calls = 0
        self.retry_values = None
        self.tracked = SimpleNamespace(recovery_metadata=current)

    def query(self, *entities):  # noqa: ARG002
        self.query_calls += 1
        mode = {1: "history", 2: "compare_and_swap"}.get(self.query_calls, "retry")
        return _CasQuery(self, mode)

    def get(self, model, row_id):  # noqa: ARG002
        assert row_id == self.row_id
        return self.tracked


def test_reconcile_recovery_history_retries_after_compare_and_swap_loss(monkeypatch):
    source = SimpleNamespace(
        id=9,
        method="GMAIL_API",
        folder="INBOX",
        gmail_email="reports@example.com",
        gmail_client_id="client",
    )
    item = {
        "message_id": "msg-1",
        "disposition": "pending",
        **import_history.recovery_binding(source),
    }
    original = json.dumps([item])
    current = json.dumps([item])
    db = _CasDatabase(original, current)
    monkeypatch.setattr(
        import_history,
        "set_committed_value",
        lambda target, attribute, value: setattr(target, attribute, value),
    )

    import_history._reconcile_recovery_history(
        db,
        source,
        {"details": [{"status": "error", "message_id": "msg-1"}]},
    )

    assert db.cas_attempts == 1
    assert db.retry_values is not None
    retried_metadata = next(iter(db.retry_values.values()))
    assert json.loads(retried_metadata)[0]["disposition"] == "superseded"
    assert json.loads(db.tracked.recovery_metadata)[0]["last_status"] == "failed"


def test_sqlite_recovery_lock_contends_across_independent_sessions(tmp_path):
    database = tmp_path / "recovery.sqlite"
    engine = create_engine(f"sqlite:///{database}")
    sessions = sessionmaker(bind=engine)
    first, second = sessions(), sessions()
    try:
        with source_recovery_lock(first, 91):
            with pytest.raises(RecoveryLockBusy):
                with source_recovery_lock(second, 91):
                    pass
        with source_recovery_lock(second, 91):
            pass
    finally:
        first.close()
        second.close()
        engine.dispose()


class _UnlockFalseResult:
    def scalar(self):
        return False


class _UnlockFalseConnection:
    def __init__(self):
        self.closed = 0
        self.invalidated = 0
        self.statements = []

    def execute(self, statement, params):
        self.statements.append((str(statement), params))
        if len(self.statements) == 1:
            return SimpleNamespace(scalar=lambda: True)
        return _UnlockFalseResult()

    def close(self):
        self.closed += 1

    def invalidate(self):
        self.invalidated += 1


def test_postgres_recovery_lock_invalidates_when_unlock_reports_false():
    connection = _UnlockFalseConnection()
    bind = SimpleNamespace(
        dialect=SimpleNamespace(name="postgresql"),
        connect=lambda: connection,
    )
    session = SimpleNamespace(get_bind=lambda: bind)

    with source_recovery_lock(session, 92):
        pass

    assert connection.invalidated == 1
    assert connection.closed == 1
