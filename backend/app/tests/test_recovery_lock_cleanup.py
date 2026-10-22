import fcntl
import threading
from types import SimpleNamespace

import pytest

from app.services import mail_source_recovery_lock as recovery_lock
from app.services.mail_source_recovery_lock import RecoveryLockBusy, source_recovery_lock


class _FakeSession:
    def __init__(self, database, dialect="sqlite"):
        self._bind = SimpleNamespace(
            dialect=SimpleNamespace(name=dialect),
            url=SimpleNamespace(database=str(database)),
        )

    def get_bind(self):
        return self._bind


def test_open_sqlite_lock_releases_mutex_when_file_lock_is_busy(tmp_path, monkeypatch):
    session = _FakeSession(tmp_path / "dmarq.sqlite")
    original_flock = fcntl.flock

    def fail_flock(*_args):
        raise BlockingIOError("lock already held")

    monkeypatch.setattr(fcntl, "flock", fail_flock)
    with pytest.raises(RecoveryLockBusy):
        recovery_lock._open_sqlite_lock(session)

    key = str((tmp_path / "dmarq.sqlite").with_suffix(".sqlite.mail-recovery.lock"))
    mutex = recovery_lock._process_lock(key)
    assert mutex.acquire(blocking=False)
    mutex.release()
    monkeypatch.setattr(fcntl, "flock", original_flock)


def test_open_sqlite_lock_releases_mutex_on_unexpected_file_error(tmp_path, monkeypatch):
    session = _FakeSession(tmp_path / "dmarq.sqlite")

    def fail_open(*_args, **_kwargs):
        raise OSError("cannot open lock file")

    monkeypatch.setattr(recovery_lock.Path, "open", fail_open)
    with pytest.raises(OSError, match="cannot open"):
        recovery_lock._open_sqlite_lock(session)

    key = str((tmp_path / "dmarq.sqlite").with_suffix(".sqlite.mail-recovery.lock"))
    mutex = recovery_lock._process_lock(key)
    assert mutex.acquire(blocking=False)
    mutex.release()


def test_discard_sqlite_lock_releases_mutex_when_file_close_fails():
    mutex = threading.Lock()
    assert mutex.acquire(blocking=False)

    class _BrokenFile:
        def close(self):
            raise OSError("close failed")

    with pytest.raises(OSError, match="close failed"):
        recovery_lock._discard_sqlite_lock(mutex, _BrokenFile())

    assert mutex.acquire(blocking=False)
    mutex.release()


def test_source_recovery_lock_rejects_unsupported_database(tmp_path):
    with pytest.raises(RecoveryLockBusy):
        with source_recovery_lock(_FakeSession(tmp_path / "dmarq.db", dialect="mysql"), 1):
            pass
