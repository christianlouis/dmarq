"""Process and database scoped serialization for manual recovery actions."""

from __future__ import annotations

import hashlib
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, Optional

from sqlalchemy import text
from sqlalchemy.orm import Session


class RecoveryLockBusy(RuntimeError):
    """Another retry or ignore is currently operating on this source."""


_PROCESS_LOCKS: dict[str, threading.Lock] = {}
_PROCESS_LOCKS_GUARD = threading.Lock()


def _process_lock(key: str) -> threading.Lock:
    with _PROCESS_LOCKS_GUARD:
        return _PROCESS_LOCKS.setdefault(key, threading.Lock())


def _advisory_key(source_id: int) -> int:
    digest = hashlib.sha256(f"dmarq:mail-source-recovery:{source_id}".encode()).digest()
    return int.from_bytes(digest[:8], byteorder="big", signed=True)


def _sqlite_lock_path(db: Session) -> Optional[Path]:
    database = db.get_bind().url.database
    if not database or database == ":memory:":
        return None
    return Path(database).resolve().with_suffix(Path(database).suffix + ".mail-recovery.lock")


@contextmanager
def source_recovery_lock(db: Session, source_id: int) -> Iterator[None]:
    """Hold one source lock through provider work and the final DB commit.

    PostgreSQL uses a dedicated connection so session commits do not release
    the advisory lock. SQLite uses a process mutex plus a nonblocking file
    lock; in-memory SQLite has only the process mutex because it has no shared
    filesystem identity.
    """
    dialect = db.get_bind().dialect.name
    if dialect == "postgresql":
        connection = db.get_bind().connect()
        key = _advisory_key(source_id)
        try:
            acquired = bool(
                connection.execute(text("SELECT pg_try_advisory_lock(:key)"), {"key": key}).scalar()
            )
            if not acquired:
                raise RecoveryLockBusy
            try:
                yield
            finally:
                try:
                    unlocked = bool(
                        connection.execute(
                            text("SELECT pg_advisory_unlock(:key)"), {"key": key}
                        ).scalar()
                    )
                    if not unlocked:
                        connection.invalidate()
                except Exception:
                    connection.invalidate()
                    raise
        except Exception:
            connection.close()
            raise
        else:
            connection.close()
        return

    if dialect == "sqlite":
        lock_key = str(_sqlite_lock_path(db) or f"sqlite-memory:{id(db.get_bind())}")
        mutex = _process_lock(lock_key)
        if not mutex.acquire(blocking=False):
            raise RecoveryLockBusy
        lock_file = None
        try:
            path = _sqlite_lock_path(db)
            if path is not None:
                import fcntl

                path.parent.mkdir(parents=True, exist_ok=True)
                lock_file = path.open("a+")
                try:
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError as exc:
                    raise RecoveryLockBusy from exc
            yield
        finally:
            if lock_file is not None:
                import fcntl

                fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)
                lock_file.close()
            mutex.release()
        return

    raise RecoveryLockBusy
