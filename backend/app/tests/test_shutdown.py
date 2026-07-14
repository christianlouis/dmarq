"""Tests for the FastAPI shutdown event handler in app.main."""
import asyncio
from unittest.mock import AsyncMock, MagicMock

from app import main
from app.main import app


class _RaisingTask:
    """Awaitable stand-in for the polling task whose await raises exc."""

    def __init__(self, exc):
        self._exc = exc
        self.cancel_called = False

    def cancel(self):
        self.cancel_called = True

    def __await__(self):
        raise self._exc
        yield


def _shutdown_handler():
    return next(
        handler
        for handler in app.router.on_shutdown
        if getattr(handler, "__name__", "") == "shutdown_event"
    )


def test_shutdown_event_logs_cancelled_error(monkeypatch, caplog):
    monkeypatch.setattr(main, "_cancel_background_task", AsyncMock())
    monkeypatch.setattr(main, "mark_scheduler_stopped", MagicMock())
    task = _RaisingTask(asyncio.CancelledError())
    monkeypatch.setattr(main, "background_task", task)

    handler = _shutdown_handler()
    with caplog.at_level("INFO"):
        asyncio.run(handler())

    assert task.cancel_called
    assert "cancelled successfully" in caplog.text


def test_shutdown_event_logs_unexpected_exception(monkeypatch, caplog):
    monkeypatch.setattr(main, "_cancel_background_task", AsyncMock())
    monkeypatch.setattr(main, "mark_scheduler_stopped", MagicMock())
    task = _RaisingTask(RuntimeError("boom"))
    monkeypatch.setattr(main, "background_task", task)

    handler = _shutdown_handler()
    with caplog.at_level("INFO"):
        asyncio.run(handler())

    assert task.cancel_called
    assert "Unexpected error" in caplog.text
