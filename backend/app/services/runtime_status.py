"""Small in-process status tracker for scheduler health."""

from datetime import datetime
from typing import Any, Dict, Optional


_scheduler_state: Dict[str, Any] = {
    "running": False,
    "started_at": None,
    "stopped_at": None,
    "last_cycle_started_at": None,
    "last_success_at": None,
    "last_error_at": None,
    "last_error": None,
}


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() if value else None


def mark_scheduler_started() -> None:
    now = datetime.utcnow()
    _scheduler_state.update(
        {
            "running": True,
            "started_at": now,
            "stopped_at": None,
            "last_error": None,
        }
    )


def mark_scheduler_stopped() -> None:
    _scheduler_state.update({"running": False, "stopped_at": datetime.utcnow()})


def mark_scheduler_cycle_started() -> None:
    _scheduler_state["last_cycle_started_at"] = datetime.utcnow()


def mark_scheduler_success() -> None:
    _scheduler_state.update({"last_success_at": datetime.utcnow(), "last_error": None})


def mark_scheduler_error(error: object) -> None:
    text = str(error)
    _scheduler_state.update(
        {
            "last_error_at": datetime.utcnow(),
            "last_error": text[:300],
        }
    )


def get_scheduler_status() -> Dict[str, Any]:
    return {
        "running": bool(_scheduler_state["running"]),
        "started_at": _iso(_scheduler_state["started_at"]),
        "stopped_at": _iso(_scheduler_state["stopped_at"]),
        "last_cycle_started_at": _iso(_scheduler_state["last_cycle_started_at"]),
        "last_success_at": _iso(_scheduler_state["last_success_at"]),
        "last_error_at": _iso(_scheduler_state["last_error_at"]),
        "last_error": _scheduler_state["last_error"],
    }
