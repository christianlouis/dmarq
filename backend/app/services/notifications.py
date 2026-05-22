"""Notification delivery helpers backed by Apprise."""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from typing import Dict, List, Optional, Tuple

import apprise
from sqlalchemy.orm import Session

from app.models.setting import Setting

logger = logging.getLogger(__name__)


@dataclass
class NotificationResult:
    """Sanitized result for a notification send attempt."""

    success: bool
    message: str
    configured_targets: int = 0
    invalid_targets: int = 0
    skipped: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def _truthy(value: Optional[str]) -> bool:
    return str(value or "").strip().lower() in {"1", "true", "yes", "on"}


def _split_apprise_urls(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [
        line.strip()
        for line in value.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


def _notification_settings(db: Session) -> Dict[str, Optional[str]]:
    rows = db.query(Setting).filter(Setting.category == "notifications").all()
    return {row.key: row.value for row in rows}


def _add_apprise_targets(notifier: apprise.Apprise, urls: List[str]) -> Tuple[int, int]:
    configured_targets = 0
    invalid_targets = 0
    for url in urls:
        try:
            if notifier.add(url):
                configured_targets += 1
            else:
                invalid_targets += 1
        except Exception:  # pylint: disable=broad-exception-caught
            invalid_targets += 1
            logger.warning("Invalid Apprise notification target was ignored.")
    return configured_targets, invalid_targets


def send_notification(
    db: Session,
    *,
    title: str,
    body: str,
    force: bool = False,
) -> NotificationResult:
    """Send a notification through configured Apprise target URLs."""
    settings = _notification_settings(db)
    enabled = _truthy(settings.get("notifications.apprise_enabled"))

    if not enabled and not force:
        return NotificationResult(
            success=False,
            skipped=True,
            message="Notifications are disabled.",
        )

    urls = _split_apprise_urls(settings.get("notifications.apprise_urls"))
    if not urls:
        return NotificationResult(
            success=False,
            message="No notification targets are configured.",
        )

    notifier = apprise.Apprise()
    configured_targets, invalid_targets = _add_apprise_targets(notifier, urls)

    if configured_targets == 0:
        return NotificationResult(
            success=False,
            message="No valid notification targets are configured.",
            invalid_targets=invalid_targets,
        )

    try:
        success = bool(notifier.notify(title=title, body=body))
    except Exception:  # pylint: disable=broad-exception-caught
        logger.exception("Apprise notification delivery failed.")
        return NotificationResult(
            success=False,
            message="Notification delivery failed.",
            configured_targets=configured_targets,
            invalid_targets=invalid_targets,
            error="delivery_failed",
        )

    if not success:
        return NotificationResult(
            success=False,
            message="Notification delivery was not accepted by any configured target.",
            configured_targets=configured_targets,
            invalid_targets=invalid_targets,
            error="not_delivered",
        )

    return NotificationResult(
        success=True,
        message="Notification sent.",
        configured_targets=configured_targets,
        invalid_targets=invalid_targets,
    )
