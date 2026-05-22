"""Notification delivery helpers backed by Apprise."""

from __future__ import annotations

import logging
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Tuple

import apprise
from sqlalchemy.orm import Session

from app.core.credential_encryption import decrypt_secret
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
    rate_limited: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, object]:
        return asdict(self)


def _truthy(value: Optional[str], default: bool = False) -> bool:
    if value in (None, ""):
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


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


def _decrypted_setting(settings: Dict[str, Optional[str]], key: str) -> Optional[str]:
    try:
        return decrypt_secret(settings.get(key))
    except ValueError:
        logger.exception("Encrypted notification setting could not be decrypted: %s", key)
        return None


def _int_setting(value: Optional[str], default: int) -> int:
    try:
        return int(value or default)
    except (TypeError, ValueError):
        return default


def _parse_timestamp(value: Optional[str]) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _set_notification_setting(db: Session, key: str, value: str) -> None:
    row = db.query(Setting).filter(Setting.key == key).first()
    if row is None:
        row = Setting(
            key=key,
            value=value,
            value_type="string",
            category="notifications",
        )
        db.add(row)
    else:
        row.value = value


def _rate_limit_result(settings: Dict[str, Optional[str]]) -> Optional[NotificationResult]:
    interval_minutes = max(
        0, _int_setting(settings.get("notifications.min_send_interval_minutes"), 15)
    )
    if interval_minutes <= 0:
        return None

    last_sent_at = _parse_timestamp(settings.get("notifications.last_sent_at"))
    if last_sent_at is None:
        return None

    next_allowed = last_sent_at + timedelta(minutes=interval_minutes)
    now = datetime.now(timezone.utc)
    if now >= next_allowed:
        return None

    retry_after = max(1, int((next_allowed - now).total_seconds() // 60) + 1)
    return NotificationResult(
        success=False,
        skipped=True,
        rate_limited=True,
        message=f"Notification rate limit active. Try again in about {retry_after} minute(s).",
        error="rate_limited",
    )


_EMAIL_LOCAL_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._%+-"
)
_EMAIL_DOMAIN_CHARS = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.-")
_EMAIL_LEADING_PUNCTUATION = frozenset("\"'(<[{")
_EMAIL_TRAILING_PUNCTUATION = frozenset("\"'.,;:!?)]}>")


def _redact_email_token(token: str) -> str:
    leading = ""
    trailing = ""
    core = token

    while core and core[0] in _EMAIL_LEADING_PUNCTUATION:
        leading += core[0]
        core = core[1:]
    while core and core[-1] in _EMAIL_TRAILING_PUNCTUATION:
        trailing = core[-1] + trailing
        core = core[:-1]

    if core.count("@") != 1:
        return token

    local_part, domain_part = core.split("@", 1)
    domain_labels = domain_part.split(".")
    if (
        not local_part
        or not domain_part
        or len(domain_labels) < 2
        or len(domain_labels[-1]) < 2
        or not domain_labels[-1].isalpha()
        or any(not label for label in domain_labels)
        or any(char not in _EMAIL_LOCAL_CHARS for char in local_part)
        or any(char not in _EMAIL_DOMAIN_CHARS for char in domain_part)
    ):
        return token

    return f"{leading}[redacted-email]@{domain_part}{trailing}"


def redact_notification_text(value: str) -> str:
    """Remove common PII from outbound notification text."""
    redacted = []
    token = []
    for char in value:
        if char.isspace():
            if token:
                redacted.append(_redact_email_token("".join(token)))
                token = []
            redacted.append(char)
        else:
            token.append(char)
    if token:
        redacted.append(_redact_email_token("".join(token)))
    return "".join(redacted)


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

    rate_limit = None if force else _rate_limit_result(settings)
    if rate_limit:
        return rate_limit

    urls = _split_apprise_urls(_decrypted_setting(settings, "notifications.apprise_urls"))
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
        if _truthy(settings.get("notifications.redact_pii_enabled"), default=True):
            title = redact_notification_text(title)
            body = redact_notification_text(body)
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

    _set_notification_setting(
        db,
        "notifications.last_sent_at",
        datetime.now(timezone.utc).isoformat(),
    )
    db.commit()

    return NotificationResult(
        success=True,
        message="Notification sent.",
        configured_targets=configured_targets,
        invalid_targets=invalid_targets,
    )
