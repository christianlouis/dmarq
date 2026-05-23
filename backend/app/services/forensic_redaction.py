import re
from dataclasses import dataclass
from typing import Any, Optional

from sqlalchemy.orm import Session

from app.models.setting import Setting


FORENSIC_REDACTION_MODE_KEY = "forensics.redaction_mode"
FORENSIC_REDACT_LONG_TOKENS_KEY = "forensics.redact_long_tokens_enabled"
DEFAULT_FORENSIC_REDACTION_MODE = "balanced"
FORENSIC_REDACTION_MODES = {"balanced", "domain_only", "strict"}

_EMAIL_RE = re.compile(
    r"\b([A-Z0-9._%+\-*]{1,64})@([A-Z0-9.-]+\.[A-Z]{2,})\b",
    re.IGNORECASE,
)
_LONG_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_./+=-]{28,}\b")


@dataclass(frozen=True)
class ForensicRedactionPolicy:
    """Privacy policy for forensic report metadata."""

    mode: str = DEFAULT_FORENSIC_REDACTION_MODE
    redact_long_tokens: bool = True


def _truthy(value: Optional[str], *, default: bool = True) -> bool:
    if value is None:
        return default
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def normalize_forensic_redaction_policy(
    policy: Optional[ForensicRedactionPolicy] = None,
    *,
    mode: Optional[str] = None,
    redact_long_tokens: Optional[bool] = None,
) -> ForensicRedactionPolicy:
    requested_mode = (mode if mode is not None else policy.mode if policy else "").strip().lower()
    if requested_mode not in FORENSIC_REDACTION_MODES:
        requested_mode = DEFAULT_FORENSIC_REDACTION_MODE
    return ForensicRedactionPolicy(
        mode=requested_mode,
        redact_long_tokens=(
            policy.redact_long_tokens
            if redact_long_tokens is None and policy is not None
            else bool(True if redact_long_tokens is None else redact_long_tokens)
        ),
    )


def get_forensic_redaction_policy(db: Optional[Session]) -> ForensicRedactionPolicy:
    """Load the current forensic redaction policy from persisted settings."""
    if db is None:
        return ForensicRedactionPolicy()

    rows = (
        db.query(Setting.key, Setting.value)
        .filter(Setting.key.in_([FORENSIC_REDACTION_MODE_KEY, FORENSIC_REDACT_LONG_TOKENS_KEY]))
        .all()
    )
    values = {key: value for key, value in rows}
    return normalize_forensic_redaction_policy(
        mode=values.get(FORENSIC_REDACTION_MODE_KEY),
        redact_long_tokens=_truthy(values.get(FORENSIC_REDACT_LONG_TOKENS_KEY), default=True),
    )


def redact_forensic_text(
    value: str,
    policy: Optional[ForensicRedactionPolicy] = None,
) -> str:
    """Redact forensic metadata according to the selected privacy policy."""
    policy = normalize_forensic_redaction_policy(policy)

    def _redact_email(match: re.Match[str]) -> str:
        local = match.group(1)
        domain = match.group(2).lower()
        if policy.mode == "strict":
            return "[redacted-email]"
        if policy.mode == "domain_only":
            return f"***@{domain}"
        prefix = local[:2] if len(local) > 2 else local[:1]
        return f"{prefix}***@{domain}"

    redacted = _EMAIL_RE.sub(_redact_email, value)
    if policy.redact_long_tokens:
        redacted = _LONG_TOKEN_RE.sub("[redacted-token]", redacted)
    return redacted


def redact_forensic_value(
    value: Any,
    policy: Optional[ForensicRedactionPolicy] = None,
) -> Any:
    """Redact strings inside a response value while preserving container shape."""
    if isinstance(value, str):
        return redact_forensic_text(value, policy)
    if isinstance(value, dict):
        return {key: redact_forensic_value(item, policy) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_forensic_value(item, policy) for item in value]
    return value
