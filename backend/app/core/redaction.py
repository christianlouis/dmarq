"""
Utilities for making diagnostic text safe to store or log.
"""

import re

SENSITIVE_VALUE = "**redacted**"

_SENSITIVE_KEY_PATTERN = re.compile(
    r"(?i)([\"']?\b(?:access_token|api_key|apikey|authorization|bearer|client_secret|"
    r"gmail_client_secret|id_token|passwd|password|refresh_token|secret|token)\b[\"']?"
    r"\s*[:=]\s*[\"']?)([^\"'\s,;&}]+)([\"']?)"
)
_BEARER_TOKEN_PATTERN = re.compile(r"(?i)\b(bearer)\s+([A-Za-z0-9._~+/=-]{8,})")


def sanitize_for_log(value: object) -> str:
    """Remove CR/LF characters from a value to prevent log injection attacks."""
    return str(value).replace("\r", "").replace("\n", " ")


def redact_sensitive_text(value: object) -> str:
    """Sanitize text and redact common secret-bearing key/value fragments."""
    text = sanitize_for_log(value)
    text = _SENSITIVE_KEY_PATTERN.sub(r"\1" + SENSITIVE_VALUE + r"\3", text)
    return _BEARER_TOKEN_PATTERN.sub(r"\1 " + SENSITIVE_VALUE, text)
