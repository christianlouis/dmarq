import hashlib
import json
import re
from datetime import datetime
from email import message_from_bytes
from email.message import Message
from email.parser import Parser
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any, Dict, Optional


MAX_FORENSIC_REPORT_SIZE = 10 * 1024 * 1024

_EMAIL_RE = re.compile(r"\b([A-Z0-9._%+-]{1,64})@([A-Z0-9.-]+\.[A-Z]{2,})\b", re.IGNORECASE)
_LONG_TOKEN_RE = re.compile(r"\b[A-Za-z0-9_./+=-]{28,}\b")


def _coerce_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _clean(value: Any, *, redact: bool = True) -> str:
    text = " ".join(_coerce_text(value).replace("\r", " ").replace("\n", " ").split())
    return redact_text(text) if redact else text


def redact_text(value: str) -> str:
    """Redact email local-parts and long opaque tokens from forensic metadata."""

    def _redact_email(match: re.Match[str]) -> str:
        local = match.group(1)
        domain = match.group(2)
        prefix = local[:2] if len(local) > 2 else local[:1]
        return f"{prefix}***@{domain.lower()}"

    redacted = _EMAIL_RE.sub(_redact_email, value)
    return _LONG_TOKEN_RE.sub("[redacted-token]", redacted)


def _header(msg: Optional[Message], name: str, *, redact: bool = True) -> str:
    return _clean(msg.get(name, "") if msg is not None else "", redact=redact)


def _payload_text(part: Message) -> str:
    payload = part.get_payload(decode=True)
    if payload is not None:
        charset = part.get_content_charset() or "utf-8"
        return payload.decode(charset, errors="replace")
    payload_value = part.get_payload()
    if isinstance(payload_value, list):
        return ""
    return _coerce_text(payload_value)


def _message_part_payload(part: Message) -> Optional[Message]:
    payload = part.get_payload()
    if isinstance(payload, list) and payload:
        return payload[0]
    return None


def _parse_feedback_headers(text: str) -> Message:
    return Parser().parsestr(text or "")


def _domain_from_address(value: str) -> str:
    addresses = getaddresses([value])
    for _, addr in addresses:
        if "@" in addr:
            return addr.rsplit("@", 1)[-1].lower()
    return ""


def _parse_datetime(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, IndexError):
        return None
    if parsed is None:
        return None
    return parsed.replace(tzinfo=None)


def _message_id_hash(value: str) -> str:
    cleaned = _clean(value, redact=False)
    if not cleaned:
        return ""
    return hashlib.sha256(cleaned.encode("utf-8")).hexdigest()[:24]


class ForensicParser:
    """Parse DMARC forensic/failure report emails without retaining message bodies."""

    @staticmethod
    def is_forensic_report(msg: Message) -> bool:
        if msg.get_content_type() == "multipart/report":
            report_type = (msg.get_param("report-type") or "").lower()
            if report_type == "feedback-report":
                return True

        for part in msg.walk():
            content_type = part.get_content_type().lower()
            if content_type == "message/feedback-report":
                return True
            if content_type == "text/rfc822-headers" and "dmarc" in _payload_text(part).lower():
                return True

        subject = _header(msg, "Subject", redact=False).lower()
        return "dmarc" in subject and any(
            term in subject for term in ("failure", "forensic", "ruf")
        )

    @classmethod
    def parse_bytes(
        cls, content: bytes, *, message_id_hint: Optional[str] = None
    ) -> Dict[str, Any]:
        if len(content) > MAX_FORENSIC_REPORT_SIZE:
            raise ValueError("Forensic report is too large")
        if not content:
            raise ValueError("Forensic report is empty")

        msg = message_from_bytes(content)
        if not cls.is_forensic_report(msg):
            raise ValueError("Email is not a DMARC forensic report")

        feedback = None
        original_headers = None

        for part in msg.walk():
            content_type = part.get_content_type().lower()
            if content_type == "message/feedback-report":
                feedback = _message_part_payload(part) or _parse_feedback_headers(
                    _payload_text(part)
                )
            elif content_type == "text/rfc822-headers":
                original_headers = _parse_feedback_headers(_payload_text(part))
            elif content_type == "message/rfc822" and original_headers is None:
                original_headers = _message_part_payload(part)

        feedback = feedback or msg
        reported_domain = (
            _header(feedback, "Reported-Domain", redact=False)
            or _header(feedback, "DKIM-Domain", redact=False)
            or _domain_from_address(_header(feedback, "Original-Mail-From", redact=False))
            or _domain_from_address(_header(original_headers, "From", redact=False))
        ).lower()
        source_ip = _header(feedback, "Source-IP", redact=False)
        auth_failure = _header(feedback, "Auth-Failure", redact=False)
        original_message_id = _header(original_headers, "Message-ID", redact=False)
        top_message_id = _header(msg, "Message-ID", redact=False)

        report_id = (
            _clean(message_id_hint, redact=False)
            or _message_id_hash(top_message_id)
            or _message_id_hash(original_message_id)
            or hashlib.sha256(content).hexdigest()[:24]
        )
        if not report_id.startswith("ruf-"):
            report_id = f"ruf-{report_id}"

        source_email = _header(msg, "From")
        arrival_date = _parse_datetime(_header(feedback, "Arrival-Date", redact=False))

        details = {
            "identity_alignment": _header(feedback, "Identity-Alignment", redact=False),
            "dkim_domain": _header(feedback, "DKIM-Domain", redact=False),
            "spf_dns": _header(feedback, "SPF-DNS", redact=False),
            "reported_uri": _header(feedback, "Reported-URI"),
        }
        details = {key: value for key, value in details.items() if value}

        return {
            "report_id": report_id,
            "source_email": source_email,
            "feedback_type": _header(feedback, "Feedback-Type", redact=False) or "auth-failure",
            "user_agent": _header(feedback, "User-Agent"),
            "version": _header(feedback, "Version", redact=False),
            "reported_domain": reported_domain,
            "source_ip": source_ip,
            "auth_failure": auth_failure,
            "delivery_result": _header(feedback, "Delivery-Result", redact=False),
            "arrival_date": arrival_date,
            "authentication_results": _header(feedback, "Authentication-Results"),
            "original_mail_from": _header(feedback, "Original-Mail-From"),
            "original_from": _header(original_headers, "From"),
            "original_to": _header(original_headers, "To"),
            "original_subject": _header(original_headers, "Subject"),
            "original_message_id": _message_id_hash(original_message_id),
            "original_date": _header(original_headers, "Date", redact=False),
            "feedback_headers": json.dumps(details, sort_keys=True) if details else None,
        }
