import hashlib
import json
from datetime import datetime, timezone
from email import message_from_bytes
from email.message import Message
from email.parser import Parser
from email.utils import getaddresses, parsedate_to_datetime
from typing import Any, Dict, Optional

from app.services.forensic_redaction import (
    ForensicRedactionPolicy,
    normalize_forensic_redaction_policy,
    redact_forensic_text,
)

MAX_FORENSIC_REPORT_SIZE = 10 * 1024 * 1024


def _coerce_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return str(value)


def _clean(
    value: Any,
    *,
    redact: bool = True,
    redaction_policy: Optional[ForensicRedactionPolicy] = None,
) -> str:
    text = " ".join(_coerce_text(value).replace("\r", " ").replace("\n", " ").split())
    return redact_text(text, redaction_policy=redaction_policy) if redact else text


def redact_text(
    value: str,
    *,
    redaction_policy: Optional[ForensicRedactionPolicy] = None,
) -> str:
    """Redact email local-parts and long opaque tokens from forensic metadata."""
    return redact_forensic_text(value, redaction_policy)


def _header(
    msg: Optional[Message],
    name: str,
    *,
    redact: bool = True,
    redaction_policy: Optional[ForensicRedactionPolicy] = None,
) -> str:
    return _clean(
        msg.get(name, "") if msg is not None else "",
        redact=redact,
        redaction_policy=redaction_policy,
    )


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
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc)
    return parsed.replace(tzinfo=None)


def _message_id_hash(value: str) -> str:
    cleaned = _clean(value, redact=False)
    if not cleaned:
        return ""
    return hashlib.sha256(cleaned.encode("utf-8")).hexdigest()[:24]


def _feedback_detail_headers(
    feedback: Message,
    *,
    redaction_policy: Optional[ForensicRedactionPolicy] = None,
) -> Dict[str, Any]:
    """Return RFC 9991 ARF metadata without retaining message body content."""
    details = {
        "identity_alignment": _header(feedback, "Identity-Alignment", redact=False),
        "dkim_domain": _header(feedback, "DKIM-Domain", redact=False),
        "dkim_identity": _header(
            feedback,
            "DKIM-Identity",
            redaction_policy=redaction_policy,
        ),
        "dkim_selector": _header(feedback, "DKIM-Selector", redact=False),
        "spf_dns": _header(feedback, "SPF-DNS", redact=False),
        "reported_uri": _header(
            feedback,
            "Reported-URI",
            redaction_policy=redaction_policy,
        ),
    }

    if _header(feedback, "DKIM-Canonicalized-Header", redact=False):
        details["dkim_canonicalized_header_present"] = True
    if _header(feedback, "DKIM-Canonicalized-Body", redact=False):
        details["dkim_canonicalized_body_present"] = True

    return {key: value for key, value in details.items() if value}


def _arc_detail_headers(
    original_headers: Optional[Message],
    *,
    redaction_policy: Optional[ForensicRedactionPolicy] = None,
) -> Dict[str, Any]:
    """Return passive ARC metadata without treating ARC as DMARC evidence."""
    if original_headers is None:
        return {}

    seal_headers = original_headers.get_all("ARC-Seal", [])
    signature_headers = original_headers.get_all("ARC-Message-Signature", [])
    auth_headers = original_headers.get_all("ARC-Authentication-Results", [])
    details: Dict[str, Any] = {}
    if seal_headers:
        details["arc_seal_present"] = True
        details["arc_set_count"] = len(seal_headers)
    if signature_headers:
        details["arc_message_signature_present"] = True
    if auth_headers:
        details["arc_authentication_results_present"] = True
        details["arc_authentication_results"] = _clean(
            auth_headers[-1],
            redaction_policy=redaction_policy,
        )
    return details


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
        cls,
        content: bytes,
        *,
        message_id_hint: Optional[str] = None,
        redaction_policy: Optional[ForensicRedactionPolicy] = None,
    ) -> Dict[str, Any]:
        if len(content) > MAX_FORENSIC_REPORT_SIZE:
            raise ValueError("Forensic report is too large")
        if not content:
            raise ValueError("Forensic report is empty")

        msg = message_from_bytes(content)
        if not cls.is_forensic_report(msg):
            raise ValueError("Email is not a DMARC forensic report")

        redaction_policy = normalize_forensic_redaction_policy(redaction_policy)
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

        source_email = _header(msg, "From", redaction_policy=redaction_policy)
        arrival_date = _parse_datetime(_header(feedback, "Arrival-Date", redact=False))

        details = _feedback_detail_headers(feedback, redaction_policy=redaction_policy)
        details.update(_arc_detail_headers(original_headers, redaction_policy=redaction_policy))

        return {
            "report_id": report_id,
            "source_email": source_email,
            "feedback_type": _header(feedback, "Feedback-Type", redact=False) or "auth-failure",
            "user_agent": _header(feedback, "User-Agent", redaction_policy=redaction_policy),
            "version": _header(feedback, "Version", redact=False),
            "reported_domain": reported_domain,
            "source_ip": source_ip,
            "auth_failure": auth_failure,
            "delivery_result": _header(feedback, "Delivery-Result", redact=False),
            "arrival_date": arrival_date,
            "authentication_results": _header(
                feedback,
                "Authentication-Results",
                redaction_policy=redaction_policy,
            ),
            "original_mail_from": _header(
                feedback,
                "Original-Mail-From",
                redaction_policy=redaction_policy,
            ),
            "original_from": _header(
                original_headers,
                "From",
                redaction_policy=redaction_policy,
            ),
            "original_to": _header(original_headers, "To", redaction_policy=redaction_policy),
            "original_subject": _header(
                original_headers,
                "Subject",
                redaction_policy=redaction_policy,
            ),
            "original_message_id": _message_id_hash(original_message_id),
            "original_date": _header(original_headers, "Date", redact=False),
            "feedback_headers": json.dumps(details, sort_keys=True) if details else None,
        }
