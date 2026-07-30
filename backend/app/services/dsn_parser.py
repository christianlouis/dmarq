"""Bounded, body-free parsing of RFC delivery status notifications."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime, timezone
from email import policy
from email.message import Message
from email.parser import BytesParser, HeaderParser
from email.utils import getaddresses, parsedate_to_datetime
from typing import Iterable, Optional

MAX_DSN_BYTES = 5 * 1024 * 1024
MAX_MIME_PARTS = 200
MAX_HEADERS_PER_PART = 500
MAX_RECIPIENT_BLOCKS = 250

DSN_ACTIONS = {"failed", "delayed", "delivered", "relayed", "expanded"}


class DSNParseError(ValueError):
    """Raised when a delivery-status message is malformed or exceeds safe bounds."""


@dataclass(frozen=True)
class ParsedDSNEvent:
    """One privacy-ready per-recipient delivery observation."""

    event_id_seed: str
    domain: Optional[str]
    recipient: Optional[str]
    action: str
    status_code: Optional[str]
    diagnostic_type: Optional[str]
    diagnostic_text: Optional[str]
    reporting_mta: Optional[str]
    remote_mta: Optional[str]
    original_envelope_id: Optional[str]
    original_message_id: Optional[str]
    occurred_at: datetime


def _clean(value: object, limit: int = 1000) -> Optional[str]:
    text = " ".join(str(value or "").replace("\x00", "").split())
    return text[:limit] or None


def _after_semicolon(value: Optional[str]) -> Optional[str]:
    if not value:
        return None
    return _clean(value.split(";", 1)[-1], 500)


def _mailbox(value: Optional[str]) -> Optional[str]:
    candidate = _after_semicolon(value)
    if not candidate:
        return None
    addresses = getaddresses([candidate])
    address = addresses[0][1] if addresses else candidate
    return _clean(address.lower(), 320)


def _domain_from_address(value: Optional[str]) -> Optional[str]:
    address = _mailbox(value)
    if not address or "@" not in address:
        return None
    domain = address.rsplit("@", 1)[-1].strip().lower().rstrip(".")
    try:
        return domain.encode("idna").decode("ascii")[:255] or None
    except UnicodeError:
        return None


def _date(value: Optional[str], fallback: datetime) -> datetime:
    if not value:
        return fallback
    try:
        parsed = parsedate_to_datetime(value)
    except (TypeError, ValueError, OverflowError):
        return fallback
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc).replace(tzinfo=None)
    return parsed


def _walk_bounded(message: Message) -> list[Message]:
    parts = list(message.walk())
    if len(parts) > MAX_MIME_PARTS:
        raise DSNParseError("Delivery status message has too many MIME parts.")
    for part in parts:
        if len(part.items()) > MAX_HEADERS_PER_PART:
            raise DSNParseError("Delivery status message has too many headers.")
    return parts


def _delivery_blocks(part: Message) -> list[Message]:
    payload = part.get_payload()
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, Message)]
    if isinstance(payload, str):
        normalized = payload.replace("\r\n", "\n")
        blocks = []
        for block in normalized.split("\n\n"):
            if not block.strip():
                continue
            blocks.append(HeaderParser(policy=policy.default).parsestr(block))
        return blocks
    return []


def _original_headers(parts: Iterable[Message]) -> Message | None:
    for part in parts:
        if part.get_content_type().lower() not in {"message/rfc822", "text/rfc822-headers"}:
            continue
        payload = part.get_payload()
        if isinstance(payload, list) and payload and isinstance(payload[0], Message):
            return payload[0]
        decoded = part.get_payload(decode=True)
        if decoded:
            return BytesParser(policy=policy.default).parsebytes(decoded, headersonly=True)
        if isinstance(payload, str):
            return HeaderParser(policy=policy.default).parsestr(payload)
    return None


def is_dsn_message(message: Message) -> bool:
    """Return whether *message* contains an RFC delivery-status report."""
    content_type = message.get_content_type().lower()
    report_type = str(message.get_param("report-type") or "").lower()
    if content_type == "multipart/report" and report_type == "delivery-status":
        return True
    return any(
        part.get_content_type().lower() == "message/delivery-status" for part in message.walk()
    )


def parse_dsn_bytes(
    raw_email: bytes, *, received_at: Optional[datetime] = None
) -> list[ParsedDSNEvent]:
    """Parse one DSN without retaining any original body content."""
    if len(raw_email) > MAX_DSN_BYTES:
        raise DSNParseError("Delivery status message exceeds the safe size limit.")
    message = BytesParser(policy=policy.default).parsebytes(raw_email)
    return parse_dsn_message(message, received_at=received_at)


def parse_dsn_message(
    message: Message, *, received_at: Optional[datetime] = None
) -> list[ParsedDSNEvent]:
    """Normalize all recipient blocks from one delivery-status message."""
    if not is_dsn_message(message):
        raise DSNParseError("Message is not a delivery status notification.")
    fallback_time = received_at or datetime.utcnow()
    parts = _walk_bounded(message)
    original = _original_headers(parts)
    original_from = original.get("From") if original is not None else None
    original_message_id = _clean(
        original.get("Message-ID") if original is not None else None,
        500,
    )
    root_message_id = _clean(message.get("Message-ID"), 500)
    events: list[ParsedDSNEvent] = []

    for part in parts:
        if part.get_content_type().lower() != "message/delivery-status":
            continue
        blocks = _delivery_blocks(part)
        if len(blocks) > MAX_RECIPIENT_BLOCKS + 1:
            raise DSNParseError("Delivery status message has too many recipient blocks.")
        message_block = blocks[0] if blocks else None
        reporting_mta = _after_semicolon(
            message_block.get("Reporting-MTA") if message_block is not None else None
        )
        envelope_id = _clean(
            message_block.get("Original-Envelope-ID") if message_block is not None else None,
            500,
        )
        arrival_date = _date(
            message_block.get("Arrival-Date") if message_block is not None else None,
            fallback_time,
        )
        for index, block in enumerate(blocks[1:] or []):
            action = str(block.get("Action") or "unknown").strip().lower()
            if action not in DSN_ACTIONS:
                action = "unknown"
            recipient = _mailbox(block.get("Final-Recipient") or block.get("Original-Recipient"))
            diagnostic = _clean(block.get("Diagnostic-Code"), 1500)
            diagnostic_type = None
            diagnostic_text = diagnostic
            if diagnostic and ";" in diagnostic:
                diagnostic_type, diagnostic_text = diagnostic.split(";", 1)
                diagnostic_type = _clean(diagnostic_type, 80)
                diagnostic_text = _clean(diagnostic_text, 1200)
            occurred_at = _date(
                block.get("Last-Attempt-Date") or block.get("Will-Retry-Until"),
                arrival_date,
            )
            seed = "|".join(
                str(value or "")
                for value in (
                    root_message_id,
                    envelope_id,
                    index,
                    recipient,
                    action,
                    block.get("Status"),
                )
            )
            events.append(
                ParsedDSNEvent(
                    event_id_seed=hashlib.sha256(seed.encode("utf-8")).hexdigest(),
                    domain=_domain_from_address(original_from),
                    recipient=recipient,
                    action=action,
                    status_code=_clean(block.get("Status"), 32),
                    diagnostic_type=diagnostic_type,
                    diagnostic_text=diagnostic_text,
                    reporting_mta=reporting_mta,
                    remote_mta=_after_semicolon(block.get("Remote-MTA")),
                    original_envelope_id=envelope_id,
                    original_message_id=original_message_id,
                    occurred_at=occurred_at,
                )
            )

    if not events:
        raise DSNParseError("Delivery status message contains no recipient status blocks.")
    return events
