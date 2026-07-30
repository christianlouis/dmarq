"""Normalize and persist privacy-minimized delivery evidence."""

from __future__ import annotations

import hashlib
import hmac
import json
from datetime import datetime, timedelta, timezone
from email.utils import getaddresses
from typing import Any, Dict, Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.delivery_event import DeliveryEvent
from app.models.workspace import Workspace
from app.services.dsn_parser import parse_dsn_bytes
from app.services.mail_signals import build_delivery_event_signal
from app.services.notifications import redact_notification_text
from app.services.workspaces import get_or_create_default_workspace

NORMALIZED_EVENTS = {
    "accepted",
    "queued",
    "delivered",
    "deferred",
    "bounced",
    "blocked",
    "dropped",
    "spam_complaint",
    "unsubscribe",
    "unknown",
}


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def _hash(workspace_id: int, value: Optional[str]) -> Optional[str]:
    clean = str(value or "").strip()
    if not clean:
        return None
    key = f"{get_settings().SECRET_KEY}:delivery-event:{workspace_id}".encode("utf-8")
    return hmac.new(key, clean.encode("utf-8"), hashlib.sha256).hexdigest()


def _address_parts(value: Optional[str]) -> tuple[Optional[str], Optional[str]]:
    addresses = getaddresses([str(value or "")])
    address = (addresses[0][1] if addresses else str(value or "")).strip().lower()
    if not address or "@" not in address:
        return (None, None)
    return address, address.rsplit("@", 1)[-1].rstrip(".")[:255]


def _sanitize(value: Optional[str], limit: int = 1200) -> Optional[str]:
    if not value:
        return None
    return (
        redact_notification_text(" ".join(str(value).replace("\x00", "").split()))[:limit] or None
    )


def classify_delivery_cause(status_code: Optional[str], diagnostic_text: Optional[str]) -> str:
    """Map status evidence conservatively while retaining the original code."""
    code = str(status_code or "").strip().lower()
    text = str(diagnostic_text or "").lower()
    if any(term in text for term in ("spf", "dkim", "dmarc", "authentication", "policy rejection")):
        return "authentication_policy_rejection"
    if code.startswith(("5.1.", "4.1.")) or any(
        term in text for term in ("user unknown", "recipient unknown", "no such user")
    ):
        return "recipient_user_unknown"
    if code.startswith(("5.2.", "4.2.")) or any(
        term in text for term in ("mailbox full", "quota exceeded", "over quota")
    ):
        return "mailbox_quota"
    if any(term in text for term in ("rate limit", "throttl", "too many messages")):
        return "rate_limiting"
    if code.startswith(("5.7.", "4.7.")) or any(
        term in text for term in ("spam", "reputation", "blacklist", "blocked")
    ):
        return "reputation_spam_policy"
    if code.startswith(("5.4.", "4.4.")) or any(
        term in text for term in ("dns", "tls", "connection timed out", "host not found")
    ):
        return "transport_tls_dns"
    if any(term in text for term in ("content", "attachment", "message size")):
        return "content_attachment_policy"
    if any(term in text for term in ("suppressed", "account disabled", "provider")):
        return "provider_account_suppression"
    if code.startswith("4."):
        return "temporary_remote_error"
    return "unknown_other"


def _normalized_dsn_action(action: str) -> str:
    return {
        "failed": "bounced",
        "delayed": "deferred",
        "delivered": "delivered",
        "relayed": "accepted",
        "expanded": "accepted",
    }.get(action, "unknown")


def _retention_until(workspace: Workspace, received_at: datetime) -> datetime:
    days = max(1, min(int(workspace.delivery_event_retention_days or 30), 400))
    return received_at + timedelta(days=days)


def _event_to_dict(row: DeliveryEvent) -> Dict[str, Any]:
    try:
        signal = json.loads(row.signal_json)
    except (TypeError, ValueError, json.JSONDecodeError):
        signal = {}
    return {
        "id": row.id,
        "workspace_id": row.workspace_id,
        "domain": row.domain,
        "source_system": row.source_system,
        "provider": row.provider,
        "event_id": row.event_id,
        "normalized_event": row.normalized_event,
        "original_event": row.original_event,
        "action": row.action,
        "status_code": row.status_code,
        "diagnostic_type": row.diagnostic_type,
        "diagnostic_text": row.diagnostic_text,
        "cause_family": row.cause_family,
        "recipient_domain": row.recipient_domain,
        "recipient_hash": row.recipient_hash,
        "reporting_mta": row.reporting_mta,
        "remote_mta": row.remote_mta,
        "occurred_at": row.occurred_at.isoformat(),
        "received_at": row.received_at.isoformat(),
        "retention_until": row.retention_until.isoformat(),
        "correlation_confidence": row.correlation_confidence,
        "correlation_reasons": json.loads(row.correlation_reasons or "[]"),
        "provider_semantics": row.provider_semantics,
        "signal": signal,
    }


def _delivery_event_for_key(
    db: Session,
    *,
    workspace_id: int,
    source_system: str,
    provider: str,
    event_id: str,
) -> Optional[DeliveryEvent]:
    return (
        db.query(DeliveryEvent)
        .filter(
            DeliveryEvent.workspace_id == workspace_id,
            DeliveryEvent.source_system == source_system,
            DeliveryEvent.provider == provider,
            DeliveryEvent.event_id == event_id,
        )
        .one_or_none()
    )


def _persist(
    db: Session,
    *,
    workspace: Workspace,
    source_system: str,
    provider: str,
    event_id: str,
    normalized_event: str,
    original_event: Optional[str],
    domain: Optional[str],
    recipient: Optional[str],
    message_id: Optional[str],
    envelope_id: Optional[str],
    action: Optional[str],
    status_code: Optional[str],
    diagnostic_type: Optional[str],
    diagnostic_text: Optional[str],
    reporting_mta: Optional[str],
    remote_mta: Optional[str],
    occurred_at: datetime,
    provider_semantics: Optional[str],
    sanitized_payload: Optional[Dict[str, Any]],
) -> tuple[DeliveryEvent, bool]:
    existing = _delivery_event_for_key(
        db,
        workspace_id=workspace.id,
        source_system=source_system,
        provider=provider,
        event_id=event_id,
    )
    if existing is not None:
        return existing, False
    received_at = datetime.utcnow()
    recipient_address, recipient_domain = _address_parts(recipient)
    clean_diagnostic = _sanitize(diagnostic_text)
    clean_domain = str(domain or "").strip().lower().rstrip(".")[:255] or None
    cause = classify_delivery_cause(status_code, clean_diagnostic)
    confidence_reasons = []
    if clean_domain:
        confidence_reasons.append("An explicit or original-message sender domain is available.")
    if message_id or envelope_id:
        confidence_reasons.append(
            "A stable message or envelope correlation identifier is available."
        )
    confidence = (
        "high" if len(confidence_reasons) == 2 else "medium" if confidence_reasons else "low"
    )
    row = DeliveryEvent(
        workspace_id=workspace.id,
        domain=clean_domain,
        source_system=source_system[:64],
        provider=(provider or "smtp")[:80],
        event_id=event_id[:160],
        normalized_event=normalized_event,
        original_event=_sanitize(original_event, 120),
        action=_sanitize(action, 32),
        status_code=_sanitize(status_code, 32),
        diagnostic_type=_sanitize(diagnostic_type, 80),
        diagnostic_text=clean_diagnostic,
        cause_family=cause,
        recipient_domain=recipient_domain,
        recipient_hash=_hash(workspace.id, recipient_address),
        message_id_hash=_hash(workspace.id, message_id),
        envelope_id_hash=_hash(workspace.id, envelope_id),
        reporting_mta=_sanitize(reporting_mta, 255),
        remote_mta=_sanitize(remote_mta, 255),
        occurred_at=occurred_at,
        received_at=received_at,
        retention_until=_retention_until(workspace, received_at),
        correlation_confidence=confidence,
        correlation_reasons=_json(confidence_reasons),
        provider_semantics=_sanitize(provider_semantics, 1000),
        signal_json="{}",
        sanitized_payload=_json(sanitized_payload) if sanitized_payload else None,
    )
    try:
        with db.begin_nested():
            db.add(row)
            db.flush()
    except IntegrityError:
        existing = _delivery_event_for_key(
            db,
            workspace_id=workspace.id,
            source_system=source_system,
            provider=provider,
            event_id=event_id,
        )
        if existing is None:
            raise
        return existing, False
    signal = build_delivery_event_signal(row)
    row.signal_json = _json(signal)
    return row, True


def ingest_dsn_email(
    db: Session,
    raw_email: bytes,
    *,
    workspace_id: Optional[int],
    source_system: str,
    source_event_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Persist normalized recipient outcomes from one RFC DSN message."""
    workspace = (
        db.query(Workspace).filter(Workspace.id == workspace_id).one()
        if workspace_id is not None
        else get_or_create_default_workspace(db, commit=False)
    )
    parsed = parse_dsn_bytes(raw_email)
    accepted = []
    duplicates = []
    for index, item in enumerate(parsed):
        event_id = item.event_id_seed
        if source_event_id:
            event_id = hashlib.sha256(
                f"{source_event_id}|{index}|{item.event_id_seed}".encode("utf-8")
            ).hexdigest()
        row, created = _persist(
            db,
            workspace=workspace,
            source_system=source_system,
            provider="smtp",
            event_id=event_id,
            normalized_event=_normalized_dsn_action(item.action),
            original_event=item.action,
            domain=item.domain,
            recipient=item.recipient,
            message_id=item.original_message_id,
            envelope_id=item.original_envelope_id,
            action=item.action,
            status_code=item.status_code,
            diagnostic_type=item.diagnostic_type,
            diagnostic_text=item.diagnostic_text,
            reporting_mta=item.reporting_mta,
            remote_mta=item.remote_mta,
            occurred_at=item.occurred_at,
            provider_semantics="RFC delivery-status action and enhanced status semantics.",
            sanitized_payload=None,
        )
        (accepted if created else duplicates).append(_event_to_dict(row))
    db.commit()
    return {"accepted": accepted, "duplicates": duplicates, "events_found": len(parsed)}


def ingest_provider_event(
    db: Session,
    *,
    workspace: Workspace,
    payload: Dict[str, Any],
) -> tuple[Dict[str, Any], bool]:
    """Persist one authenticated, versioned provider event idempotently."""
    normalized_event = str(payload["event"]).strip().lower()
    if normalized_event not in NORMALIZED_EVENTS:
        raise ValueError("Unsupported normalized delivery event.")
    occurred_at = payload["occurred_at"]
    if occurred_at.tzinfo is not None:
        occurred_at = occurred_at.astimezone(timezone.utc).replace(tzinfo=None)
    now = datetime.utcnow()
    if occurred_at > now + timedelta(minutes=5):
        raise ValueError("Provider event timestamp is too far in the future.")
    if occurred_at < now - timedelta(days=7):
        raise ValueError("Provider event timestamp is outside the seven-day replay window.")
    row, created = _persist(
        db,
        workspace=workspace,
        source_system="provider_webhook",
        provider=str(payload["provider"]).strip().lower(),
        event_id=str(payload["event_id"]),
        normalized_event=normalized_event,
        original_event=payload.get("original_event"),
        domain=payload.get("domain"),
        recipient=payload.get("recipient"),
        message_id=payload.get("message_id"),
        envelope_id=payload.get("envelope_id"),
        action=normalized_event,
        status_code=payload.get("status_code"),
        diagnostic_type=payload.get("diagnostic_type"),
        diagnostic_text=payload.get("diagnostic_text"),
        reporting_mta=None,
        remote_mta=payload.get("remote_mta"),
        occurred_at=occurred_at,
        provider_semantics=payload.get("provider_semantics"),
        sanitized_payload={
            "schema_version": payload["schema_version"],
            "reason_code": payload.get("reason_code"),
        },
    )
    db.commit()
    return _event_to_dict(row), created


def list_delivery_events(
    db: Session,
    *,
    workspace: Workspace,
    domain: Optional[str] = None,
    limit: int = 100,
) -> list[Dict[str, Any]]:
    query = db.query(DeliveryEvent).filter(DeliveryEvent.workspace_id == workspace.id)
    if domain:
        query = query.filter(DeliveryEvent.domain == domain.strip().lower().rstrip("."))
    rows = query.order_by(DeliveryEvent.occurred_at.desc(), DeliveryEvent.id.desc()).limit(
        max(1, min(limit, 500))
    )
    return [_event_to_dict(row) for row in rows]


def purge_expired_delivery_events(db: Session, *, now: Optional[datetime] = None) -> int:
    """Delete delivery evidence after its workspace retention boundary."""
    count = (
        db.query(DeliveryEvent)
        .filter(DeliveryEvent.retention_until <= (now or datetime.utcnow()))
        .delete(synchronize_session=False)
    )
    db.commit()
    return int(count or 0)
