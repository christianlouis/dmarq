"""Outbound webhook event creation, signing, and delivery."""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.credential_encryption import decrypt_secret, encrypt_secret, is_encrypted_secret
from app.models.webhook import WebhookDelivery, WebhookEndpoint

EVENT_REPORT_IMPORTED = "dmarq.report.imported"
EVENT_SENDER_NEW = "dmarq.sender.new"
EVENT_COMPLIANCE_DROP = "dmarq.compliance.drop"
EVENT_REPORTS_MISSING = "dmarq.reports.missing"
EVENT_ALERT_CREATED = "dmarq.alert.created"
EVENT_ALERT_RESOLVED = "dmarq.alert.resolved"
EVENT_WEBHOOK_TEST = "dmarq.webhook.test"

SUPPORTED_EVENT_TYPES = [
    EVENT_REPORT_IMPORTED,
    EVENT_SENDER_NEW,
    EVENT_COMPLIANCE_DROP,
    EVENT_REPORTS_MISSING,
    EVENT_ALERT_CREATED,
    EVENT_ALERT_RESOLVED,
    EVENT_WEBHOOK_TEST,
]

DELIVERY_PENDING = "pending"
DELIVERY_DELIVERED = "delivered"
DELIVERY_FAILED = "failed"
DELIVERY_ABANDONED = "abandoned"


@dataclass
class DeliveryAttemptResult:
    """Result returned by a webhook HTTP sender."""

    status_code: int
    body: str = ""


WebhookSender = Callable[[str, bytes, Dict[str, str], int], DeliveryAttemptResult]


def normalize_event_types(event_types: Iterable[str]) -> List[str]:
    """Return validated event types for endpoint storage."""
    cleaned = sorted({item.strip() for item in event_types if item and item.strip()})
    if not cleaned:
        return ["*"]
    if "*" in cleaned:
        return ["*"]
    invalid = [item for item in cleaned if item not in SUPPORTED_EVENT_TYPES]
    if invalid:
        raise ValueError(f"Unsupported webhook event type: {', '.join(invalid)}")
    return cleaned


def event_types_to_string(event_types: Iterable[str]) -> str:
    """Serialize event types for storage."""
    return ",".join(normalize_event_types(event_types))


def parse_event_types(value: str) -> List[str]:
    """Parse stored event types."""
    return normalize_event_types((value or "*").split(","))


def endpoint_matches_event(endpoint: WebhookEndpoint, event_type: str) -> bool:
    """Return True when an endpoint should receive an event."""
    event_types = parse_event_types(endpoint.event_types)
    return "*" in event_types or event_type in event_types


def generate_webhook_secret() -> str:
    """Generate a signing secret for outbound webhook deliveries."""
    return secrets.token_urlsafe(32)


def _encrypt(value: str) -> str:
    return encrypt_secret(value) or ""


def _decrypt(value: str) -> str:
    return decrypt_secret(value) or ""


def _redact_url(url: str) -> str:
    parsed = urlparse(url)
    if not parsed.scheme or not parsed.netloc:
        return "[invalid url]"
    host = parsed.hostname or parsed.netloc
    port = f":{parsed.port}" if parsed.port else ""
    path = parsed.path or "/"
    return f"{parsed.scheme}://{host}{port}{path}"


def validate_webhook_url(url: str) -> str:
    """Validate and normalize an outbound webhook URL."""
    clean_url = url.strip()
    parsed = urlparse(clean_url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("Webhook URL must be an absolute http or https URL")
    return clean_url


def create_webhook_endpoint(
    db: Session,
    *,
    name: str,
    url: str,
    secret: Optional[str] = None,
    event_types: Iterable[str] = ("*",),
    enabled: bool = True,
    max_attempts: int = 5,
    timeout_seconds: int = 10,
) -> Tuple[WebhookEndpoint, str]:
    """Create a webhook endpoint and return the endpoint plus raw signing secret."""
    clean_name = name.strip()
    if not clean_name:
        raise ValueError("Webhook name is required")
    clean_url = validate_webhook_url(url)
    raw_secret = secret.strip() if secret else generate_webhook_secret()
    if len(raw_secret) < 16:
        raise ValueError("Webhook signing secret must be at least 16 characters")

    endpoint = WebhookEndpoint(
        name=clean_name,
        url=_encrypt(clean_url),
        secret=_encrypt(raw_secret),
        event_types=event_types_to_string(event_types),
        enabled=enabled,
        max_attempts=max(1, min(int(max_attempts or 5), 10)),
        timeout_seconds=max(1, min(int(timeout_seconds or 10), 30)),
    )
    db.add(endpoint)
    db.commit()
    db.refresh(endpoint)
    return endpoint, raw_secret


def update_webhook_endpoint(
    db: Session,
    endpoint: WebhookEndpoint,
    *,
    name: Optional[str] = None,
    url: Optional[str] = None,
    secret: Optional[str] = None,
    event_types: Optional[Iterable[str]] = None,
    enabled: Optional[bool] = None,
    max_attempts: Optional[int] = None,
    timeout_seconds: Optional[int] = None,
) -> Tuple[WebhookEndpoint, Optional[str]]:
    """Update a webhook endpoint. Return the endpoint and newly supplied/generated secret."""
    returned_secret = None
    if name is not None:
        clean_name = name.strip()
        if not clean_name:
            raise ValueError("Webhook name is required")
        endpoint.name = clean_name
    if url is not None and url.strip() and url != "**redacted**":
        endpoint.url = _encrypt(validate_webhook_url(url))
    if secret is not None and secret.strip() and secret != "**redacted**":
        returned_secret = secret.strip()
        if len(returned_secret) < 16:
            raise ValueError("Webhook signing secret must be at least 16 characters")
        endpoint.secret = _encrypt(returned_secret)
    if event_types is not None:
        endpoint.event_types = event_types_to_string(event_types)
    if enabled is not None:
        endpoint.enabled = enabled
    if max_attempts is not None:
        endpoint.max_attempts = max(1, min(int(max_attempts), 10))
    if timeout_seconds is not None:
        endpoint.timeout_seconds = max(1, min(int(timeout_seconds), 30))
    db.commit()
    db.refresh(endpoint)
    return endpoint, returned_secret


def _stable_json(value: Dict[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)


def build_event_payload(event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    """Wrap event data in a stable, documented envelope."""
    now = datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
    return {
        "event_type": event_type,
        "created_at": now,
        "data": payload,
    }


def default_idempotency_key(event_type: str, payload: Dict[str, Any]) -> str:
    """Build a deterministic idempotency key for an event payload."""
    digest = hashlib.sha256(_stable_json(payload).encode("utf-8")).hexdigest()[:32]
    return f"{event_type}:{digest}"


def enqueue_webhook_event(
    db: Session,
    *,
    event_type: str,
    payload: Dict[str, Any],
    idempotency_key: Optional[str] = None,
) -> List[WebhookDelivery]:
    """Create pending deliveries for all enabled endpoints matching an event."""
    if event_type not in SUPPORTED_EVENT_TYPES:
        raise ValueError(f"Unsupported webhook event type: {event_type}")
    endpoints = db.query(WebhookEndpoint).filter(WebhookEndpoint.enabled.is_(True)).all()
    event_payload = build_event_payload(event_type, payload)
    key = idempotency_key or default_idempotency_key(event_type, event_payload)
    deliveries: List[WebhookDelivery] = []

    for endpoint in endpoints:
        if not endpoint_matches_event(endpoint, event_type):
            continue
        delivery = WebhookDelivery(
            endpoint_id=endpoint.id,
            event_type=event_type,
            payload=_stable_json(event_payload),
            idempotency_key=key,
            status=DELIVERY_PENDING,
            max_attempts=endpoint.max_attempts,
        )
        db.add(delivery)
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            existing = (
                db.query(WebhookDelivery)
                .filter(
                    WebhookDelivery.endpoint_id == endpoint.id,
                    WebhookDelivery.idempotency_key == key,
                )
                .first()
            )
            if existing:
                deliveries.append(existing)
            continue
        db.refresh(delivery)
        deliveries.append(delivery)
    return deliveries


def _delivery_body(delivery: WebhookDelivery) -> bytes:
    return delivery.payload.encode("utf-8")


def sign_delivery(secret: str, delivery: WebhookDelivery, timestamp: int, body: bytes) -> str:
    """Return the v1 HMAC signature for a delivery."""
    signed = f"{timestamp}.{delivery.id}.".encode("utf-8") + body
    digest = hmac.new(secret.encode("utf-8"), signed, hashlib.sha256).hexdigest()
    return f"v1={digest}"


def build_delivery_headers(endpoint: WebhookEndpoint, delivery: WebhookDelivery) -> Dict[str, str]:
    """Build outbound webhook headers with event metadata and HMAC signature."""
    body = _delivery_body(delivery)
    timestamp = int(datetime.utcnow().timestamp())
    secret = _decrypt(endpoint.secret)
    return {
        "Content-Type": "application/json",
        "User-Agent": "DMARQ-Webhooks/1.0",
        "X-DMARQ-Event": delivery.event_type,
        "X-DMARQ-Delivery": str(delivery.id),
        "X-DMARQ-Idempotency-Key": delivery.idempotency_key,
        "X-DMARQ-Timestamp": str(timestamp),
        "X-DMARQ-Signature": sign_delivery(secret, delivery, timestamp, body),
    }


def default_webhook_sender(
    url: str, body: bytes, headers: Dict[str, str], timeout_seconds: int
) -> DeliveryAttemptResult:
    """Send a webhook delivery using the Python standard library."""
    request = urllib.request.Request(url=url, data=body, headers=headers, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=timeout_seconds) as response:  # nosec B310
            response_body = response.read(4096).decode("utf-8", errors="replace")
            return DeliveryAttemptResult(status_code=response.status, body=response_body)
    except urllib.error.HTTPError as exc:
        response_body = exc.read(4096).decode("utf-8", errors="replace")
        return DeliveryAttemptResult(status_code=exc.code, body=response_body)
    except urllib.error.URLError as exc:
        raise ConnectionError(str(exc.reason)) from exc


def _backoff_for_attempt(attempt_count: int) -> timedelta:
    seconds = min(3600, 60 * (2 ** max(0, attempt_count - 1)))
    return timedelta(seconds=seconds)


def _response_excerpt(value: str) -> str:
    return (value or "")[:500]


def deliver_webhook_delivery(
    db: Session,
    delivery: WebhookDelivery,
    *,
    sender: WebhookSender = default_webhook_sender,
) -> WebhookDelivery:
    """Attempt one webhook delivery and persist retry state."""
    endpoint = db.query(WebhookEndpoint).filter(WebhookEndpoint.id == delivery.endpoint_id).first()
    now = datetime.utcnow()
    delivery.attempt_count = int(delivery.attempt_count or 0) + 1
    delivery.last_attempt_at = now

    if endpoint is None or not endpoint.enabled:
        delivery.status = DELIVERY_ABANDONED
        delivery.last_error = "Webhook endpoint is disabled or missing."
        delivery.next_attempt_at = now
        db.commit()
        db.refresh(delivery)
        return delivery

    try:
        body = _delivery_body(delivery)
        result = sender(
            _decrypt(endpoint.url),
            body,
            build_delivery_headers(endpoint, delivery),
            endpoint.timeout_seconds,
        )
        delivery.last_status_code = result.status_code
        delivery.response_excerpt = _response_excerpt(result.body)
        if 200 <= result.status_code < 300:
            delivery.status = DELIVERY_DELIVERED
            delivery.delivered_at = now
            delivery.last_error = None
            delivery.next_attempt_at = now
            endpoint.last_success_at = now
            endpoint.failure_count = 0
        else:
            delivery.last_error = f"HTTP {result.status_code}"
            _mark_delivery_failure(delivery, endpoint, now)
    except Exception as exc:  # pylint: disable=broad-exception-caught
        delivery.last_error = str(exc)[:500]
        _mark_delivery_failure(delivery, endpoint, now)

    db.commit()
    db.refresh(delivery)
    return delivery


def _mark_delivery_failure(
    delivery: WebhookDelivery, endpoint: WebhookEndpoint, now: datetime
) -> None:
    endpoint.last_failure_at = now
    endpoint.failure_count = int(endpoint.failure_count or 0) + 1
    if delivery.attempt_count >= delivery.max_attempts:
        delivery.status = DELIVERY_FAILED
        delivery.next_attempt_at = now
        return
    delivery.status = DELIVERY_PENDING
    delivery.next_attempt_at = now + _backoff_for_attempt(delivery.attempt_count)


def deliver_due_webhooks(
    db: Session,
    *,
    limit: int = 25,
    endpoint_id: Optional[int] = None,
    sender: WebhookSender = default_webhook_sender,
) -> List[WebhookDelivery]:
    """Deliver pending webhook deliveries whose retry time has arrived."""
    now = datetime.utcnow()
    query = db.query(WebhookDelivery).filter(
        WebhookDelivery.status == DELIVERY_PENDING,
        WebhookDelivery.next_attempt_at <= now,
    )
    if endpoint_id is not None:
        query = query.filter(WebhookDelivery.endpoint_id == endpoint_id)
    deliveries = (
        query.order_by(WebhookDelivery.next_attempt_at, WebhookDelivery.id).limit(limit).all()
    )
    return [deliver_webhook_delivery(db, delivery, sender=sender) for delivery in deliveries]


def queue_test_webhook(db: Session, endpoint_id: int) -> WebhookDelivery:
    """Queue a one-off test delivery for a specific webhook endpoint."""
    endpoint = db.query(WebhookEndpoint).filter(WebhookEndpoint.id == endpoint_id).first()
    if endpoint is None:
        raise ValueError("Webhook endpoint not found")
    payload = {
        "endpoint_id": endpoint.id,
        "endpoint_name": endpoint.name,
        "message": "DMARQ webhook test delivery",
    }
    delivery = WebhookDelivery(
        endpoint_id=endpoint.id,
        event_type=EVENT_WEBHOOK_TEST,
        payload=_stable_json(build_event_payload(EVENT_WEBHOOK_TEST, payload)),
        idempotency_key=f"{EVENT_WEBHOOK_TEST}:{secrets.token_hex(16)}",
        status=DELIVERY_PENDING,
        max_attempts=endpoint.max_attempts,
    )
    db.add(delivery)
    db.commit()
    db.refresh(delivery)
    return delivery


def endpoint_to_dict(endpoint: WebhookEndpoint) -> Dict[str, Any]:
    """Return an API-safe webhook endpoint representation."""
    raw_url = _decrypt(endpoint.url)
    return {
        "id": endpoint.id,
        "name": endpoint.name,
        "url": _redact_url(raw_url),
        "event_types": parse_event_types(endpoint.event_types),
        "enabled": endpoint.enabled,
        "max_attempts": endpoint.max_attempts,
        "timeout_seconds": endpoint.timeout_seconds,
        "created_at": endpoint.created_at.isoformat() if endpoint.created_at else None,
        "updated_at": endpoint.updated_at.isoformat() if endpoint.updated_at else None,
        "last_success_at": (
            endpoint.last_success_at.isoformat() if endpoint.last_success_at else None
        ),
        "last_failure_at": (
            endpoint.last_failure_at.isoformat() if endpoint.last_failure_at else None
        ),
        "failure_count": endpoint.failure_count,
        "secret_configured": bool(endpoint.secret),
        "url_encrypted": is_encrypted_secret(endpoint.url),
    }


def delivery_to_dict(delivery: WebhookDelivery) -> Dict[str, Any]:
    """Return an API-safe delivery representation."""
    return {
        "id": delivery.id,
        "endpoint_id": delivery.endpoint_id,
        "event_type": delivery.event_type,
        "idempotency_key": delivery.idempotency_key,
        "status": delivery.status,
        "attempt_count": delivery.attempt_count,
        "max_attempts": delivery.max_attempts,
        "next_attempt_at": (
            delivery.next_attempt_at.isoformat() if delivery.next_attempt_at else None
        ),
        "last_attempt_at": (
            delivery.last_attempt_at.isoformat() if delivery.last_attempt_at else None
        ),
        "delivered_at": delivery.delivered_at.isoformat() if delivery.delivered_at else None,
        "last_status_code": delivery.last_status_code,
        "last_error": delivery.last_error,
        "response_excerpt": delivery.response_excerpt,
        "created_at": delivery.created_at.isoformat() if delivery.created_at else None,
        "updated_at": delivery.updated_at.isoformat() if delivery.updated_at else None,
    }
