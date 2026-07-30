"""Privacy, idempotency, and API tests for delivery evidence."""

import json
from datetime import datetime, timedelta

from sqlalchemy.exc import IntegrityError

from app.models.delivery_event import DeliveryEvent
from app.models.workspace import Workspace
from app.services.api_tokens import (
    ALL_API_TOKEN_SCOPES,
    DELIVERY_EVENTS_WRITE_SCOPE,
    create_api_token,
)
from app.services.delivery_events import ingest_dsn_email, ingest_provider_event
from app.services.dsn_parser import DSNParseError, parse_dsn_bytes


def _dsn_bytes() -> bytes:
    return b"""From: MAILER-DAEMON@example.net\r
To: sender@cklnet.com\r
Subject: Delivery Status Notification (Failure)\r
Message-ID: <dsn-1@example.net>\r
MIME-Version: 1.0\r
Content-Type: multipart/report; report-type=delivery-status; boundary=\"dsn\"\r
\r
--dsn\r
Content-Type: text/plain\r
\r
The private message body must not be stored.\r
--dsn\r
Content-Type: message/delivery-status\r
\r
Reporting-MTA: dns; mx.example.net\r
Original-Envelope-ID: envelope-1\r
Arrival-Date: Thu, 30 Jul 2026 10:00:00 +0000\r
\r
Final-Recipient: rfc822; private-person@example.org\r
Action: failed\r
Status: 5.7.26\r
Remote-MTA: dns; mx.remote.net\r
Diagnostic-Code: smtp; 550 5.7.26 DMARC authentication failed\r
Last-Attempt-Date: Thu, 30 Jul 2026 10:01:00 +0000\r
\r
--dsn\r
Content-Type: message/rfc822\r
\r
From: sender@cklnet.com\r
To: private-person@example.org\r
Message-ID: <original-1@cklnet.com>\r
\r
Secret content that must not be persisted.\r
--dsn--\r
"""


def test_dsn_parser_extracts_delivery_semantics_without_body():
    event = parse_dsn_bytes(_dsn_bytes())[0]

    assert event.domain == "cklnet.com"
    assert event.action == "failed"
    assert event.status_code == "5.7.26"
    assert event.remote_mta == "mx.remote.net"
    assert not hasattr(event, "body")


def test_dsn_ingest_is_idempotent_and_privacy_minimized(db_session):
    workspace = Workspace(slug="dsn", name="DSN")
    db_session.add(workspace)
    db_session.commit()

    first = ingest_dsn_email(
        db_session,
        _dsn_bytes(),
        workspace_id=workspace.id,
        source_system="manual_dsn_upload",
    )
    second = ingest_dsn_email(
        db_session,
        _dsn_bytes(),
        workspace_id=workspace.id,
        source_system="manual_dsn_upload",
    )
    row = db_session.query(DeliveryEvent).one()

    assert len(first["accepted"]) == 1
    assert len(second["duplicates"]) == 1
    assert row.normalized_event == "bounced"
    assert row.cause_family == "authentication_policy_rejection"
    assert row.recipient_domain == "example.org"
    assert row.recipient_hash and "private-person" not in row.recipient_hash
    assert "private-person" not in (row.diagnostic_text or "")
    assert "Secret content" not in (row.sanitized_payload or "")
    assert row.retention_until > row.received_at
    assert json.loads(row.signal_json)["family"] == "dsn_delivery_status"


def test_provider_diagnostic_redacts_recipient_local_part(db_session):
    workspace = Workspace(slug="provider-redaction", name="Provider redaction")
    db_session.add(workspace)
    db_session.commit()
    payload = {
        "schema_version": "dmarq.provider_delivery_event.v1",
        "provider": "example-provider",
        "event_id": "evt-private-diagnostic",
        "event": "bounced",
        "occurred_at": datetime.utcnow(),
        "domain": "example.com",
        "recipient": "private-person@example.net",
        "status_code": "5.1.1",
        "diagnostic_text": "550 private-person@example.net user unknown",
    }

    event, created = ingest_provider_event(db_session, workspace=workspace, payload=payload)

    assert created is True
    assert "private-person" not in (event["diagnostic_text"] or "")
    assert "[redacted-email]@example.net" in event["diagnostic_text"]


def test_provider_event_enforces_replay_window_and_idempotency(db_session):
    workspace = Workspace(slug="provider-events", name="Provider events")
    db_session.add(workspace)
    db_session.commit()
    payload = {
        "schema_version": "dmarq.provider_delivery_event.v1",
        "provider": "example-provider",
        "event_id": "evt-1",
        "event": "bounced",
        "occurred_at": datetime.utcnow(),
        "domain": "example.com",
        "recipient": "person@example.net",
        "status_code": "5.1.1",
        "diagnostic_text": "550 user unknown",
    }

    first, created = ingest_provider_event(db_session, workspace=workspace, payload=payload)
    duplicate, duplicate_created = ingest_provider_event(
        db_session, workspace=workspace, payload=payload
    )

    assert created is True
    assert duplicate_created is False
    assert duplicate["id"] == first["id"]
    payload["event_id"] = "evt-old"
    payload["occurred_at"] = datetime.utcnow() - timedelta(days=8)
    try:
        ingest_provider_event(db_session, workspace=workspace, payload=payload)
    except ValueError as exc:
        assert "replay window" in str(exc)
    else:
        raise AssertionError("Old provider event was accepted")


def test_provider_event_treats_unique_race_as_duplicate(db_session, monkeypatch):
    workspace = Workspace(slug="provider-event-race", name="Provider event race")
    db_session.add(workspace)
    db_session.commit()
    payload = {
        "schema_version": "dmarq.provider_delivery_event.v1",
        "provider": "example-provider",
        "event_id": "evt-race",
        "event": "bounced",
        "occurred_at": datetime.utcnow(),
        "domain": "example.com",
    }
    original, _ = ingest_provider_event(db_session, workspace=workspace, payload=payload)
    from app.services import delivery_events as delivery_service

    real_lookup = delivery_service._delivery_event_for_key
    lookup_calls = 0

    def raced_lookup(*args, **kwargs):
        nonlocal lookup_calls
        lookup_calls += 1
        return None if lookup_calls == 1 else real_lookup(*args, **kwargs)

    real_flush = db_session.flush
    flush_calls = 0

    def raced_flush(*args, **kwargs):
        nonlocal flush_calls
        flush_calls += 1
        if flush_calls == 1:
            raise IntegrityError("insert", {}, Exception("duplicate"))
        return real_flush(*args, **kwargs)

    monkeypatch.setattr(delivery_service, "_delivery_event_for_key", raced_lookup)
    monkeypatch.setattr(db_session, "flush", raced_flush)

    duplicate, created = ingest_provider_event(db_session, workspace=workspace, payload=payload)

    assert created is False
    assert duplicate["id"] == original["id"]


def test_provider_event_endpoint_requires_the_delivery_write_scope(client, db_session):
    token = create_api_token(
        db_session,
        name="delivery webhook",
        scopes=[DELIVERY_EVENTS_WRITE_SCOPE],
        allowed_scopes=ALL_API_TOKEN_SCOPES,
    )
    payload = {
        "schema_version": "dmarq.provider_delivery_event.v1",
        "provider": "example-provider",
        "event_id": "evt-api-1",
        "event": "deferred",
        "occurred_at": datetime.utcnow().isoformat(),
        "domain": "example.com",
        "status_code": "4.7.0",
    }

    missing = client.post("/api/v1/delivery-events/provider", json=payload)
    accepted = client.post(
        "/api/v1/delivery-events/provider",
        json=payload,
        headers={"X-API-Key": token.secret},
    )
    duplicate = client.post(
        "/api/v1/delivery-events/provider",
        json=payload,
        headers={"X-API-Key": token.secret},
    )

    assert missing.status_code == 401
    assert accepted.status_code == 202
    assert accepted.json()["accepted"] is True
    assert duplicate.json()["duplicate"] is True


def test_non_dsn_is_rejected():
    try:
        parse_dsn_bytes(b"From: sender@example.com\r\nSubject: hello\r\n\r\nbody")
    except DSNParseError as exc:
        assert "not a delivery status" in str(exc)
    else:
        raise AssertionError("Ordinary email was accepted as a DSN")
