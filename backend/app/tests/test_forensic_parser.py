import email
from unittest.mock import MagicMock

import pytest

from app.services import forensic_parser as forensic_parser_module
from app.services.forensic_parser import (
    ForensicParser,
    MAX_FORENSIC_REPORT_SIZE,
    _coerce_text,
    _domain_from_address,
    _message_part_payload,
    _payload_text,
)


SAMPLE_FORENSIC_EMAIL = b"""\
From: DMARC Reporter <dmarc-reports@example.net>
To: postmaster@example.com
Subject: DMARC Failure Report for example.com
Message-ID: <report-1@example.net>
MIME-Version: 1.0
Content-Type: multipart/report; report-type=feedback-report; boundary="ruf-boundary"

--ruf-boundary
Content-Type: text/plain; charset=utf-8

This is a DMARC failure report.

--ruf-boundary
Content-Type: message/feedback-report

Feedback-Type: auth-failure
User-Agent: Example Reporter
Version: 1
Original-Mail-From: alice@example.com
Arrival-Date: Fri, 22 May 2026 10:15:00 +0000
Source-IP: 203.0.113.8
Reported-Domain: example.com
Authentication-Results: mx.example.net; dkim=fail header.d=example.com; spf=pass
Auth-Failure: dkim
Delivery-Result: reject

--ruf-boundary
Content-Type: text/rfc822-headers

From: Alice Sender <alice@example.com>
To: Bob Receiver <bob@example.net>
Subject: Customer renewal token abcdefghijklmnopqrstuvwxyz123456
Message-ID: <original-message@example.com>
Date: Fri, 22 May 2026 10:14:55 +0000

--ruf-boundary--
"""


def test_detects_forensic_report_email():
    msg = email.message_from_bytes(SAMPLE_FORENSIC_EMAIL)

    assert ForensicParser.is_forensic_report(msg) is True


def test_parse_forensic_email_redacts_and_extracts_failure_fields():
    parsed = ForensicParser.parse_bytes(SAMPLE_FORENSIC_EMAIL)

    assert parsed["report_id"].startswith("ruf-")
    assert parsed["reported_domain"] == "example.com"
    assert parsed["source_ip"] == "203.0.113.8"
    assert parsed["auth_failure"] == "dkim"
    assert parsed["delivery_result"] == "reject"
    assert parsed["arrival_date"].year == 2026
    assert parsed["original_mail_from"] == "al***@example.com"
    assert "al***@example.com" in parsed["original_from"]
    assert "bo***@example.net" in parsed["original_to"]
    assert "[redacted-token]" in parsed["original_subject"]
    assert parsed["original_message_id"]
    assert "original-message@example.com" not in parsed["original_message_id"]


def test_non_forensic_email_is_rejected():
    content = b"From: sender@example.com\r\nSubject: hello\r\n\r\nplain email"

    with pytest.raises(ValueError, match="forensic"):
        ForensicParser.parse_bytes(content)


def test_parse_forensic_email_uses_explicit_message_hint():
    parsed = ForensicParser.parse_bytes(SAMPLE_FORENSIC_EMAIL, message_id_hint="gmail-message-1")

    assert parsed["report_id"] == "ruf-gmail-message-1"


def test_parse_forensic_email_handles_invalid_dates():
    content = SAMPLE_FORENSIC_EMAIL.replace(
        b"Arrival-Date: Fri, 22 May 2026 10:15:00 +0000",
        b"Arrival-Date: not a real date",
    )

    parsed = ForensicParser.parse_bytes(content)

    assert parsed["arrival_date"] is None


def test_parse_forensic_email_normalizes_offset_dates_to_utc():
    content = SAMPLE_FORENSIC_EMAIL.replace(
        b"Arrival-Date: Fri, 22 May 2026 10:15:00 +0000",
        b"Arrival-Date: Fri, 22 May 2026 12:15:00 +0200",
    )

    parsed = ForensicParser.parse_bytes(content)

    assert parsed["arrival_date"].hour == 10
    assert parsed["arrival_date"].tzinfo is None


def test_parse_forensic_email_falls_back_to_dkim_domain_and_content_hash():
    content = SAMPLE_FORENSIC_EMAIL.replace(b"Message-ID: <report-1@example.net>\n", b"")
    content = content.replace(b"Reported-Domain: example.com\n", b"DKIM-Domain: fallback.test\n")
    content = content.replace(b"Message-ID: <original-message@example.com>\n", b"")

    parsed = ForensicParser.parse_bytes(content)

    assert parsed["reported_domain"] == "fallback.test"
    assert parsed["report_id"].startswith("ruf-")
    assert parsed["original_message_id"] == ""
    assert parsed["feedback_headers"]


def test_parse_forensic_email_extracts_message_rfc822_headers():
    content = b"""\
From: DMARC Reporter <dmarc-reports@example.net>
Subject: DMARC forensic report
MIME-Version: 1.0
Content-Type: multipart/report; report-type=feedback-report; boundary="ruf-boundary"

--ruf-boundary
Content-Type: message/feedback-report

Feedback-Type: auth-failure
Original-Mail-From: sender@fallback.test
Source-IP: 203.0.113.9

--ruf-boundary
Content-Type: message/rfc822

From: Carol <carol@fallback.test>
To: Dave <dave@example.net>
Subject: Forwarded failure sample
Message-ID: <forwarded@example.test>

body is ignored
--ruf-boundary--
"""

    parsed = ForensicParser.parse_bytes(content)

    assert parsed["reported_domain"] == "fallback.test"
    assert "ca***@fallback.test" in parsed["original_from"]
    assert parsed["original_subject"] == "Forwarded failure sample"


def test_is_forensic_report_detects_headers_and_subject_fallbacks():
    header_only = email.message_from_bytes(
        b"""\
Subject: Delivery report
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b"

--b
Content-Type: text/rfc822-headers

Authentication-Results: mx; dmarc=fail

--b--
"""
    )
    subject_only = email.message_from_bytes(b"Subject: DMARC RUF failure\r\n\r\nbody")

    assert ForensicParser.is_forensic_report(header_only) is True
    assert ForensicParser.is_forensic_report(subject_only) is True


def test_parse_forensic_email_rejects_empty_and_oversized_payloads():
    with pytest.raises(ValueError, match="empty"):
        ForensicParser.parse_bytes(b"")

    with pytest.raises(ValueError, match="too large"):
        ForensicParser.parse_bytes(b"x" * (MAX_FORENSIC_REPORT_SIZE + 1))


def test_forensic_parser_helper_fallbacks(monkeypatch):
    multipart = email.message_from_bytes(
        b"Subject: container\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n--x--"
    )
    message = email.message_from_bytes(b"Subject: plain\r\n\r\nbody")

    assert _coerce_text(b"hello") == "hello"
    assert _payload_text(multipart) == ""
    assert _message_part_payload(message) is None
    assert _domain_from_address("not-an-address") == ""

    part = MagicMock()
    part.get_payload.side_effect = [None, ["nested"]]
    assert _payload_text(part) == ""

    part = MagicMock()
    part.get_payload.side_effect = [None, "plain text"]
    assert _payload_text(part) == "plain text"

    monkeypatch.setattr(forensic_parser_module, "parsedate_to_datetime", lambda _value: None)
    assert forensic_parser_module._parse_datetime("Fri, 22 May 2026 10:15:00 +0000") is None


def test_is_forensic_report_detects_feedback_part_without_report_container():
    msg = email.message_from_bytes(
        b"""\
Subject: Delivery notice
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b"

--b
Content-Type: message/feedback-report

Feedback-Type: auth-failure

--b--
"""
    )

    assert ForensicParser.is_forensic_report(msg) is True


def test_is_forensic_report_ignores_non_dmarc_header_parts():
    msg = email.message_from_bytes(
        b"""\
Subject: DMARC forensic notice
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="b"

--b
Content-Type: text/rfc822-headers

Authentication-Results: mx; spf=pass

--b--
"""
    )

    assert ForensicParser.is_forensic_report(msg) is True
