import email

from app.services.forensic_parser import ForensicParser


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

    try:
        ForensicParser.parse_bytes(content)
    except ValueError as exc:
        assert "forensic" in str(exc)
    else:
        raise AssertionError("Expected parser to reject non-forensic email")
