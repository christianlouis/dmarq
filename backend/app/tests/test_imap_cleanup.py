"""Regression coverage for opt-in cleanup of imported aggregate report mail."""

import email
import json
from datetime import datetime
from email.mime.application import MIMEApplication
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from app.models.report import DMARCReport, TLSReport
from app.models.mail_source import MailSource
from app.models.mail_source_import import MailSourceImport
from app.models.workspace import Workspace
from app.services.imap_client import IMAPClient
from app.services.mail_connector import initial_import_stats
from app.services.import_history import record_import_attempt
from app.tests.test_imap_client import MINIMAL_TLS_RPT_JSON, _make_email_with_attachment


def make_client(db, enabled=True, workspace_id=None):
    with patch(
        "app.services.imap_client.get_settings",
        return_value=SimpleNamespace(DELETE_IMPORTED_EMAILS=enabled),
    ):
        # Same explicit credentials and inherited setting as configured Mail Sources.
        return IMAPClient(
            server="imap.example.com",
            port=993,
            username="reports@example.com",
            password="test-password",
            db=db,
            workspace_id=workspace_id,
        )


def mailbox(raw=None):
    mail = MagicMock()
    mail.fetch.return_value = ("OK", [(b"1", raw or _make_email_with_attachment())])
    mail.store.return_value = ("OK", [])
    return mail


@pytest.mark.parametrize("enabled", [False, True])
def test_duplicate_cleanup_inherits_setting_for_configured_source(db_session, enabled):
    client = make_client(db_session, enabled=False)
    first = initial_import_stats(deleted=True)
    client._process_single_email(mailbox(), b"1", first)
    db_session.commit()
    assert first["reports_found"] == 1

    client = make_client(db_session, enabled=enabled)
    mail = mailbox()
    second = initial_import_stats(deleted=True)
    client._process_single_email(mail, b"1", second)

    assert second["reports_found"] == 0
    assert second["duplicate_reports"] == 1
    assert second["deleted"] == int(enabled)
    assert db_session.query(DMARCReport).count() == 1
    if enabled:
        mail.store.assert_any_call(b"1", "+FLAGS", "\\Deleted")
    else:
        mail.store.assert_called_once_with(b"1", "+FLAGS", "\\Seen")


def test_persisted_mail_source_two_fetches_retain_then_delete(db_session):
    """A duplicate second fetch is retained first, then deleted when enabled."""
    source = MailSource(name="Persisted IMAP", method="IMAP")
    db_session.add(source)
    db_session.commit()

    first_client = make_client(db_session, enabled=False)
    first_stats = initial_import_stats(deleted=True)
    first_client._process_single_email(mailbox(), b"1", first_stats)
    record_import_attempt(
        db_session,
        source,
        {**first_stats, "success": True},
        started_at=datetime.utcnow(),
        trigger="manual",
    )
    db_session.commit()

    second_client = make_client(db_session, enabled=True)
    second_mail = mailbox()
    second_stats = initial_import_stats(deleted=True)
    second_client._process_single_email(second_mail, b"2", second_stats)
    record_import_attempt(
        db_session,
        source,
        {**second_stats, "success": True},
        started_at=datetime.utcnow(),
        trigger="manual",
    )
    db_session.commit()

    attempts = db_session.query(MailSourceImport).order_by(MailSourceImport.id).all()
    assert len(attempts) == 2
    assert json.loads(attempts[0].details)[0]["status"] == "imported"
    assert json.loads(attempts[1].details)[0]["status"] == "duplicate"
    assert first_stats["deleted"] == 0
    assert second_stats["deleted"] == 1
    second_mail.store.assert_any_call(b"2", "+FLAGS", "\\Deleted")


def test_tls_duplicate_cleanup_and_commit_failure_are_durable(db_session):
    tls_message = _make_email_with_attachment("tls.json", MINIMAL_TLS_RPT_JSON, "application/json")
    first_client = make_client(db_session, enabled=False)
    first_stats = initial_import_stats(deleted=True)
    first_client._process_single_email(mailbox(tls_message), b"1", first_stats)
    db_session.commit()
    assert first_stats["reports_found"] == 1
    assert first_stats["deleted"] == 0

    second_mail = mailbox(tls_message)
    second_stats = initial_import_stats(deleted=True)
    make_client(db_session, enabled=True)._process_single_email(second_mail, b"2", second_stats)
    assert second_stats["duplicate_reports"] == 1
    assert second_stats["deleted"] == 1
    assert db_session.query(TLSReport).count() == 1

    failed_payload = json.loads(MINIMAL_TLS_RPT_JSON)
    failed_payload["report-id"] = "tlsrpt-commit-failure"
    failed_mail = mailbox(
        _make_email_with_attachment(
            "tls-failure.json", json.dumps(failed_payload).encode(), "application/json"
        )
    )
    failed_stats = initial_import_stats(deleted=True)
    with patch.object(db_session, "commit", side_effect=RuntimeError("commit failed")):
        make_client(db_session, enabled=True)._process_single_email(failed_mail, b"3", failed_stats)
    assert failed_stats["errors"]
    assert failed_stats["deleted"] == 0
    assert db_session.query(TLSReport).count() == 1


def test_invalid_tls_sibling_dmarc_is_retained(db_session):
    msg = email.message_from_bytes(
        _make_email_with_attachment("invalid.json", b"{invalid", "application/json")
    )
    valid = email.message_from_bytes(_make_email_with_attachment())
    for part in valid.get_payload()[1:]:
        msg.attach(part)

    mail = mailbox(msg.as_bytes())
    stats = initial_import_stats(deleted=True)
    make_client(db_session, enabled=True)._process_single_email(mail, b"1", stats)

    assert stats["reports_found"] == 1
    assert stats["deleted"] == 0
    assert stats["errors"]
    mail.store.assert_called_once_with(b"1", "+FLAGS", "\\Seen")


@pytest.mark.parametrize("duplicate", [False, True])
@pytest.mark.parametrize(
    "filename,content", [("broken.xml", b"broken"), ("notes.txt", b"notes"), (None, b"nameless")]
)
def test_preserves_message_with_unhandled_attachment(db_session, duplicate, filename, content):
    client = make_client(db_session)
    if duplicate:
        client._process_single_email(mailbox(), b"1", initial_import_stats(deleted=True))
    msg = email.message_from_bytes(_make_email_with_attachment())
    part = MIMEApplication(content)
    part["Content-Disposition"] = f'attachment; filename="{filename}"' if filename else "attachment"
    msg.attach(part)
    mail = mailbox(msg.as_bytes())
    stats = initial_import_stats(deleted=True)
    client._process_single_email(mail, b"2", stats)
    assert stats["deleted"] == 0
    mail.store.assert_called_once_with(b"2", "+FLAGS", "\\Seen")


def test_cache_only_duplicate_is_retained_without_database():
    client = make_client(None, enabled=False)
    client._process_single_email(mailbox(), b"1", initial_import_stats(deleted=True))
    client.delete_emails = True
    mail = mailbox()
    stats = initial_import_stats(deleted=True)
    client._process_single_email(mail, b"1", stats)
    assert stats["duplicate_reports"] == 1
    assert stats["deleted"] == 0
    mail.store.assert_called_once_with(b"1", "+FLAGS", "\\Seen")


def test_commit_failure_keeps_email_and_retry_ignores_stale_cache(db_session):
    client = make_client(db_session)
    mail = mailbox()
    stats = initial_import_stats(deleted=True)
    with patch.object(db_session, "commit", side_effect=RuntimeError("commit failed")):
        client._process_single_email(mail, b"1", stats)
    assert stats["errors"]
    assert stats["deleted"] == 0
    mail.store.assert_called_once_with(b"1", "+FLAGS", "\\Seen")
    assert db_session.query(DMARCReport).count() == 0
    retry = initial_import_stats(deleted=True)
    client._process_single_email(mailbox(), b"1", retry)
    assert retry["reports_found"] == 1
    assert retry["duplicate_reports"] == 0
    assert retry["deleted"] == 1
    assert db_session.query(DMARCReport).count() == 1


def test_cache_from_other_workspace_does_not_authorize_deletion(db_session):
    first = Workspace(name="First", slug="cleanup-first")
    second = Workspace(name="Second", slug="cleanup-second")
    db_session.add_all([first, second])
    db_session.commit()
    client = make_client(db_session, workspace_id=first.id)
    client._process_single_email(mailbox(), b"1", initial_import_stats(deleted=True))
    client = make_client(db_session, workspace_id=second.id)
    stats = initial_import_stats(deleted=True)
    mail = mailbox()
    client._process_single_email(mail, b"1", stats)
    # Domains are globally unique: importing into another workspace fails and
    # must retain the email, rather than trusting the first workspace's cache.
    assert stats["duplicate_reports"] == 0
    assert stats["deleted"] == 0
    assert stats["errors"]
    mail.store.assert_called_once_with(b"1", "+FLAGS", "\\Seen")


def test_fetch_expunge_for_duplicate_only_mailbox(db_session):
    client = make_client(db_session, enabled=False)
    client._process_single_email(mailbox(), b"1", initial_import_stats(deleted=True))
    db_session.commit()
    client = make_client(db_session)
    mail = mailbox()
    mail.search.return_value = ("OK", [b"1"])
    with patch.object(client, "_connect", return_value=mail):
        stats = client.fetch_reports()
    assert stats["success"] is True
    assert stats["reports_found"] == 0
    assert stats["duplicate_reports"] == 1
    assert stats["deleted"] == 1
    mail.expunge.assert_called_once()


def test_commit_precedes_delete_flag_and_rejected_flag_is_not_counted(db_session):
    client = make_client(db_session)
    mail = mailbox()
    calls = []
    real_commit = db_session.commit

    def commit():
        calls.append("commit")
        real_commit()

    def store(_id, _operation, flag):
        calls.append(flag)
        return ("NO" if flag == "\\Deleted" else "OK", [])

    mail.store.side_effect = store
    stats = initial_import_stats(deleted=True)
    with patch.object(db_session, "commit", side_effect=commit):
        client._process_single_email(mail, b"1", stats)
    assert calls == ["\\Seen", "commit", "\\Deleted"]
    assert stats["deleted"] == 0
    assert stats["errors"]
