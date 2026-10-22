import json
from datetime import datetime

from app.models.mail_source import MailSource
from app.services.import_history import record_import_attempt


def test_already_ingested_skip_does_not_settle_prior_real_failure(db_session):
    source = MailSource(
        name="Gmail recovery regression",
        method="GMAIL_API",
        gmail_email="reports@example.com",
    )
    db_session.add(source)
    db_session.flush()

    failed = record_import_attempt(
        db_session,
        source,
        {"success": False, "details": [{"status": "error", "message_id": "cached-id"}]},
        started_at=datetime.utcnow(),
        trigger="scheduled",
    )
    db_session.flush()
    assert json.loads(failed.recovery_metadata)[0]["disposition"] == "pending"

    skipped = record_import_attempt(
        db_session,
        source,
        {
            "success": True,
            "details": [
                {
                    "status": "skipped",
                    "reason": "already_ingested_message",
                    "message_id": "cached-id",
                }
            ],
        },
        started_at=datetime.utcnow(),
        trigger="scheduled",
    )
    db_session.flush()
    assert json.loads(failed.recovery_metadata)[0]["disposition"] == "pending"
    assert json.loads(skipped.recovery_metadata)[0]["disposition"] == "settled"

    imported = record_import_attempt(
        db_session,
        source,
        {"success": True, "details": [{"status": "imported", "message_id": "cached-id"}]},
        started_at=datetime.utcnow(),
        trigger="scheduled",
    )
    assert json.loads(skipped.recovery_metadata)[0]["disposition"] == "settled"
    assert imported.recovery_metadata == "[]"
