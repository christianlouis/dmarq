"""Webhook ingestion endpoints for inbound DMARC report emails."""

import base64
import email
import hmac
import logging
from email.header import decode_header
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.core.redaction import sanitize_for_log
from app.services.dmarc_parser import DMARCParser
from app.services.report_persistence import report_exists, save_parsed_report
from app.services.report_store import ReportStore

logger = logging.getLogger(__name__)
router = APIRouter()


class EmailWebhookPayload(BaseModel):
    """Payload for JSON webhook delivery from an email worker."""

    raw_email: str
    from_address: Optional[str] = None
    to_address: Optional[str] = None
    subject: Optional[str] = None


def _decode_email_header(header: Optional[str]) -> str:
    """Decode an RFC 2047 email header to display text."""
    if not header:
        return ""
    decoded_parts = []
    for text, encoding in decode_header(header):
        if isinstance(text, bytes):
            decoded_parts.append(text.decode(encoding or "utf-8", errors="replace"))
        else:
            decoded_parts.append(text)
    return " ".join(decoded_parts)


def _is_dmarc_filename(filename: str) -> bool:
    lower = filename.lower()
    return lower.endswith((".xml", ".zip", ".gz", ".gzip"))


def _require_webhook_secret(x_webhook_secret: Optional[str]) -> None:
    settings = get_settings()
    if not settings.WEBHOOK_SECRET:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Webhook ingestion is not configured.",
        )
    if not x_webhook_secret or not hmac.compare_digest(x_webhook_secret, settings.WEBHOOK_SECRET):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid webhook secret.",
        )


def _store_report(db: Session, store: ReportStore, report: Dict[str, Any]) -> str:
    domain = report.get("domain") or "unknown"
    report_id = report.get("report_id") or ""
    if report_id and (store.has_report(domain, report_id) or report_exists(db, domain, report_id)):
        return "duplicate"
    save_parsed_report(db, report)
    store.add_report(report)
    return "imported"


def _process_email_attachments(msg: email.message.Message, db: Session) -> Dict[str, Any]:
    store = ReportStore.get_instance()
    results: Dict[str, Any] = {
        "reports_found": 0,
        "imported": 0,
        "duplicates": 0,
        "errors": [],
    }

    for part in msg.walk():
        if part.get_content_disposition() != "attachment":
            continue

        filename = _decode_email_header(part.get_filename())
        if not filename or not _is_dmarc_filename(filename):
            continue

        try:
            content = part.get_payload(decode=True)
            if not content:
                continue
            report = DMARCParser.parse_file(content, filename)
            outcome = _store_report(db, store, report)
            results["reports_found"] += 1
            if outcome == "duplicate":
                results["duplicates"] += 1
            else:
                results["imported"] += 1
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.warning(
                "Webhook failed to process DMARC attachment %s: %s",
                sanitize_for_log(filename),
                sanitize_for_log(exc),
            )
            results["errors"].append(filename)

    return results


def _subject_from_message(msg: email.message.Message, fallback: Optional[str] = None) -> str:
    return fallback or _decode_email_header(msg.get("Subject"))


@router.post("/email")
async def receive_email(
    payload: EmailWebhookPayload,
    x_webhook_secret: Optional[str] = Header(None),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Receive a base64 encoded raw email from an email worker webhook."""
    _require_webhook_secret(x_webhook_secret)
    try:
        raw_email = base64.b64decode(payload.raw_email, validate=True)
    except (ValueError, TypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="raw_email must be valid base64.",
        ) from exc

    return _handle_raw_email(raw_email, db, subject=payload.subject)


@router.post("/email/raw")
async def receive_raw_email(
    request: Request,
    x_webhook_secret: Optional[str] = Header(None),
    db: Session = Depends(get_db),
) -> Dict[str, Any]:
    """Receive raw RFC 822 email bytes from an email worker webhook."""
    _require_webhook_secret(x_webhook_secret)
    return _handle_raw_email(await request.body(), db)


def _handle_raw_email(
    raw_email: bytes,
    db: Session,
    *,
    subject: Optional[str] = None,
) -> Dict[str, Any]:
    try:
        msg = email.message_from_bytes(raw_email)
        attachment_results = _process_email_attachments(msg, db)
        db.commit()
    except HTTPException:
        raise
    except Exception as exc:  # pylint: disable=broad-exception-caught
        db.rollback()
        logger.warning("Webhook failed to process email: %s", sanitize_for_log(exc))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Error processing email.",
        ) from exc

    return {
        "success": True,
        "subject": _subject_from_message(msg, subject),
        **attachment_results,
    }
