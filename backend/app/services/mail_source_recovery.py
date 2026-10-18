"""Persistence helpers for bounded, source-scoped mail recovery actions."""

from typing import List

from sqlalchemy.orm import Session

from app.models.mail_source import MailSource
from app.models.mail_source_ignored_message import MailSourceIgnoredMessage


def recovery_binding(source: MailSource) -> dict:
    """Return the non-secret provider context that authorizes a retry."""
    method = str(source.method or "").upper()
    binding = {
        "method": method,
        "folder": str(source.folder or "INBOX"),
        "account": "",
    }
    if method == "GMAIL_API":
        binding.update(
            account=str(source.gmail_email or ""),
            client_id=str(source.gmail_client_id or ""),
        )
    elif method == "M365_GRAPH":
        binding.update(
            account=str(source.m365_mailbox or source.m365_email or ""),
            auth_mode=str(source.m365_auth_mode or "delegated"),
            tenant_id=str(source.m365_tenant_id or "common"),
            client_id=str(source.m365_client_id or ""),
            folder_id=str(source.m365_folder_id or ""),
        )
    return binding


def ignored_message_ids(db: Session, source: MailSource) -> List[str]:
    """Return durable local ignore IDs for the source's current provider."""
    provider = str(source.method or "").upper()
    workspace_id = getattr(source, "workspace_id", None)
    source_id = getattr(source, "id", None)
    if not isinstance(workspace_id, int) or not isinstance(source_id, int):
        return []
    return [
        str(row.message_id)
        for row in (
            db.query(MailSourceIgnoredMessage.message_id)
            .filter(
                MailSourceIgnoredMessage.workspace_id == workspace_id,
                MailSourceIgnoredMessage.mail_source_id == source_id,
                MailSourceIgnoredMessage.provider == provider,
            )
            .all()
        )
    ]


def ignore_message(db: Session, source: MailSource, message_id: str) -> None:
    """Persist an ignore without evicting earlier dispositions."""
    provider = str(source.method or "").upper()
    exists = (
        db.query(MailSourceIgnoredMessage.id)
        .filter(
            MailSourceIgnoredMessage.workspace_id == source.workspace_id,
            MailSourceIgnoredMessage.mail_source_id == source.id,
            MailSourceIgnoredMessage.provider == provider,
            MailSourceIgnoredMessage.message_id == message_id,
        )
        .first()
    )
    if exists is None:
        db.add(
            MailSourceIgnoredMessage(
                workspace_id=source.workspace_id,
                mail_source_id=source.id,
                provider=provider,
                message_id=message_id,
            )
        )


def restore_message(db: Session, source: MailSource, message_id: str) -> None:
    """Remove only the requested source-scoped local ignore disposition."""
    provider = str(source.method or "").upper()
    (
        db.query(MailSourceIgnoredMessage)
        .filter(
            MailSourceIgnoredMessage.workspace_id == source.workspace_id,
            MailSourceIgnoredMessage.mail_source_id == source.id,
            MailSourceIgnoredMessage.provider == provider,
            MailSourceIgnoredMessage.message_id == message_id,
        )
        .delete(synchronize_session=False)
    )
