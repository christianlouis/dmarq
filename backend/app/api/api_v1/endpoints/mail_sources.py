"""
Mail Sources API endpoints.

Provides CRUD operations for MailSource objects stored in the database, plus
a *test-connection* action that validates the supplied credentials without
persisting anything.  Gmail API and Microsoft 365 sources additionally have
OAuth2 helper endpoints (authorize-url, callback, fetch).
"""

import base64
import hmac
import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.core.redaction import sanitize_for_log
from app.core.security import require_admin_auth
from app.models.mail_source import MailSource
from app.models.mail_source_import import MailSourceImport
from app.services.gmail_client import GmailClient
from app.services.imap_client import IMAPClient
from app.services.import_history import record_import_attempt
from app.services.mailbox_recovery import (
    connection_diagnostic,
    connection_test_response,
    diagnostic_category,
    import_result_diagnostic,
    redact_recovery_text,
)
from app.services.microsoft_graph_client import MicrosoftGraphClient
from app.services.workspace_access import (
    PERMISSION_MAIL_SOURCES_WRITE,
    parse_selected_workspace_id,
    resolve_authorized_workspace,
)
from app.services.workspace_audit import changed_fields, record_workspace_audit_log
from app.services.workspaces import (
    workspace_mail_source_query,
)

router = APIRouter()
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class MailSourceBase(BaseModel):
    """Fields shared by create and update payloads."""

    name: str
    method: str = "IMAP"  # IMAP | POP3 | GMAIL_API | M365_GRAPH
    server: Optional[str] = None
    port: int = 993
    username: Optional[str] = None
    password: Optional[str] = None
    use_ssl: bool = True
    folder: str = "INBOX"
    polling_interval: int = 60
    enabled: bool = True
    # Gmail API OAuth2 fields (only relevant when method == GMAIL_API)
    gmail_client_id: Optional[str] = None
    gmail_client_secret: Optional[str] = None
    # Microsoft 365 Graph OAuth2 fields (only relevant when method == M365_GRAPH)
    m365_tenant_id: Optional[str] = "common"
    m365_client_id: Optional[str] = None
    m365_client_secret: Optional[str] = None
    m365_mailbox: Optional[str] = None
    m365_folder_id: Optional[str] = None


class MailSourceCreate(MailSourceBase):
    """Payload for creating a new mail source."""


class MailSourceUpdate(BaseModel):
    """Payload for partial updates – all fields optional."""

    name: Optional[str] = None
    method: Optional[str] = None
    server: Optional[str] = None
    port: Optional[int] = None
    username: Optional[str] = None
    password: Optional[str] = None
    use_ssl: Optional[bool] = None
    folder: Optional[str] = None
    polling_interval: Optional[int] = None
    enabled: Optional[bool] = None
    gmail_client_id: Optional[str] = None
    gmail_client_secret: Optional[str] = None
    m365_tenant_id: Optional[str] = None
    m365_client_id: Optional[str] = None
    m365_client_secret: Optional[str] = None
    m365_mailbox: Optional[str] = None
    m365_folder_id: Optional[str] = None


class MailSourceResponse(MailSourceBase):
    """Response schema – exposes the stored row without exposing raw password."""

    id: int
    last_checked: Optional[datetime] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    # Mask the stored password in responses
    password: Optional[str] = None
    # Gmail: show the authorised email address but not tokens
    gmail_email: Optional[str] = None
    # Indicate whether OAuth tokens are present (without exposing them)
    gmail_connected: bool = False
    # Microsoft 365: show the authorised account and token state, but not tokens
    m365_email: Optional[str] = None
    m365_connected: bool = False

    class Config:
        from_attributes = True


class TestConnectionRequest(BaseModel):
    """Credentials for an ad-hoc connection test (not persisted)."""

    server: Optional[str] = None
    port: int = 993
    username: Optional[str] = None
    password: Optional[str] = None
    ssl: bool = True
    method: str = "IMAP"


class GmailCallbackRequest(BaseModel):
    """Payload for the Gmail OAuth2 callback endpoint."""

    code: str
    redirect_uri: str


class M365CallbackRequest(BaseModel):
    """Payload for the Microsoft 365 OAuth2 callback endpoint."""

    code: str
    redirect_uri: str


class MailSourceImportResponse(BaseModel):
    """Sanitized import-history entry for a mail source."""

    id: int
    mail_source_id: int
    trigger: str
    status: str
    processed: int
    reports_found: int
    duplicate_reports: int
    error_count: int
    new_domains: List[str]
    errors: List[str]
    details: List[Dict[str, str]]
    started_at: datetime
    finished_at: datetime
    created_at: datetime


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------


def _sanitize_for_log(value: object) -> str:
    """Remove CR/LF characters from a value to prevent log injection attacks."""
    return sanitize_for_log(value)


def _redact_sensitive_text(value: object) -> str:
    """Remove log-injection characters and redact secret-like diagnostic text."""
    return redact_recovery_text(value)


def _diagnostic_category(message: str, details: Optional[object] = None) -> str:
    """Map provider-specific failures to operator-friendly categories."""
    return diagnostic_category(message, details)


def _connection_diagnostic(
    success: bool, message: str, details: Optional[object] = None
) -> Dict[str, Any]:
    """Build sanitized connection diagnostics for API responses and UI recovery copy."""
    return connection_diagnostic(success, message, details)


def _connection_test_response(
    success: bool,
    message: str,
    stats: Optional[Dict[str, Any]] = None,
    details: Optional[object] = None,
) -> Dict[str, Any]:
    """Normalize stored and ad-hoc mailbox test responses."""
    return {
        **connection_test_response(success, message, stats, details),
        "timestamp": datetime.now().isoformat(),
    }


def _get_source_or_404(source_id: int, db: Session, workspace=None) -> MailSource:
    query = db.query(MailSource).filter(MailSource.id == source_id)
    if workspace is not None:
        query = query.filter(MailSource.workspace_id == workspace.id)
    source = query.first()
    if source is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Mail source {source_id} not found",
        )
    return source


def _selected_workspace_id(selected_workspace: Optional[str]) -> Optional[int]:
    return parse_selected_workspace_id(selected_workspace)


def _selected_workspace_or_oauth_state(
    selected_workspace: Optional[str],
    state_value: Optional[str],
    source_id: int,
) -> Optional[int]:
    return _workspace_id_from_oauth_state(state_value, source_id) or _selected_workspace_id(
        selected_workspace
    )


def _authorized_mail_source_workspace(
    auth_context: Dict[str, Any],
    db: Session,
    selected_workspace_id: Optional[int] = None,
):
    """Resolve and authorize the selected workspace for mail-source operations."""
    return resolve_authorized_workspace(
        db,
        auth_context,
        PERMISSION_MAIL_SOURCES_WRITE,
        selected_workspace_id=selected_workspace_id,
    )


def _oauth_state(workspace_id: int, source_id: int) -> str:
    """Return a signed OAuth state value bound to one workspace and source."""
    payload = json.dumps(
        {"source_id": int(source_id), "workspace_id": int(workspace_id)},
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    encoded_payload = _base64url_encode(payload)
    signature = _oauth_state_signature(encoded_payload)
    return f"v1.{encoded_payload}.{_base64url_encode(signature)}"


def _base64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _base64url_decode(value: str) -> bytes:
    padded = value + ("=" * (-len(value) % 4))
    return base64.urlsafe_b64decode(padded.encode("ascii"))


def _oauth_state_signature(encoded_payload: str) -> bytes:
    return hmac.digest(
        get_settings().SECRET_KEY.encode("utf-8"),
        encoded_payload.encode("ascii"),
        "sha256",
    )


def _invalid_oauth_state() -> HTTPException:
    return HTTPException(status_code=400, detail="Invalid OAuth state.")


def _oauth_state_source_mismatch() -> HTTPException:
    return HTTPException(
        status_code=400,
        detail="OAuth state does not match the requested mail source.",
    )


def _signed_oauth_state_workspace_id(state_value: str, source_id: int) -> int:
    parts = state_value.split(".")
    if len(parts) != 3:
        raise _invalid_oauth_state()

    encoded_payload, encoded_signature = parts[1], parts[2]
    expected_signature = _oauth_state_signature(encoded_payload)
    try:
        actual_signature = _base64url_decode(encoded_signature)
        payload = json.loads(_base64url_decode(encoded_payload))
        workspace_id = int(payload["workspace_id"])
        state_source_id = int(payload["source_id"])
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        raise _invalid_oauth_state() from None

    if not hmac.compare_digest(actual_signature, expected_signature):
        raise _invalid_oauth_state()
    if state_source_id != int(source_id):
        raise _oauth_state_source_mismatch()
    return workspace_id


def _legacy_oauth_state_workspace_id(state_value: str, source_id: int) -> Optional[int]:
    # Legacy states from older authorization URLs are accepted only when they
    # bind to the callback source id; they are not treated as trusted workspace
    # selectors.
    parts = state_value.split(":")
    if len(parts) == 4 and parts[0] == "workspace" and parts[2] == "source":
        try:
            workspace_id = int(parts[1])
            state_source_id = int(parts[3])
        except ValueError:
            raise _invalid_oauth_state() from None
        if state_source_id != int(source_id):
            raise _oauth_state_source_mismatch()
        return workspace_id

    if state_value.isdigit():
        if int(state_value) != int(source_id):
            raise _oauth_state_source_mismatch()
        return None

    raise _invalid_oauth_state()


def _workspace_id_from_oauth_state(
    state_value: Optional[str],
    source_id: int,
) -> Optional[int]:
    """Return a workspace id from OAuth state after validating source binding."""
    if not state_value:
        return None

    if state_value.startswith("v1."):
        return _signed_oauth_state_workspace_id(state_value, source_id)
    return _legacy_oauth_state_workspace_id(state_value, source_id)


def _audit_mail_source_change(
    db: Session,
    *,
    workspace,
    source: MailSource,
    action: str,
    auth_context: Dict[str, Any],
    request: Request,
    details: Optional[Dict[str, Any]] = None,
) -> None:
    record_workspace_audit_log(
        db,
        workspace=workspace,
        action=action,
        entity_type="mail_source",
        entity_id=source.id,
        entity_name=source.name,
        details=details or {"method": source.method},
        auth_context=auth_context,
        request=request,
        commit=True,
    )


def _safe_attr(source: MailSource, name: str, default: Any = None) -> Any:
    """Read optional source attributes without letting test doubles invent fields."""
    value = getattr(source, name, default)
    if value.__class__.__module__.startswith("unittest.mock"):
        return default
    return value


def _source_to_response(source: MailSource) -> MailSourceResponse:
    """Convert ORM row to response schema, masking the stored password."""
    return MailSourceResponse(
        id=source.id,
        name=source.name,
        method=source.method,
        server=source.server,
        port=source.port or 993,
        username=source.username,
        password="**redacted**" if source.password else None,
        use_ssl=source.use_ssl if source.use_ssl is not None else True,
        folder=source.folder or "INBOX",
        polling_interval=source.polling_interval or 60,
        enabled=source.enabled if source.enabled is not None else True,
        last_checked=source.last_checked,
        created_at=source.created_at,
        updated_at=source.updated_at,
        gmail_client_id=source.gmail_client_id,
        gmail_client_secret="**redacted**" if source.gmail_client_secret else None,
        gmail_email=source.gmail_email,
        gmail_connected=bool(source.gmail_access_token),
        m365_tenant_id=_safe_attr(source, "m365_tenant_id", "common") or "common",
        m365_client_id=_safe_attr(source, "m365_client_id"),
        m365_client_secret=("**redacted**" if _safe_attr(source, "m365_client_secret") else None),
        m365_mailbox=_safe_attr(source, "m365_mailbox"),
        m365_folder_id=_safe_attr(source, "m365_folder_id"),
        m365_email=_safe_attr(source, "m365_email"),
        m365_connected=bool(_safe_attr(source, "m365_access_token")),
    )


def _decode_json_list(value: Optional[str]) -> List[str]:
    """Decode a JSON list stored on import history rows."""
    if not value:
        return []
    try:
        decoded = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(decoded, list):
        return []
    return [str(item) for item in decoded]


def _decode_json_details(value: Optional[str]) -> List[Dict[str, str]]:
    """Decode a sanitized JSON detail list stored on import history rows."""
    if not value:
        return []
    try:
        decoded = json.loads(value)
    except (json.JSONDecodeError, TypeError):
        return []
    if not isinstance(decoded, list):
        return []

    details: List[Dict[str, str]] = []
    for item in decoded:
        if isinstance(item, dict):
            details.append({str(key): str(val) for key, val in item.items()})
    return details


def _import_to_response(row: MailSourceImport) -> MailSourceImportResponse:
    """Convert an import-history ORM row to an API response."""
    return MailSourceImportResponse(
        id=row.id,
        mail_source_id=row.mail_source_id,
        trigger=row.trigger,
        status=row.status,
        processed=row.processed,
        reports_found=row.reports_found,
        duplicate_reports=row.duplicate_reports,
        error_count=row.error_count,
        new_domains=_decode_json_list(row.new_domains),
        errors=_decode_json_list(row.errors),
        details=_decode_json_details(row.details),
        started_at=row.started_at,
        finished_at=row.finished_at,
        created_at=row.created_at,
    )


def _fetch_response(source: MailSource, results: Dict[str, Any]) -> Dict[str, Any]:
    """Build the common response payload for a manual source fetch."""
    diagnostic = import_result_diagnostic(results)
    return {
        "source_id": source.id,
        "name": source.name,
        "success": bool(results.get("success", False)),
        "processed": int(results.get("processed", 0)),
        "reports_found": int(results.get("reports_found", 0)),
        "duplicate_reports": int(results.get("duplicate_reports", 0)),
        "forensic_reports_found": int(results.get("forensic_reports_found", 0)),
        "duplicate_forensic_reports": int(results.get("duplicate_forensic_reports", 0)),
        "new_domains": [str(d) for d in results.get("new_domains", [])],
        "error_count": len(results.get("errors", [])),
        "target_mailbox": results.get("target_mailbox"),
        "target_folder": results.get("target_folder"),
        "search_window_days": results.get("search_window_days"),
        "diagnostic": diagnostic,
        "diagnostic_category": diagnostic["category"],
        "diagnostic_summary": diagnostic["summary"],
        "recovery_steps": diagnostic["recovery_steps"],
        "timestamp": datetime.now().isoformat(),
    }


def _fetch_gmail_source(source: MailSource, db: Session) -> Dict[str, Any]:
    """Run one Gmail API import and persist source/import metadata."""
    if not source.gmail_access_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Gmail account not yet authorised. Complete OAuth2 flow first.",
        )

    already = GmailClient.load_ingested_ids(source.gmail_ingested_ids)
    client = GmailClient(
        client_id=source.gmail_client_id or "",
        client_secret=source.gmail_client_secret or "",
        access_token=source.gmail_access_token,
        refresh_token=source.gmail_refresh_token or "",
        already_ingested_ids=already,
        db=db,
    )

    started_at = datetime.utcnow()
    results = client.fetch_reports()

    if results.get("new_ingested_ids"):
        all_ids = list(dict.fromkeys(already + results["new_ingested_ids"]))
        source.gmail_ingested_ids = GmailClient.dump_ingested_ids(all_ids)

    refreshed = client.get_refreshed_tokens()
    if refreshed:
        source.gmail_access_token = refreshed["access_token"]
        if "refresh_token" in refreshed:
            source.gmail_refresh_token = refreshed["refresh_token"]

    source.last_checked = datetime.utcnow()
    record_import_attempt(db, source, results, started_at=started_at, trigger="manual")
    db.commit()
    return results


def _fetch_m365_source(source: MailSource, db: Session, days: int = 7) -> Dict[str, Any]:
    """Run one Microsoft 365 Graph import and persist source/import metadata."""
    if not source.m365_access_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Microsoft 365 account not yet authorised. Complete OAuth2 flow first.",
        )

    already = MicrosoftGraphClient.load_ingested_ids(source.m365_ingested_ids)
    client = MicrosoftGraphClient(
        tenant_id=source.m365_tenant_id or "common",
        client_id=source.m365_client_id or "",
        client_secret=source.m365_client_secret or "",
        access_token=source.m365_access_token,
        refresh_token=source.m365_refresh_token or "",
        mailbox=source.m365_mailbox,
        folder=source.folder or "INBOX",
        folder_id=_safe_attr(source, "m365_folder_id"),
        already_ingested_ids=already,
        db=db,
    )

    started_at = datetime.utcnow()
    results = client.fetch_reports(days=days)

    if results.get("new_ingested_ids"):
        all_ids = list(dict.fromkeys(already + results["new_ingested_ids"]))
        source.m365_ingested_ids = MicrosoftGraphClient.dump_ingested_ids(all_ids)

    refreshed = client.get_refreshed_tokens()
    if refreshed:
        source.m365_access_token = refreshed["access_token"]
        if "refresh_token" in refreshed:
            source.m365_refresh_token = refreshed["refresh_token"]

    source.last_checked = datetime.utcnow()
    record_import_attempt(db, source, results, started_at=started_at, trigger="manual")
    db.commit()
    return results


def _fetch_imap_source(source: MailSource, db: Session, days: int) -> Dict[str, Any]:
    """Run one IMAP import and persist source/import metadata."""
    client = IMAPClient(
        server=source.server,
        port=source.port or 993,
        username=source.username,
        password=source.password,
        folder=source.folder,
        db=db,
    )
    started_at = datetime.utcnow()
    results = client.fetch_reports(days=days)
    source.last_checked = datetime.utcnow()
    record_import_attempt(db, source, results, started_at=started_at, trigger="manual")
    db.commit()
    return results


def _fetch_source(source: MailSource, db: Session, days: int) -> Dict[str, Any]:
    """Dispatch a manual fetch for one configured mail source."""
    if source.method == "GMAIL_API":
        return _fetch_gmail_source(source, db)
    if source.method == "M365_GRAPH":
        return _fetch_m365_source(source, db, days=days)
    if source.method == "IMAP":
        return _fetch_imap_source(source, db, days)
    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail=f"Manual fetch is not available for method '{source.method}'.",
    )


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("", response_model=List[MailSourceResponse])
async def list_mail_sources(
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> List[MailSourceResponse]:
    """Return all configured mail sources (passwords redacted)."""
    workspace = _authorized_mail_source_workspace(
        _auth,
        db,
        _selected_workspace_id(selected_workspace),
    )
    sources = workspace_mail_source_query(db, workspace).order_by(MailSource.id).all()
    return [_source_to_response(s) for s in sources]


@router.post("", response_model=MailSourceResponse, status_code=status.HTTP_201_CREATED)
async def create_mail_source(
    payload: MailSourceCreate,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> MailSourceResponse:
    """Create a new mail source."""
    workspace = _authorized_mail_source_workspace(
        _auth,
        db,
        _selected_workspace_id(selected_workspace),
    )
    source = MailSource(
        workspace_id=workspace.id,
        name=payload.name,
        method=payload.method.upper(),
        server=payload.server,
        port=payload.port,
        username=payload.username,
        password=payload.password,
        use_ssl=payload.use_ssl,
        folder=payload.folder,
        polling_interval=payload.polling_interval,
        enabled=payload.enabled,
        gmail_client_id=payload.gmail_client_id,
        gmail_client_secret=payload.gmail_client_secret,
        m365_tenant_id=payload.m365_tenant_id or "common",
        m365_client_id=payload.m365_client_id,
        m365_client_secret=payload.m365_client_secret,
        m365_mailbox=payload.m365_mailbox,
        m365_folder_id=payload.m365_folder_id,
    )
    db.add(source)
    db.commit()
    db.refresh(source)
    _audit_mail_source_change(
        db,
        workspace=workspace,
        source=source,
        action="mail_source.created",
        auth_context=_auth,
        request=request,
        details={"method": source.method, "enabled": source.enabled},
    )
    logger.info(
        "Created mail source id=%d name=%r method=%r", source.id, source.name, source.method
    )
    return _source_to_response(source)


@router.get("/{source_id}", response_model=MailSourceResponse)
async def get_mail_source(
    source_id: int,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> MailSourceResponse:
    """Return a single mail source by ID (password redacted)."""
    workspace = _authorized_mail_source_workspace(
        _auth,
        db,
        _selected_workspace_id(selected_workspace),
    )
    source = _get_source_or_404(source_id, db, workspace)
    return _source_to_response(source)


@router.get("/{source_id}/imports", response_model=List[MailSourceImportResponse])
async def list_mail_source_imports(
    source_id: int,
    limit: int = 20,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> List[MailSourceImportResponse]:
    """Return recent sanitized import attempts for one mail source."""
    workspace = _authorized_mail_source_workspace(
        _auth,
        db,
        _selected_workspace_id(selected_workspace),
    )
    _get_source_or_404(source_id, db, workspace)
    safe_limit = min(max(limit, 1), 100)
    rows = (
        db.query(MailSourceImport)
        .filter(MailSourceImport.mail_source_id == source_id)
        .order_by(MailSourceImport.started_at.desc(), MailSourceImport.id.desc())
        .limit(safe_limit)
        .all()
    )
    return [_import_to_response(row) for row in rows]


@router.post("/{source_id}/fetch", response_model=Dict[str, Any])
async def fetch_mail_source(
    source_id: int,
    days: int = 7,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """Manually fetch DMARC reports for one configured mail source."""
    if days < 1 or days > 365:
        raise HTTPException(status_code=400, detail="Days parameter must be between 1 and 365")

    workspace = _authorized_mail_source_workspace(
        _auth, db, _selected_workspace_id(selected_workspace)
    )
    source = _get_source_or_404(source_id, db, workspace)
    results = _fetch_source(source, db, days)
    logger.info(
        "Manual fetch for source id=%d: processed=%d reports_found=%d "
        "forensic_reports_found=%d duplicates=%d",
        int(source_id),
        int(results.get("processed", 0)),
        int(results.get("reports_found", 0)),
        int(results.get("forensic_reports_found", 0)),
        int(results.get("duplicate_reports", 0)),
    )
    for err in results.get("errors", []):
        logger.warning(
            "Manual fetch warning for source id=%d: %s",
            int(source_id),
            _redact_sensitive_text(err),
        )

    return _fetch_response(source, results)  # lgtm[py/stack-trace-exposure]


@router.put("/{source_id}", response_model=MailSourceResponse)
async def update_mail_source(
    source_id: int,
    payload: MailSourceUpdate,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> MailSourceResponse:
    """Update one or more fields of an existing mail source."""
    workspace = _authorized_mail_source_workspace(
        _auth, db, _selected_workspace_id(selected_workspace)
    )
    source = _get_source_or_404(source_id, db, workspace)

    update_data = payload.model_dump(exclude_unset=True)
    if "method" in update_data and update_data["method"]:
        update_data["method"] = update_data["method"].upper()

    for field, value in update_data.items():
        setattr(source, field, value)

    source.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(source)
    _audit_mail_source_change(
        db,
        workspace=workspace,
        source=source,
        action="mail_source.updated",
        auth_context=_auth,
        request=request,
        details={"changed_fields": changed_fields(update_data), "method": source.method},
    )
    logger.info("Updated mail source id=%d", source.id)
    return _source_to_response(source)


@router.delete("/{source_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_mail_source(
    source_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> None:
    """Delete a mail source permanently."""
    workspace = _authorized_mail_source_workspace(
        _auth, db, _selected_workspace_id(selected_workspace)
    )
    source = _get_source_or_404(source_id, db, workspace)
    source_name = source.name
    source_method = source.method
    db.delete(source)
    db.commit()
    record_workspace_audit_log(
        db,
        workspace=workspace,
        action="mail_source.deleted",
        entity_type="mail_source",
        entity_id=source_id,
        entity_name=source_name,
        details={"method": source_method},
        auth_context=_auth,
        request=request,
        commit=True,
    )
    logger.info("Deleted mail source id=%s", _sanitize_for_log(source_id))


@router.post("/{source_id}/toggle", response_model=MailSourceResponse)
async def toggle_mail_source(
    source_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> MailSourceResponse:
    """Toggle the *enabled* flag of a mail source."""
    workspace = _authorized_mail_source_workspace(
        _auth, db, _selected_workspace_id(selected_workspace)
    )
    source = _get_source_or_404(source_id, db, workspace)
    source.enabled = not source.enabled
    source.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(source)
    _audit_mail_source_change(
        db,
        workspace=workspace,
        source=source,
        action="mail_source.toggled",
        auth_context=_auth,
        request=request,
        details={"enabled": source.enabled},
    )
    return _source_to_response(source)


@router.post("/{source_id}/test", response_model=Dict[str, Any])
async def test_stored_mail_source(  # noqa: C901
    source_id: int,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """Test the connection for an already-stored mail source using its saved credentials."""
    workspace = _authorized_mail_source_workspace(
        _auth, db, _selected_workspace_id(selected_workspace)
    )
    source = _get_source_or_404(source_id, db, workspace)

    if source.method == "GMAIL_API":
        if not source.gmail_access_token:
            return _connection_test_response(
                False,
                "Gmail API source is not yet authorised. "
                "Use the Connect Gmail button to complete OAuth2 authorisation.",
            )
        try:
            gmail_client = GmailClient(
                client_id=source.gmail_client_id or "",
                client_secret=source.gmail_client_secret or "",
                access_token=source.gmail_access_token,
                refresh_token=source.gmail_refresh_token or "",
            )
            # Attempt to list one message to verify the credentials work
            service = gmail_client._build_service()  # pylint: disable=protected-access
            service.users().getProfile(userId="me").execute()
            source.last_checked = datetime.utcnow()
            db.commit()
            return _connection_test_response(
                True,
                f"Gmail API credentials are valid (account: {source.gmail_email or 'unknown'}).",
            )
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.error(
                "Gmail API test failed for source id=%d: %s",
                int(source_id),
                _redact_sensitive_text(exc),
            )
            return _connection_test_response(
                False,
                "Gmail API test failed. The saved authorization may need attention.",
                details=exc,
            )

    if source.method == "M365_GRAPH":
        if not source.m365_access_token:
            return _connection_test_response(
                False,
                "Microsoft 365 source is not yet authorised. "
                "Use the Connect Microsoft 365 button to complete OAuth2 authorisation.",
            )
        try:
            graph_client = MicrosoftGraphClient(
                tenant_id=source.m365_tenant_id or "common",
                client_id=source.m365_client_id or "",
                client_secret=source.m365_client_secret or "",
                access_token=source.m365_access_token,
                refresh_token=source.m365_refresh_token or "",
                mailbox=source.m365_mailbox,
                folder=source.folder or "INBOX",
                folder_id=_safe_attr(source, "m365_folder_id"),
            )
            stats = graph_client.test_connection()
            refreshed = graph_client.get_refreshed_tokens()
            if refreshed:
                source.m365_access_token = refreshed["access_token"]
                if "refresh_token" in refreshed:
                    source.m365_refresh_token = refreshed["refresh_token"]
            source.last_checked = datetime.utcnow()
            db.commit()
            return _connection_test_response(
                True,
                f"Microsoft 365 credentials are valid (account: {source.m365_email or 'unknown'}).",
                stats=stats,
            )
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.error(
                "Microsoft 365 Graph test failed for source id=%d: %s",
                int(source_id),
                _redact_sensitive_text(exc),
            )
            return _connection_test_response(
                False,
                "Microsoft 365 test failed. The saved authorization may need attention.",
                details=exc,
            )

    if source.method != "IMAP":
        return _connection_test_response(
            False,
            f"Connection testing for method '{source.method}' is not yet implemented.",
        )

    imap_client = IMAPClient(
        server=source.server,
        port=source.port or 993,
        username=source.username,
        password=source.password,
        folder=source.folder,
    )
    success, message, stats = imap_client.test_connection()

    if success:
        source.last_checked = datetime.utcnow()
        db.commit()

    return _connection_test_response(success, message, stats)


@router.post("/test-connection", response_model=Dict[str, Any])
async def test_connection_adhoc(
    request: TestConnectionRequest,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """
    Test a connection using ad-hoc credentials (not stored in the database).

    Useful when filling out the *add/edit mail source* form before saving.
    """
    _authorized_mail_source_workspace(_auth, db, _selected_workspace_id(selected_workspace))
    method = request.method.upper()

    if method != "IMAP":
        return _connection_test_response(
            False,
            f"Connection testing for method '{method}' is not yet implemented.",
        )

    imap_client = IMAPClient(
        server=request.server,
        port=request.port,
        username=request.username,
        password=request.password,
    )
    success, message, stats = imap_client.test_connection()

    return _connection_test_response(success, message, stats)


# ---------------------------------------------------------------------------
# Microsoft 365 / Graph OAuth2 routes
# ---------------------------------------------------------------------------


@router.get("/{source_id}/m365/authorize-url", response_model=Dict[str, Any])
async def m365_authorize_url(
    source_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """Return a Microsoft identity platform authorization URL for M365_GRAPH."""
    workspace = _authorized_mail_source_workspace(
        _auth, db, _selected_workspace_id(selected_workspace)
    )
    source = _get_source_or_404(source_id, db, workspace)

    if source.method != "M365_GRAPH":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This endpoint is only available for M365_GRAPH sources.",
        )
    if not source.m365_client_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="m365_client_id is not configured for this source.",
        )

    base_url = str(request.base_url).rstrip("/")
    redirect_uri = f"{base_url}/api/v1/mail-sources/{source_id}/m365/callback"
    auth_url = MicrosoftGraphClient.build_authorization_url(
        tenant_id=source.m365_tenant_id or "common",
        client_id=source.m365_client_id,
        redirect_uri=redirect_uri,
        state=_oauth_state(workspace.id, source_id),
    )
    return {"authorization_url": auth_url, "redirect_uri": redirect_uri}


@router.get("/{source_id}/m365/folders", response_model=Dict[str, Any])
async def m365_list_folders(
    source_id: int,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """Return selectable Microsoft 365 mail folders for this source."""
    workspace = _authorized_mail_source_workspace(
        _auth, db, _selected_workspace_id(selected_workspace)
    )
    source = _get_source_or_404(source_id, db, workspace)

    if source.method != "M365_GRAPH":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This endpoint is only available for M365_GRAPH sources.",
        )
    if not source.m365_access_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Microsoft 365 account not yet authorised. Complete OAuth2 flow first.",
        )

    graph_client = MicrosoftGraphClient(
        tenant_id=source.m365_tenant_id or "common",
        client_id=source.m365_client_id or "",
        client_secret=source.m365_client_secret or "",
        access_token=source.m365_access_token,
        refresh_token=source.m365_refresh_token or "",
        mailbox=source.m365_mailbox,
        folder=source.folder or "INBOX",
        folder_id=_safe_attr(source, "m365_folder_id"),
    )

    try:
        folders = graph_client.list_mail_folders()
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error(
            "Microsoft 365 folder listing failed for source id=%d: %s",
            int(source_id),
            _redact_sensitive_text(exc),
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Could not load Microsoft 365 folders. Confirm the authorised "
                "account can read the selected mailbox."
            ),
        ) from exc

    refreshed = graph_client.get_refreshed_tokens()
    if refreshed:
        source.m365_access_token = refreshed["access_token"]
        if "refresh_token" in refreshed:
            source.m365_refresh_token = refreshed["refresh_token"]
        db.commit()

    return {
        "target_mailbox": source.m365_mailbox or source.m365_email or "authorized account",
        "selected_folder_id": _safe_attr(source, "m365_folder_id"),
        "selected_folder": source.folder or "INBOX",
        "folders": folders,
    }


@router.get("/{source_id}/m365/callback")
async def m365_oauth_callback(
    source_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Any:
    """Handle the Microsoft identity platform OAuth2 redirect."""
    from fastapi.responses import HTMLResponse

    code = request.query_params.get("code")
    error = request.query_params.get("error")

    if error or not code:
        html = (
            "<html><body><p>Microsoft 365 authorisation failed: "
            f"{error or 'no code received'}. "
            "You may close this window.</p></body></html>"
        )
        return HTMLResponse(content=html, status_code=400)

    workspace = _authorized_mail_source_workspace(
        _auth,
        db,
        _selected_workspace_or_oauth_state(
            selected_workspace,
            request.query_params.get("state"),
            source_id,
        ),
    )
    source = _get_source_or_404(source_id, db, workspace)
    if source.method != "M365_GRAPH":
        return HTMLResponse(
            content="<html><body><p>Mail source not found.</p></body></html>",
            status_code=404,
        )

    base_url = str(request.base_url).rstrip("/")
    redirect_uri = f"{base_url}/api/v1/mail-sources/{source_id}/m365/callback"

    try:
        token_data = MicrosoftGraphClient.exchange_code_for_tokens(
            tenant_id=source.m365_tenant_id or "common",
            client_id=source.m365_client_id or "",
            client_secret=source.m365_client_secret or "",
            code=code,
            redirect_uri=redirect_uri,
        )
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error(
            "Microsoft 365 token exchange error for source id=%d: %s",
            int(source_id),
            _redact_sensitive_text(exc),
        )
        html = (
            "<html><body><p>Token exchange failed. "
            "Please close this window and try again.</p></body></html>"
        )
        return HTMLResponse(content=html, status_code=400)

    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")
    if not access_token:
        return HTMLResponse(
            content="<html><body><p>No access token returned by Microsoft.</p></body></html>",
            status_code=400,
        )

    m365_email = MicrosoftGraphClient.get_account_email(access_token)
    source.m365_access_token = access_token
    if refresh_token:
        source.m365_refresh_token = refresh_token
    if m365_email:
        source.m365_email = m365_email
    source.updated_at = datetime.utcnow()
    db.commit()

    logger.info(
        "Microsoft 365 OAuth2 authorisation complete for source id=%d (account=%s)",
        int(source_id),
        _sanitize_for_log(m365_email or "unknown"),
    )

    html = (
        "<html><body>"
        "<p>Microsoft 365 account connected successfully"
        f"{(' (' + m365_email + ')') if m365_email else ''}. "
        "You may close this window.</p>"
        "<script>window.close();</script>"
        "</body></html>"
    )
    return HTMLResponse(content=html)


@router.post("/{source_id}/m365/callback", response_model=MailSourceResponse)
async def m365_oauth_callback_post(
    source_id: int,
    payload: M365CallbackRequest,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> MailSourceResponse:
    """Exchange a Microsoft OAuth2 authorization code for Graph tokens."""
    workspace = _authorized_mail_source_workspace(
        _auth, db, _selected_workspace_id(selected_workspace)
    )
    source = _get_source_or_404(source_id, db, workspace)

    if source.method != "M365_GRAPH":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This endpoint is only available for M365_GRAPH sources.",
        )

    try:
        token_data = MicrosoftGraphClient.exchange_code_for_tokens(
            tenant_id=source.m365_tenant_id or "common",
            client_id=source.m365_client_id or "",
            client_secret=source.m365_client_secret or "",
            code=payload.code,
            redirect_uri=payload.redirect_uri,
        )
    except Exception as exc:  # pylint: disable=broad-exception-caught
        logger.error(
            "Microsoft 365 token exchange error for source id=%d: %s",
            int(source_id),
            _redact_sensitive_text(exc),
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Token exchange failed. Please check the Microsoft 365 "
                "connection settings and try again."
            ),
        ) from exc

    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")
    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Microsoft did not return an access token.",
        )

    m365_email = MicrosoftGraphClient.get_account_email(access_token)
    source.m365_access_token = access_token
    if refresh_token:
        source.m365_refresh_token = refresh_token
    if m365_email:
        source.m365_email = m365_email
    source.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(source)
    _audit_mail_source_change(
        db,
        workspace=workspace,
        source=source,
        action="mail_source.m365_connected",
        auth_context=_auth,
        request=request,
        details={"account": m365_email or "unknown"},
    )

    logger.info(
        "Microsoft 365 OAuth2 tokens saved for source id=%d (account=%s)",
        int(source_id),
        _sanitize_for_log(m365_email or "unknown"),
    )
    return _source_to_response(source)


@router.post("/{source_id}/m365/fetch", response_model=Dict[str, Any])
async def m365_fetch_reports(
    source_id: int,
    days: int = Query(7, ge=1, le=365, title="Number of days to fetch"),
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """Manually trigger a Microsoft 365 Graph DMARC report fetch."""
    workspace = _authorized_mail_source_workspace(
        _auth, db, _selected_workspace_id(selected_workspace)
    )
    source = _get_source_or_404(source_id, db, workspace)

    if source.method != "M365_GRAPH":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This endpoint is only available for M365_GRAPH sources.",
        )

    results = _fetch_m365_source(source, db, days=days)
    logger.info(
        "Microsoft 365 fetch for source id=%d: processed=%d reports_found=%d",
        int(source_id),
        int(results.get("processed", 0)),
        int(results.get("reports_found", 0)),
    )
    for err in results.get("errors", []):
        logger.warning(
            "Microsoft 365 fetch warning for source id=%d: %s",
            int(source_id),
            _redact_sensitive_text(err),
        )

    return _fetch_response(source, results)  # lgtm[py/stack-trace-exposure]


@router.delete("/{source_id}/m365/connection", status_code=status.HTTP_204_NO_CONTENT)
async def m365_disconnect(
    source_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> None:
    """Clear the stored Microsoft Graph OAuth2 tokens for this source."""
    workspace = _authorized_mail_source_workspace(
        _auth, db, _selected_workspace_id(selected_workspace)
    )
    source = _get_source_or_404(source_id, db, workspace)

    if source.method != "M365_GRAPH":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This endpoint is only available for M365_GRAPH sources.",
        )

    source.m365_access_token = None
    source.m365_refresh_token = None
    source.m365_email = None
    source.updated_at = datetime.utcnow()
    db.commit()
    _audit_mail_source_change(
        db,
        workspace=workspace,
        source=source,
        action="mail_source.m365_disconnected",
        auth_context=_auth,
        request=request,
    )
    logger.info("Microsoft 365 tokens cleared for source id=%d", int(source_id))


# ---------------------------------------------------------------------------
# Gmail API OAuth2 routes
# ---------------------------------------------------------------------------


@router.get("/{source_id}/gmail/authorize-url", response_model=Dict[str, Any])
async def gmail_authorize_url(
    source_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """
    Return a Google OAuth2 authorization URL for the given GMAIL_API source.

    The frontend should redirect the user to this URL.  After the user
    grants access Google redirects back to
    ``<origin>/mail-sources/<id>/gmail/callback`` with a ``code`` parameter.
    """
    workspace = _authorized_mail_source_workspace(
        _auth, db, _selected_workspace_id(selected_workspace)
    )
    source = _get_source_or_404(source_id, db, workspace)

    if source.method != "GMAIL_API":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This endpoint is only available for GMAIL_API sources.",
        )
    if not source.gmail_client_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="gmail_client_id is not configured for this source.",
        )

    # Build a redirect_uri that points back to this server's callback endpoint
    base_url = str(request.base_url).rstrip("/")
    redirect_uri = f"{base_url}/api/v1/mail-sources/{source_id}/gmail/callback"

    auth_url = GmailClient.build_authorization_url(
        client_id=source.gmail_client_id,
        redirect_uri=redirect_uri,
        state=_oauth_state(workspace.id, source_id),
    )
    return {
        "authorization_url": auth_url,
        "redirect_uri": redirect_uri,
    }


@router.get("/{source_id}/gmail/callback")
async def gmail_oauth_callback(
    source_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Any:
    """
    Handle the Google OAuth2 redirect after the user grants Gmail access.

    Exchanges the authorization ``code`` query parameter for access/refresh
    tokens and stores them on the MailSource row after the user's authenticated
    workspace access has been verified.
    """
    from fastapi.responses import HTMLResponse

    code = request.query_params.get("code")
    error = request.query_params.get("error")

    if error or not code:
        html = (
            "<html><body><p>Gmail authorisation failed: "
            f"{error or 'no code received'}. "
            "You may close this window.</p></body></html>"
        )
        return HTMLResponse(content=html, status_code=400)

    workspace = _authorized_mail_source_workspace(
        _auth,
        db,
        _selected_workspace_or_oauth_state(
            selected_workspace,
            request.query_params.get("state"),
            source_id,
        ),
    )
    source = _get_source_or_404(source_id, db, workspace)
    if source.method != "GMAIL_API":
        return HTMLResponse(
            content="<html><body><p>Mail source not found.</p></body></html>",
            status_code=404,
        )

    base_url = str(request.base_url).rstrip("/")
    redirect_uri = f"{base_url}/api/v1/mail-sources/{source_id}/gmail/callback"

    try:
        token_data = GmailClient.exchange_code_for_tokens(
            client_id=source.gmail_client_id or "",
            client_secret=source.gmail_client_secret or "",
            code=code,
            redirect_uri=redirect_uri,
        )
    except ValueError as exc:
        logger.error(
            "Gmail token exchange error for source id=%d: %s",
            int(source_id),
            _redact_sensitive_text(exc),
        )
        html = (
            "<html><body><p>Token exchange failed. "
            "Please close this window and try again.</p></body></html>"
        )
        return HTMLResponse(content=html, status_code=400)

    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")

    if not access_token:
        return HTMLResponse(
            content="<html><body><p>No access token returned by Google.</p></body></html>",
            status_code=400,
        )

    gmail_email = GmailClient.get_gmail_email(access_token)

    source.gmail_access_token = access_token
    if refresh_token:
        source.gmail_refresh_token = refresh_token
    if gmail_email:
        source.gmail_email = gmail_email
    source.updated_at = datetime.utcnow()
    db.commit()

    logger.info(
        "Gmail OAuth2 authorisation complete for source id=%d (account=%s)",
        int(source_id),
        _sanitize_for_log(gmail_email or "unknown"),
    )

    html = (
        "<html><body>"
        "<p>✅ Gmail account connected successfully"
        f"{(' (' + gmail_email + ')') if gmail_email else ''}. "
        "You may close this window.</p>"
        "<script>window.close();</script>"
        "</body></html>"
    )
    return HTMLResponse(content=html)


@router.post("/{source_id}/gmail/callback", response_model=MailSourceResponse)
async def gmail_oauth_callback_post(
    source_id: int,
    payload: GmailCallbackRequest,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> MailSourceResponse:
    """
    Exchange an OAuth2 authorization code for tokens (JSON / programmatic flow).

    This POST variant is for clients that handle the OAuth2 redirect
    themselves and post the code here as JSON.  Requires the standard
    admin authentication.
    """
    workspace = _authorized_mail_source_workspace(
        _auth, db, _selected_workspace_id(selected_workspace)
    )
    source = _get_source_or_404(source_id, db, workspace)

    if source.method != "GMAIL_API":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This endpoint is only available for GMAIL_API sources.",
        )

    try:
        token_data = GmailClient.exchange_code_for_tokens(
            client_id=source.gmail_client_id or "",
            client_secret=source.gmail_client_secret or "",
            code=payload.code,
            redirect_uri=payload.redirect_uri,
        )
    except ValueError as exc:
        logger.error(
            "Gmail token exchange error for source id=%d: %s",
            int(source_id),
            _redact_sensitive_text(exc),
        )
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "Token exchange failed. Please check the Gmail connection settings "
                "and try again."
            ),
        ) from exc

    access_token = token_data.get("access_token")
    refresh_token = token_data.get("refresh_token")

    if not access_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Google did not return an access token.",
        )

    gmail_email = GmailClient.get_gmail_email(access_token)

    source.gmail_access_token = access_token
    if refresh_token:
        source.gmail_refresh_token = refresh_token
    if gmail_email:
        source.gmail_email = gmail_email
    source.updated_at = datetime.utcnow()
    db.commit()
    db.refresh(source)
    _audit_mail_source_change(
        db,
        workspace=workspace,
        source=source,
        action="mail_source.gmail_connected",
        auth_context=_auth,
        request=request,
        details={"account": gmail_email or "unknown"},
    )

    logger.info(
        "Gmail OAuth2 tokens saved for source id=%d (account=%s)",
        int(source_id),
        _sanitize_for_log(gmail_email or "unknown"),
    )
    return _source_to_response(source)


@router.post("/{source_id}/gmail/fetch", response_model=Dict[str, Any])
async def gmail_fetch_reports(
    source_id: int,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> Dict[str, Any]:
    """
    Manually trigger a Gmail DMARC report fetch for the given source.

    Searches Gmail for emails matching the DMARC report heuristic, ingests
    any attachments not yet seen, and returns a summary.
    """
    workspace = _authorized_mail_source_workspace(
        _auth, db, _selected_workspace_id(selected_workspace)
    )
    source = _get_source_or_404(source_id, db, workspace)

    if source.method != "GMAIL_API":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This endpoint is only available for GMAIL_API sources.",
        )
    if not source.gmail_access_token:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Gmail account not yet authorised. Complete OAuth2 flow first.",
        )

    already = GmailClient.load_ingested_ids(source.gmail_ingested_ids)
    client = GmailClient(
        client_id=source.gmail_client_id or "",
        client_secret=source.gmail_client_secret or "",
        access_token=source.gmail_access_token,
        refresh_token=source.gmail_refresh_token or "",
        already_ingested_ids=already,
        db=db,
    )

    started_at = datetime.utcnow()
    results = client.fetch_reports()

    # Persist updated ingested IDs and any refreshed tokens
    if results.get("new_ingested_ids"):
        all_ids = list(dict.fromkeys(already + results["new_ingested_ids"]))
        source.gmail_ingested_ids = GmailClient.dump_ingested_ids(all_ids)

    refreshed = client.get_refreshed_tokens()
    if refreshed:
        source.gmail_access_token = refreshed["access_token"]
        if "refresh_token" in refreshed:
            source.gmail_refresh_token = refreshed["refresh_token"]

    source.last_checked = datetime.utcnow()
    record_import_attempt(db, source, results, started_at=started_at, trigger="manual")
    db.commit()

    logger.info(
        "Gmail fetch for source id=%d: processed=%d reports_found=%d forensic_reports_found=%d",
        int(source_id),
        int(results.get("processed", 0)),
        int(results.get("reports_found", 0)),
        int(results.get("forensic_reports_found", 0)),
    )

    for err in results.get("errors", []):
        logger.warning(
            "Gmail fetch warning for source id=%d: %s",
            int(source_id),
            _redact_sensitive_text(err),
        )

    return {
        "success": bool(results.get("success", False)),
        "processed": int(results.get("processed", 0)),
        "reports_found": int(results.get("reports_found", 0)),
        "forensic_reports_found": int(results.get("forensic_reports_found", 0)),
        "duplicate_forensic_reports": int(results.get("duplicate_forensic_reports", 0)),
        "new_domains": [str(d) for d in results.get("new_domains", [])],
        "error_count": len(results.get("errors", [])),
        "timestamp": datetime.now().isoformat(),
    }


@router.delete("/{source_id}/gmail/connection", status_code=status.HTTP_204_NO_CONTENT)
async def gmail_disconnect(
    source_id: int,
    request: Request,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_admin_auth),
    selected_workspace: Optional[str] = Header(default=None, alias="X-DMARQ-Workspace-ID"),
) -> None:
    """Revoke / clear the stored Gmail OAuth2 tokens for this source."""
    workspace = _authorized_mail_source_workspace(
        _auth, db, _selected_workspace_id(selected_workspace)
    )
    source = _get_source_or_404(source_id, db, workspace)

    if source.method != "GMAIL_API":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This endpoint is only available for GMAIL_API sources.",
        )

    source.gmail_access_token = None
    source.gmail_refresh_token = None
    source.gmail_email = None
    source.updated_at = datetime.utcnow()
    db.commit()
    _audit_mail_source_change(
        db,
        workspace=workspace,
        source=source,
        action="mail_source.gmail_disconnected",
        auth_context=_auth,
        request=request,
    )
    logger.info("Gmail tokens cleared for source id=%d", int(source_id))
