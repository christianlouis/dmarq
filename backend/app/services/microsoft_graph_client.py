"""Microsoft Graph client for retrieving DMARC aggregate reports."""

import base64
import logging
import time
from datetime import datetime, timedelta
from typing import Any, Callable, Dict, Iterable, List, Optional
from urllib.parse import quote, urlencode

import httpx

from app.services.dmarc_parser import DMARCParser
from app.services.mail_connector import (
    ConnectorImportContext,
    MailSourceConnector,
    append_import_detail,
    clamp_search_window,
    connector_failure_stats,
    dump_ingested_ids,
    initial_import_stats,
    load_ingested_ids,
    sanitize_connector_error,
)
from app.services.report_persistence import report_exists, save_parsed_report
from app.services.report_store import ReportStore

logger = logging.getLogger(__name__)

GRAPH_BASE_URL = "https://graph.microsoft.com/v1.0"
LOGIN_BASE_URL = "https://login.microsoftonline.com"

M365_SCOPES = [
    "offline_access",
    "https://graph.microsoft.com/User.Read",
    "https://graph.microsoft.com/Mail.Read",
    "https://graph.microsoft.com/Mail.Read.Shared",
]

_PAGE_SIZE = 100
_MAX_FOLDER_DEPTH = 5
_MAX_GRAPH_RETRIES = 3
_MAX_RETRY_DELAY_SECONDS = 30
_RETRYABLE_STATUS_CODES = {429, 503, 504}
_DMARC_SUBJECT_TERMS = (
    "dmarc",
    "aggregate report",
    "domain report",
    "report domain",
    "rua",
    "submitter",
)
_DMARC_SENDER_TERMS = (
    "dmarc",
    "reports",
    "postmaster",
)


class MicrosoftGraphError(RuntimeError):
    """Raised when Microsoft Graph or the token endpoint returns a failure."""


class MicrosoftGraphClient(MailSourceConnector):
    """
    Retrieve DMARC aggregate reports from Microsoft 365 through Microsoft Graph.

    The client uses delegated OAuth tokens and read-only Graph scopes. Messages
    are never modified or deleted; already-ingested Graph message IDs are stored
    by the caller to avoid reprocessing the same email.
    """

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        access_token: str,
        refresh_token: str,
        mailbox: Optional[str] = None,
        folder: str = "inbox",
        folder_id: Optional[str] = None,
        already_ingested_ids: Optional[List[str]] = None,
        db: Any = None,
        workspace_id: Optional[int] = None,
        sleep: Optional[Callable[[float], None]] = None,
    ):
        self.tenant_id = tenant_id or "common"
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.mailbox = (mailbox or "").strip()
        self.folder = folder or "inbox"
        self.folder_id = (folder_id or "").strip()
        self.already_ingested_ids: List[str] = list(already_ingested_ids or [])
        self.report_store = ReportStore.get_instance()
        self.db = db
        self.workspace_id = workspace_id
        self._sleep = sleep or time.sleep
        self._refreshed_tokens: Optional[Dict[str, str]] = None

    def get_refreshed_tokens(self) -> Optional[Dict[str, str]]:
        """Return refreshed OAuth tokens, if a request had to refresh them."""
        return self._refreshed_tokens

    @staticmethod
    def build_authorization_url(
        tenant_id: str,
        client_id: str,
        redirect_uri: str,
        state: Optional[str] = None,
    ) -> str:
        """Build a Microsoft identity platform authorization-code URL."""
        tenant = quote(tenant_id or "common", safe="")
        params: Dict[str, str] = {
            "client_id": client_id,
            "response_type": "code",
            "redirect_uri": redirect_uri,
            "response_mode": "query",
            "scope": " ".join(M365_SCOPES),
            "prompt": "select_account",
        }
        if state:
            params["state"] = state
        return f"{LOGIN_BASE_URL}/{tenant}/oauth2/v2.0/authorize?" + urlencode(params)

    @staticmethod
    def exchange_code_for_tokens(
        tenant_id: str,
        client_id: str,
        client_secret: str,
        code: str,
        redirect_uri: str,
    ) -> Dict[str, Any]:
        """Exchange an authorization code for Microsoft Graph tokens."""
        data = {
            "client_id": client_id,
            "client_secret": client_secret,
            "code": code,
            "redirect_uri": redirect_uri,
            "grant_type": "authorization_code",
            "scope": " ".join(M365_SCOPES),
        }
        resp = httpx.post(MicrosoftGraphClient._token_url(tenant_id), data=data, timeout=30)
        if resp.status_code != 200:
            raise MicrosoftGraphError(
                f"Microsoft token exchange failed ({resp.status_code}): {resp.text}"
            )
        return resp.json()

    @staticmethod
    def get_account_email(access_token: str) -> Optional[str]:
        """Return the mailbox identity exposed by Graph /me for an access token."""
        try:
            resp = httpx.get(
                f"{GRAPH_BASE_URL}/me",
                headers={"Authorization": f"Bearer {access_token}"},
                params={"$select": "mail,userPrincipalName"},
                timeout=30,
            )
            if resp.status_code == 200:
                profile = resp.json()
                return profile.get("mail") or profile.get("userPrincipalName")
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.error("Failed to fetch Microsoft 365 account email: %s", exc)
        return None

    @staticmethod
    def load_ingested_ids(json_text: Optional[str]) -> List[str]:
        """Deserialize the m365_ingested_ids text column into a list."""
        return load_ingested_ids(json_text)

    @staticmethod
    def dump_ingested_ids(ids: List[str]) -> str:
        """Serialize Graph message IDs for database storage."""
        return dump_ingested_ids(ids)

    def test_connection(self) -> Dict[str, Any]:
        """Verify that the saved delegated token can read the target mailbox."""
        data = self._request(
            "GET",
            self._messages_path(),
            params={"$top": 1, "$select": "id"},
        )
        return {
            "success": True,
            "message_count": len(data.get("value", [])),
            "target_mailbox": self._target_mailbox_label(),
            "target_folder": self._target_folder_label(),
            "diagnostic_detail": "Microsoft Graph mailbox read succeeded.",
        }

    def list_mail_folders(self) -> List[Dict[str, str]]:
        """Return selectable mail folders for the configured mailbox."""
        folders: List[Dict[str, str]] = []
        self._collect_mail_folders(
            f"{self._mailbox_path()}/mailFolders",
            folders,
            parent_path="",
            depth=0,
        )
        return folders

    def _collect_mail_folders(
        self,
        start_url: str,
        folders: List[Dict[str, str]],
        *,
        parent_path: str,
        depth: int,
    ) -> None:
        params: Optional[Dict[str, Any]] = {
            "$top": _PAGE_SIZE,
            "$select": "id,displayName,parentFolderId,childFolderCount",
        }
        url: Optional[str] = start_url

        while url:
            data = self._request("GET", url, params=params)
            for folder in data.get("value", []):
                folder_id = str(folder.get("id") or "")
                display_name = str(folder.get("displayName") or folder_id)
                if not folder_id:
                    continue
                folder_path = f"{parent_path} / {display_name}" if parent_path else display_name
                folders.append(
                    {
                        "id": folder_id,
                        "display_name": display_name,
                        "path": folder_path,
                        "parent_folder_id": str(folder.get("parentFolderId") or ""),
                    }
                )
                if int(folder.get("childFolderCount") or 0) > 0 and depth < _MAX_FOLDER_DEPTH:
                    self._collect_mail_folders(
                        f"{self._mailbox_path()}/mailFolders/{quote(folder_id, safe='')}/childFolders",
                        folders,
                        parent_path=folder_path,
                        depth=depth + 1,
                    )
            url = data.get("@odata.nextLink")
            params = None

    def import_context(self, days: Optional[int] = None) -> ConnectorImportContext:
        """Return safe Microsoft 365 import context for API responses/history."""
        return ConnectorImportContext(
            source_type="M365_GRAPH",
            mailbox=self._target_mailbox_label(),
            folder=self._target_folder_label(),
            search_window_days=days,
        )

    def search_messages(self, days: int) -> Iterable[Dict[str, Any]]:
        """Return Microsoft Graph messages that look like DMARC reports."""
        return self._list_dmarc_messages(days=days)

    def iter_attachments(self, message: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
        """Yield Microsoft Graph attachments for one message."""
        message_id = str(message.get("id") or "")
        return self._list_attachments(message_id)

    def fetch_reports(self, days: int = 7) -> Dict[str, Any]:
        """Fetch and ingest DMARC report attachments from Microsoft Graph."""
        safe_days = clamp_search_window(days)
        stats = initial_import_stats(self.import_context(days=safe_days))

        try:
            messages = self.search_messages(days=safe_days)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.error("Microsoft Graph: failed to list messages: %s", exc)
            return connector_failure_stats(
                stats, "Failed to list Microsoft Graph messages.", error=exc
            )

        domains_before = set(self.report_store.get_domains())

        for message in messages:
            message_id = str(message.get("id") or "")
            if not message_id:
                continue
            if message_id in self.already_ingested_ids:
                self._append_detail(
                    stats,
                    status="skipped",
                    reason="already_ingested_message",
                    message_id=message_id,
                )
                continue

            stats["processed"] += 1
            found = self._process_message(message, stats)
            if found >= 0:
                stats["new_ingested_ids"].append(message_id)
                self.already_ingested_ids.append(message_id)

        domains_after = set(self.report_store.get_domains())
        stats["new_domains"] = list(domains_after - domains_before)
        return stats

    @staticmethod
    def _token_url(tenant_id: str) -> str:
        tenant = quote(tenant_id or "common", safe="")
        return f"{LOGIN_BASE_URL}/{tenant}/oauth2/v2.0/token"

    def _append_detail(self, stats: dict, **detail: str) -> None:
        append_import_detail(stats, context=self.import_context(), **detail)

    def _target_mailbox_label(self) -> str:
        return self.mailbox or "authorized account"

    def _target_folder_label(self) -> str:
        if self.folder:
            return self.folder
        if self.folder_id:
            return self.folder_id
        return "All messages"

    def _mailbox_path(self) -> str:
        if not self.mailbox or self.mailbox.lower() == "me":
            return "/me"
        return f"/users/{quote(self.mailbox, safe='')}"

    def _messages_path(self) -> str:
        mailbox_path = self._mailbox_path()
        if self.folder_id:
            return f"{mailbox_path}/mailFolders/{quote(self.folder_id, safe='')}/messages"
        folder = (self.folder or "").strip()
        if not folder:
            return f"{mailbox_path}/messages"
        if folder.upper() == "INBOX":
            folder = "inbox"
        return f"{mailbox_path}/mailFolders/{quote(folder, safe='')}/messages"

    def _headers(self) -> Dict[str, str]:
        return {"Authorization": f"Bearer {self.access_token}"}

    def _request(
        self,
        method: str,
        path_or_url: str,
        *,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        url = path_or_url if path_or_url.startswith("http") else f"{GRAPH_BASE_URL}{path_or_url}"
        resp: Optional[httpx.Response] = None

        for attempt in range(_MAX_GRAPH_RETRIES + 1):
            resp = httpx.request(method, url, headers=self._headers(), params=params, timeout=30)
            if resp.status_code == 401 and self.refresh_token:
                self._refresh_access_token()
                resp = httpx.request(
                    method, url, headers=self._headers(), params=params, timeout=30
                )
            if resp.status_code in _RETRYABLE_STATUS_CODES and attempt < _MAX_GRAPH_RETRIES:
                delay = self._retry_delay_seconds(resp, attempt)
                logger.warning(
                    "Microsoft Graph request throttled/unavailable; retrying in %.1fs",
                    delay,
                )
                self._sleep(delay)
                continue
            break

        if resp is None:
            raise MicrosoftGraphError("Microsoft Graph request failed before receiving a response.")
        if resp.status_code < 200 or resp.status_code >= 300:
            raise MicrosoftGraphError(self._format_error(resp))
        return resp.json() if resp.content else {}

    @staticmethod
    def _retry_delay_seconds(resp: httpx.Response, attempt: int) -> float:
        retry_after = resp.headers.get("Retry-After")
        if retry_after:
            try:
                return min(float(retry_after), _MAX_RETRY_DELAY_SECONDS)
            except ValueError:
                pass
        return min(float(2**attempt), _MAX_RETRY_DELAY_SECONDS)

    def _refresh_access_token(self) -> None:
        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "refresh_token": self.refresh_token,
            "grant_type": "refresh_token",
            "scope": " ".join(M365_SCOPES),
        }
        resp = httpx.post(self._token_url(self.tenant_id), data=data, timeout=30)
        if resp.status_code != 200:
            raise MicrosoftGraphError(
                f"Microsoft token refresh failed ({resp.status_code}): {resp.text}"
            )
        token_data = resp.json()
        access_token = token_data.get("access_token")
        if not access_token:
            raise MicrosoftGraphError("Microsoft token refresh did not return an access token.")
        self.access_token = access_token
        refreshed = {"access_token": access_token}
        if token_data.get("refresh_token"):
            self.refresh_token = token_data["refresh_token"]
            refreshed["refresh_token"] = token_data["refresh_token"]
        self._refreshed_tokens = refreshed

    @staticmethod
    def _format_error(resp: httpx.Response) -> str:
        try:
            payload = resp.json()
        except ValueError:
            payload = {}
        message = payload.get("error_description")
        if not message and isinstance(payload.get("error"), dict):
            message = payload["error"].get("message")
            code = payload["error"].get("code")
            if code:
                message = f"{code}: {message}" if message else code
        return message or f"Microsoft Graph request failed ({resp.status_code}): {resp.text}"

    @staticmethod
    def _looks_like_dmarc_message(message: Dict[str, Any]) -> bool:
        if not message.get("hasAttachments"):
            return False
        subject = str(message.get("subject") or "").lower()
        sender = (
            ((message.get("from") or {}).get("emailAddress") or {}).get("address") or ""
        ).lower()
        return any(term in subject for term in _DMARC_SUBJECT_TERMS) or any(
            term in sender for term in _DMARC_SENDER_TERMS
        )

    @staticmethod
    def _is_dmarc_attachment(filename: str) -> bool:
        lower = filename.lower()
        return (
            lower.endswith(".xml")
            or lower.endswith(".zip")
            or lower.endswith(".gz")
            or lower.endswith(".gzip")
        )

    def _list_dmarc_messages(self, days: int) -> List[Dict[str, Any]]:
        messages: List[Dict[str, Any]] = []
        url = self._messages_path()
        cutoff = datetime.utcnow() - timedelta(days=days)
        params: Optional[Dict[str, Any]] = {
            "$top": _PAGE_SIZE,
            "$select": "id,subject,from,hasAttachments,receivedDateTime",
            "$orderby": "receivedDateTime desc",
            "$filter": f"receivedDateTime ge {cutoff.strftime('%Y-%m-%dT%H:%M:%SZ')}",
        }

        while url:
            data = self._request("GET", url, params=params)
            for message in data.get("value", []):
                if self._looks_like_dmarc_message(message):
                    messages.append(message)
            url = data.get("@odata.nextLink")
            params = None

        return messages

    def _process_message(self, message: Dict[str, Any], stats: Dict[str, Any]) -> int:
        message_id = str(message.get("id") or "")
        try:
            attachments = self._list_attachments(message_id)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.error("Microsoft Graph: failed to fetch attachments for %s: %s", message_id, exc)
            stats["errors"].append(
                sanitize_connector_error(
                    f"Failed to fetch attachments for message {message_id}: {exc}"
                )
            )
            self._append_detail(
                stats,
                status="error",
                reason="attachment_fetch_failed",
                message_id=message_id,
                error=str(exc),
            )
            return -1
        return self._process_attachments(message_id, attachments, stats)

    def _list_attachments(self, message_id: str) -> List[Dict[str, Any]]:
        mailbox_path = self._mailbox_path()
        data = self._request(
            "GET",
            f"{mailbox_path}/messages/{quote(message_id, safe='')}/attachments",
        )
        return list(data.get("value", []))

    def _store_report_if_new(self, report: Dict[str, Any]) -> bool:
        domain = report.get("domain", "unknown")
        report_id = report.get("report_id", "")
        if report_id and (
            self.report_store.has_report(domain, report_id)
            or (
                self.db is not None
                and report_exists(self.db, domain, report_id, workspace_id=self.workspace_id)
            )
        ):
            logger.info("Skipping duplicate DMARC report %s for %s", report_id, domain)
            return False

        if self.db is not None:
            save_parsed_report(self.db, report, workspace_id=self.workspace_id)
        self.report_store.add_report(report)
        return True

    def _process_attachments(
        self,
        message_id: str,
        attachments: List[Dict[str, Any]],
        stats: Dict[str, Any],
    ) -> int:
        reports_found = 0

        for attachment in attachments:
            filename = str(attachment.get("name") or "")
            if not filename:
                continue
            if not self._is_dmarc_attachment(filename):
                self._append_detail(
                    stats,
                    status="skipped",
                    reason="unsupported_attachment",
                    message_id=message_id,
                    filename=filename,
                )
                continue

            attachment_type = str(attachment.get("@odata.type") or "").lower()
            if "fileattachment" not in attachment_type:
                self._append_detail(
                    stats,
                    status="skipped",
                    reason="unsupported_attachment_type",
                    message_id=message_id,
                    filename=filename,
                )
                continue

            content_b64 = attachment.get("contentBytes")
            if not content_b64:
                self._append_detail(
                    stats,
                    status="skipped",
                    reason="empty_attachment",
                    message_id=message_id,
                    filename=filename,
                )
                continue

            try:
                content = base64.b64decode(content_b64)
                report = DMARCParser.parse_file(content, filename)
                domain = str(report.get("domain", "unknown"))
                report_id = str(report.get("report_id", ""))
                if self._store_report_if_new(report):
                    stats["reports_found"] += 1
                    reports_found += 1
                    self._append_detail(
                        stats,
                        status="imported",
                        message_id=message_id,
                        filename=filename,
                        domain=domain,
                        report_id=report_id,
                    )
                else:
                    stats["duplicate_reports"] = stats.get("duplicate_reports", 0) + 1
                    self._append_detail(
                        stats,
                        status="duplicate",
                        message_id=message_id,
                        filename=filename,
                        domain=domain,
                        report_id=report_id,
                    )
            except Exception as exc:  # pylint: disable=broad-exception-caught
                logger.error("Failed to parse Graph DMARC attachment %s: %s", filename, exc)
                stats["errors"].append(
                    sanitize_connector_error(f"Failed to parse {filename}: {exc}")
                )
                self._append_detail(
                    stats,
                    status="error",
                    reason="parse_failed",
                    message_id=message_id,
                    filename=filename,
                    error=str(exc),
                )

        return reports_found
