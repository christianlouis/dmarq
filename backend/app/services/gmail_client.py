"""
Gmail API client for retrieving DMARC reports.

Connects to Gmail via OAuth 2.0, searches for emails that are likely to
contain DMARC aggregate-report attachments, and processes any new ones.
Already-ingested message IDs are tracked so the same email is never
processed twice (no messages are modified or deleted).
"""

import base64
import email
import logging
from typing import Any, Dict, List, Optional
from urllib.parse import urlencode

import httpx
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

from app.services.dmarc_parser import DMARCParser
from app.services.forensic_parser import ForensicParser
from app.services.forensic_persistence import forensic_report_exists, save_forensic_report
from app.services.forensic_redaction import get_forensic_redaction_policy
from app.services.mail_connector import (
    append_import_detail,
    connector_failure_stats,
    dump_ingested_ids,
    initial_import_stats,
    load_ingested_ids,
    sanitize_connector_error,
)
from app.services.report_persistence import report_exists, save_parsed_report
from app.services.report_store import ReportStore

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# OAuth2 scopes – read-only access to Gmail messages is all we need
# ---------------------------------------------------------------------------

GMAIL_SCOPES = [
    "https://www.googleapis.com/auth/gmail.readonly",
]

# ---------------------------------------------------------------------------
# Gmail search query used to find emails likely containing DMARC reports.
#
# Strategy:
#   • Require at least one attachment whose name ends in .zip, .gz, or .xml
#     (the three formats used by virtually every DMARC sender).
#   • Additionally require *either* a keyword in the subject that DMARC senders
#     use, or an envelope-from that belongs to a well-known DMARC reporting
#     address.  This keeps false-positive rates low while catching reports
#     from providers that don't follow naming conventions perfectly.
# ---------------------------------------------------------------------------

DMARC_GMAIL_QUERY = (
    "((has:attachment (filename:zip OR filename:gz OR filename:xml)) "
    'OR subject:"DMARC failure" OR subject:"failure report" OR subject:forensic OR subject:ruf) '
    "(subject:dmarc OR subject:report OR subject:rua OR subject:submitter "
    'OR subject:"aggregate report" OR subject:"domain report" '
    'OR subject:"report domain" OR from:dmarc OR from:dmarc-noreply '
    "OR from:noreply-dmarc-support OR from:reports OR from:postmaster)"
)

# How many message results to fetch per API page
_PAGE_SIZE = 100
RETRYABLE_MESSAGE_FAILURE = -1


class GmailClient:
    """
    Client for retrieving DMARC reports from a Gmail account via the Gmail API.

    OAuth2 tokens are accepted at construction time and auto-refreshed when
    expired.  The caller is responsible for persisting any refreshed tokens
    returned by :meth:`get_refreshed_tokens`.
    """

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        access_token: str,
        refresh_token: str,
        already_ingested_ids: Optional[List[str]] = None,
        db: Any = None,
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self._initial_access_token = access_token
        self.already_ingested_ids: List[str] = list(already_ingested_ids or [])
        self.report_store = ReportStore.get_instance()
        self.db = db

        self.credentials = Credentials(
            token=access_token,
            refresh_token=refresh_token,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=client_id,
            client_secret=client_secret,
            scopes=GMAIL_SCOPES,
        )

    # ------------------------------------------------------------------
    # Public helpers
    # ------------------------------------------------------------------

    def get_refreshed_tokens(self) -> Optional[Dict[str, str]]:
        """
        Return updated tokens if the google-auth library has refreshed them.

        Call this after :meth:`fetch_reports` and persist any non-None result
        so the next run doesn't need an extra refresh round-trip.
        """
        current = self.credentials.token
        if current and current != self._initial_access_token:
            result: Dict[str, str] = {"access_token": current}
            if self.credentials.refresh_token:
                result["refresh_token"] = self.credentials.refresh_token
            return result
        return None

    # ------------------------------------------------------------------
    # OAuth2 helpers (static / class methods used by the endpoint layer)
    # ------------------------------------------------------------------

    @staticmethod
    def build_authorization_url(
        client_id: str,
        redirect_uri: str,
        state: Optional[str] = None,
    ) -> str:
        """
        Construct the Google OAuth2 authorization URL.

        Requests offline access so a refresh token is issued, and forces
        the consent screen so the refresh token is always returned even if
        the user has authorised this app before.
        """
        params: Dict[str, str] = {
            "client_id": client_id,
            "response_type": "code",
            "scope": " ".join(GMAIL_SCOPES),
            "redirect_uri": redirect_uri,
            "access_type": "offline",
            "prompt": "consent",
        }
        if state:
            params["state"] = state
        return "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)

    @staticmethod
    def exchange_code_for_tokens(
        client_id: str,
        client_secret: str,
        code: str,
        redirect_uri: str,
    ) -> Dict[str, Any]:
        """
        Synchronously exchange an authorization code for access+refresh tokens.

        Returns the raw JSON from Google's token endpoint.  The caller
        should check for ``access_token`` in the result before using it.

        Raises:
            ValueError: if Google returns a non-200 response.
        """
        resp = httpx.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": client_id,
                "client_secret": client_secret,
                "redirect_uri": redirect_uri,
                "grant_type": "authorization_code",
            },
        )
        if resp.status_code != 200:
            raise ValueError(f"Token exchange failed ({resp.status_code}): {resp.text}")
        return resp.json()

    @staticmethod
    def get_gmail_email(access_token: str) -> Optional[str]:
        """
        Return the email address associated with an access token.

        Uses the OAuth2 userinfo endpoint.  Returns None on failure.
        """
        try:
            resp = httpx.get(
                "https://www.googleapis.com/oauth2/v2/userinfo",
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if resp.status_code == 200:
                return resp.json().get("email")
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.error("Failed to fetch Gmail email address: %s", exc)
        return None

    # ------------------------------------------------------------------
    # Core fetching logic
    # ------------------------------------------------------------------

    def fetch_reports(self) -> Dict[str, Any]:
        """
        Search Gmail for DMARC report emails and ingest any new ones.

        Emails that have already been ingested (tracked via
        ``already_ingested_ids``) are silently skipped.  No messages are
        modified or deleted.

        Returns:
            A dict with keys ``success``, ``processed``, ``reports_found``,
            ``new_domains``, ``errors``, and ``new_ingested_ids`` (the IDs
            added in this run so the caller can persist them).
        """
        stats = initial_import_stats()

        try:
            service = self._build_service()
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.error("Gmail API: failed to build service: %s", exc)
            return connector_failure_stats(stats, "Failed to initialize Gmail API.", error=exc)

        try:
            message_ids = self._list_dmarc_message_ids(service)
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.error("Gmail API: failed to list messages: %s", exc)
            return connector_failure_stats(stats, "Failed to list Gmail messages.", error=exc)

        domains_before = set(self.report_store.get_domains())

        for msg_id in message_ids:
            if msg_id in self.already_ingested_ids:
                self._append_detail(
                    stats,
                    status="skipped",
                    reason="already_ingested_message",
                    message_id=msg_id,
                )
                continue

            stats["processed"] += 1
            found = self._process_message(service, msg_id, stats)
            if found >= 0:
                # Track it even when no report is found so we don't re-examine
                # unrelated messages on every poll. Retryable failures return -1.
                stats["new_ingested_ids"].append(msg_id)
                self.already_ingested_ids.append(msg_id)

        domains_after = set(self.report_store.get_domains())
        stats["new_domains"] = list(domains_after - domains_before)
        return stats

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_service(self):
        """Build (and auto-refresh if needed) the Gmail API service object."""
        if self.credentials.expired and self.credentials.refresh_token:
            try:
                self.credentials.refresh(Request())
            except Exception as exc:  # pylint: disable=broad-exception-caught
                logger.error("Gmail token refresh failed: %s", exc)
                raise

        return build("gmail", "v1", credentials=self.credentials, cache_discovery=False)

    def _list_dmarc_message_ids(self, service) -> List[str]:
        """Return all Gmail message IDs matching the DMARC search query."""
        ids: List[str] = []
        page_token: Optional[str] = None

        while True:
            kwargs: Dict[str, Any] = {
                "userId": "me",
                "q": DMARC_GMAIL_QUERY,
                "maxResults": _PAGE_SIZE,
            }
            if page_token:
                kwargs["pageToken"] = page_token

            try:
                result = service.users().messages().list(**kwargs).execute()
            except HttpError as exc:
                logger.error("Gmail API list error: %s", exc)
                raise

            for msg in result.get("messages", []):
                ids.append(msg["id"])

            page_token = result.get("nextPageToken")
            if not page_token:
                break

        return ids

    @staticmethod
    def _append_detail(stats: dict, **detail: str) -> None:
        """Append a compact attachment/message outcome to the import stats."""
        append_import_detail(stats, **detail)

    def _process_message(self, service, msg_id: str, stats: dict) -> int:
        """
        Download a Gmail message and process any DMARC-report attachments.

        Returns the number of DMARC reports found in this message.
        """
        try:
            msg_data = (
                service.users().messages().get(userId="me", id=msg_id, format="raw").execute()
            )
        except HttpError as exc:
            logger.error("Gmail API: failed to fetch message %s: %s", msg_id, exc)
            stats["errors"].append(sanitize_connector_error(f"Failed to fetch message {msg_id}"))
            self._append_detail(
                stats,
                status="error",
                reason="message_fetch_failed",
                message_id=msg_id,
            )
            return 0

        raw_bytes = base64.urlsafe_b64decode(msg_data.get("raw", ""))
        msg = email.message_from_bytes(raw_bytes)
        if ForensicParser.is_forensic_report(msg):
            return self._process_forensic_message(raw_bytes, stats, message_id=msg_id)
        return self._process_attachments(msg, stats, message_id=msg_id)

    @staticmethod
    def _decode_part_filename(part: email.message.Message) -> str:
        """Return the decoded filename for a MIME part (handles RFC 2047 encoding)."""
        from email.header import decode_header

        raw_name = part.get_filename() or ""
        decoded_parts = []
        for fragment, charset in decode_header(raw_name):
            if isinstance(fragment, bytes):
                decoded_parts.append(fragment.decode(charset or "utf-8", errors="replace"))
            else:
                decoded_parts.append(fragment)
        return "".join(decoded_parts)

    @staticmethod
    def _is_dmarc_attachment(filename: str) -> bool:
        """Return True if *filename* looks like a DMARC aggregate-report file."""
        lower = filename.lower()
        return (
            lower.endswith(".xml")
            or lower.endswith(".zip")
            or lower.endswith(".gz")
            or lower.endswith(".gzip")
        )

    def _store_report_if_new(self, report: Dict[str, Any]) -> bool:
        """Store a parsed report unless that domain/report ID is already present."""
        domain = report.get("domain", "unknown")
        report_id = report.get("report_id", "")
        if report_id and (
            self.report_store.has_report(domain, report_id)
            or (self.db is not None and report_exists(self.db, domain, report_id))
        ):
            logger.info("Skipping duplicate DMARC report %s for %s", report_id, domain)
            return False

        if self.db is not None:
            save_parsed_report(self.db, report)
        self.report_store.add_report(report)
        return True

    def _process_forensic_message(
        self,
        raw_bytes: bytes,
        stats: dict,
        message_id: Optional[str] = None,
    ) -> int:
        """Parse and persist one DMARC forensic report message."""
        try:
            report = ForensicParser.parse_bytes(
                raw_bytes,
                message_id_hint=message_id,
                redaction_policy=get_forensic_redaction_policy(self.db),
            )
            report_id = str(report.get("report_id", ""))
            domain = str(report.get("reported_domain") or "unknown")

            if self.db is None:
                self._append_detail(
                    stats,
                    status="skipped",
                    reason="forensic_report_requires_database",
                    message_id=message_id,
                    domain=domain,
                    report_id=report_id,
                )
                return RETRYABLE_MESSAGE_FAILURE

            if forensic_report_exists(self.db, report_id):
                stats["duplicate_forensic_reports"] = stats.get("duplicate_forensic_reports", 0) + 1
                self._append_detail(
                    stats,
                    status="duplicate",
                    reason="duplicate_forensic_report",
                    message_id=message_id,
                    domain=domain,
                    report_id=report_id,
                )
                return 0

            _row, created = save_forensic_report(self.db, report)
            if not created:
                stats["duplicate_forensic_reports"] = stats.get("duplicate_forensic_reports", 0) + 1
                self._append_detail(
                    stats,
                    status="duplicate",
                    reason="duplicate_forensic_report",
                    message_id=message_id,
                    domain=domain,
                    report_id=report_id,
                )
                return 0

            stats["forensic_reports_found"] = stats.get("forensic_reports_found", 0) + 1
            self._append_detail(
                stats,
                status="imported",
                reason="forensic_report",
                message_id=message_id,
                domain=domain,
                report_id=report_id,
            )
            return 1
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.error("Failed to parse Gmail forensic report %s: %s", message_id, exc)
            stats.setdefault("errors", []).append(
                sanitize_connector_error(f"Failed to parse forensic report {message_id}: {exc}")
            )
            self._append_detail(
                stats,
                status="error",
                reason="forensic_parse_failed",
                message_id=message_id,
                error=str(exc),
            )
            return RETRYABLE_MESSAGE_FAILURE

    def _process_attachments(
        self,
        msg: email.message.Message,
        stats: dict,
        message_id: Optional[str] = None,
    ) -> int:
        """Walk a parsed email message and extract DMARC report attachments."""
        reports_found = 0

        for part in msg.walk():
            filename = self._decode_part_filename(part)
            if not filename:
                continue

            disposition = part.get_content_disposition()
            if disposition not in ("attachment", None):
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

            content = part.get_payload(decode=True)
            if not content:
                self._append_detail(
                    stats,
                    status="skipped",
                    reason="empty_attachment",
                    message_id=message_id,
                    filename=filename,
                )
                continue

            try:
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
                logger.error("Failed to parse DMARC attachment %s: %s", filename, exc)
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

    # ------------------------------------------------------------------
    # Convenience: load / save ingested IDs from/to the JSON text column
    # ------------------------------------------------------------------

    @staticmethod
    def load_ingested_ids(json_text: Optional[str]) -> List[str]:
        """Deserialise the gmail_ingested_ids text column into a list."""
        return load_ingested_ids(json_text)

    @staticmethod
    def dump_ingested_ids(ids: List[str]) -> str:
        """Serialise the list of ingested IDs back to a JSON string."""
        return dump_ingested_ids(ids)
