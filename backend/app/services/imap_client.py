import email
import imaplib
import logging
from datetime import datetime, timedelta
from email.header import decode_header
from typing import Any, Dict, Optional, Tuple

from app.core.config import get_settings
from app.services.dmarc_parser import DMARCParser
from app.services.forensic_parser import ForensicParser
from app.services.forensic_persistence import forensic_report_exists, save_forensic_report
from app.services.forensic_redaction import get_forensic_redaction_policy
from app.services.mail_connector import (
    append_import_detail,
    initial_import_stats,
    sanitize_connector_error,
)
from app.services.report_persistence import report_exists, save_parsed_report
from app.services.report_store import ReportStore

# Setup logger
logger = logging.getLogger(__name__)


class IMAPClient:
    """
    Client for retrieving DMARC reports from an IMAP mailbox
    """

    def __init__(  # pylint: disable=too-many-positional-arguments,too-many-arguments
        self,
        server: str = None,
        port: int = None,
        username: str = None,
        password: str = None,
        delete_emails: Optional[bool] = None,
        folder: str = None,
        db: Any = None,
    ):
        """
        Initialize the IMAP client with credentials

        Args:
            server: IMAP server hostname (if None, uses settings)
            port: IMAP server port (if None, uses settings)
            username: IMAP username (if None, uses settings)
            password: IMAP password (if None, uses settings)
            delete_emails: Whether to delete emails after successful report imports.
                If omitted, uses DELETE_IMPORTED_EMAILS from settings.
            folder: IMAP mailbox folder to read (if None, uses settings or INBOX)
            db: Optional SQLAlchemy session used to persist imported reports
        """
        settings = get_settings()
        settings_folder = getattr(settings, "IMAP_FOLDER", None)
        if not isinstance(settings_folder, str):
            settings_folder = None

        self.server = server or settings.IMAP_SERVER
        self.port = port or settings.IMAP_PORT
        self.username = username or settings.IMAP_USERNAME
        self.password = password or settings.IMAP_PASSWORD
        configured_delete = getattr(settings, "DELETE_IMPORTED_EMAILS", False)
        if not isinstance(configured_delete, bool):
            configured_delete = False
        self.delete_emails = configured_delete if delete_emails is None else delete_emails
        self.folder = folder or settings_folder or "INBOX"
        self.db = db

        self.report_store = ReportStore.get_instance()

        if not all([self.server, self.username, self.password]):
            logger.warning("IMAP credentials not fully configured")

    def _quoted_folder(self) -> str:
        escaped = self.folder.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'

    def _list_mailboxes(self, mailbox_data: list) -> list:
        """Parse the raw IMAP LIST response into a list of mailbox name strings."""
        available_mailboxes = []
        for mailbox in mailbox_data:
            if isinstance(mailbox, bytes):
                try:
                    mailbox_str = mailbox.decode("utf-8")
                    # Extract the mailbox name (after the last quote)
                    parts = mailbox_str.split('"')
                    if len(parts) > 2:
                        mailbox_name = parts[-1].strip()
                        if mailbox_name.startswith(" "):
                            mailbox_name = mailbox_name[1:]
                        available_mailboxes.append(mailbox_name)
                except Exception:  # pylint: disable=broad-exception-caught
                    # Silently skip mailboxes that can't be parsed; they are simply
                    # omitted from the returned list so callers should expect it may
                    # be incomplete.  Some IMAP servers return non-standard list
                    # responses or use different delimiters/encodings that don't follow
                    # RFC 3501 (special characters, non-UTF-8 encodings, malformed
                    # responses).  This is expected behaviour and not a critical error.
                    pass  # nosec B110
        return available_mailboxes

    def test_connection(self) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Test the IMAP connection and gather basic mailbox statistics

        Returns:
            Tuple of (success, message, stats)
            - success: Boolean indicating if connection was successful
            - message: String message describing the result
            - stats: Dictionary with mailbox statistics (if successful)
        """
        if not all([self.server, self.username, self.password]):
            return (
                False,
                "IMAP credentials not fully configured.",
                {"diagnostic_detail": "missing server, username, or password"},
            )

        try:
            # Create IMAP4 connection
            mail = imaplib.IMAP4_SSL(self.server, self.port)
            # Login
            mail.login(self.username, self.password)

            # List available mailboxes
            status, mailbox_list = mail.list()
            available_mailboxes = self._list_mailboxes(mailbox_list) if status == "OK" else []

            # Select configured mailbox and get message count
            status, data = mail.select(self._quoted_folder())
            message_count = 0
            unread_count = 0

            if status != "OK":
                mail.logout()
                return (
                    False,
                    "Configured mailbox folder could not be opened.",
                    {
                        "available_mailboxes": available_mailboxes,
                        "diagnostic_detail": f"select failed for folder {self.folder}",
                    },
                )

            message_count = int(data[0])

            # Count unread messages
            status, data = mail.search(None, "UNSEEN")
            if status == "OK":
                unread_count = len(data[0].split())

            # Gather some stats about potential DMARC reports
            dmarc_count = 0
            status, data = mail.search(None, 'SUBJECT "DMARC"')
            if status == "OK":
                dmarc_count = len(data[0].split())

            # Close connection
            mail.close()
            mail.logout()

            stats = {
                "message_count": message_count,
                "unread_count": unread_count,
                "dmarc_count": dmarc_count,
                "available_mailboxes": available_mailboxes,
                "server": self.server,
                "port": self.port,
                "timestamp": datetime.now().isoformat(),
            }

            return True, "Connection successful", stats
        except imaplib.IMAP4.error as e:
            logger.error("IMAP connection test failed: %s", str(e))
            return (
                False,
                "IMAP authentication failed or the mailbox server rejected the request.",
                {"diagnostic_detail": str(e)},
            )
        except (TimeoutError, OSError) as e:
            logger.error("IMAP connection test failed: %s", str(e))
            return (
                False,
                "Could not reach the IMAP server.",
                {"diagnostic_detail": str(e)},
            )
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("IMAP connection test failed: %s", str(e))
            return (
                False,
                "Connection failed. Check mailbox settings and try again.",
                {"diagnostic_detail": str(e)},
            )

    def _process_single_email(self, mail, email_id: bytes, stats: dict) -> None:
        """Fetch, parse, and store DMARC attachments from one email message."""
        message_id = email_id.decode("utf-8", errors="replace")
        try:
            status, msg_data = mail.fetch(email_id, "(RFC822)")
            if status != "OK":
                logger.error("Error fetching email ID %s", email_id)
                self._append_detail(
                    stats,
                    status="error",
                    reason="message_fetch_failed",
                    message_id=message_id,
                )
                return

            raw_email = msg_data[0][1]
            msg = email.message_from_bytes(raw_email)

            if ForensicParser.is_forensic_report(msg):
                imported = self._process_forensic_email(
                    raw_email,
                    stats=stats,
                    message_id=message_id,
                )
                mail.store(email_id, "+FLAGS", "\\Seen")
                if self.delete_emails and imported:
                    mail.store(email_id, "+FLAGS", "\\Deleted")
                    stats["deleted"] = stats.get("deleted", 0) + 1
                stats["processed"] += 1
                return

            if self._is_dmarc_report_email(msg):
                reports_found = self._process_attachments(msg, stats, message_id=message_id)
                stats["reports_found"] += reports_found

                # Mark DMARC-looking email as read, and delete only after a successful import.
                mail.store(email_id, "+FLAGS", "\\Seen")
                if self.delete_emails and reports_found > 0:
                    mail.store(email_id, "+FLAGS", "\\Deleted")
                    stats["deleted"] = stats.get("deleted", 0) + 1

                stats["processed"] += 1
        except Exception as e:  # pylint: disable=broad-exception-caught
            error_msg = f"Error processing email ID {email_id}: {str(e)}"
            logger.error(error_msg)
            stats["errors"].append(error_msg)
            self._append_detail(
                stats,
                status="error",
                reason="message_processing_failed",
                message_id=message_id,
                error=str(e),
            )

    def fetch_reports(self, days: int = 7) -> Dict[str, Any]:
        """
        Fetch and process DMARC reports from the configured mailbox

        Args:
            days: Number of days to look back for emails

        Returns:
            Dictionary with stats about processing results
        """
        if not all([self.server, self.username, self.password]):
            logger.error("IMAP credentials not fully configured")
            return {"success": False, "error": "IMAP credentials not configured", "processed": 0}

        stats = initial_import_stats(deleted=True)

        try:
            # Connect to the mail server
            mail = imaplib.IMAP4_SSL(self.server, self.port)
            mail.login(self.username, self.password)
            mail.select(self._quoted_folder())

            # Calculate the date range for search
            date_since = (datetime.now() - timedelta(days=days)).strftime("%d-%b-%Y")

            # Search for all emails containing possible DMARC reports
            search_criteria = f"(SINCE {date_since})"
            status, data = mail.search(None, search_criteria)

            if status != "OK":
                logger.error("Error searching mailbox")
                stats["success"] = False
                stats["error"] = "Error searching mailbox"
                mail.logout()
                return stats

            # Get list of email IDs
            email_ids = data[0].split()

            # Track domains before processing to identify new ones
            domains_before = set(self.report_store.get_domains())

            # Process each email
            for email_id in email_ids:
                self._process_single_email(mail, email_id, stats)

            # Actually remove emails marked for deletion
            if self.delete_emails and stats["deleted"] > 0:
                mail.expunge()

            # Logout
            mail.logout()

            # Identify new domains
            domains_after = set(self.report_store.get_domains())
            stats["new_domains"] = list(domains_after - domains_before)

            return stats

        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Error fetching DMARC reports: %s", str(e))
            return {
                "success": False,
                "error": "Error connecting to mailbox. Check server logs for details.",
                "processed": 0,
                "errors": [sanitize_connector_error(e)],
            }

    def _is_dmarc_report_email(self, msg: email.message.Message) -> bool:
        """
        Check if an email likely contains DMARC reports

        Args:
            msg: Email message object

        Returns:
            True if the email is likely a DMARC report, False otherwise
        """
        # Get email subject
        subject = ""
        if "Subject" in msg:
            subject = self._decode_email_header(msg["Subject"])

        # Get email from
        from_addr = ""
        if "From" in msg:
            from_addr = self._decode_email_header(msg["From"])

        # Common keywords in DMARC report emails
        dmarc_keywords = [
            "dmarc",
            "aggregate",
            "report",
            "rua",
            "authentication",
            "domain",
            "failure",
        ]

        # Common senders of DMARC reports
        dmarc_senders = [
            "noreply@",
            "dmarc-noreply@",
            "postmaster@",
            "microsoft.com",
            "google.com",
            "yahoo.com",
            "hotmail.com",
            "outlook.com",
            "mail.ru",
        ]

        # Check if subject contains DMARC keywords
        if any(keyword in subject.lower() for keyword in dmarc_keywords):
            return True

        # Check if sender matches common DMARC report senders
        if any(sender in from_addr.lower() for sender in dmarc_senders):
            return True

        # Check for attachments with typical DMARC report filenames
        return self._has_dmarc_attachments(msg)

    def _decode_email_header(self, header: str) -> str:
        """
        Decode an email header that might contain non-ASCII characters

        Args:
            header: Email header string

        Returns:
            Decoded header text
        """
        decoded_parts = []
        for text, encoding in decode_header(header):
            if isinstance(text, bytes):
                if encoding:
                    decoded_parts.append(text.decode(encoding or "utf-8", errors="replace"))
                else:
                    decoded_parts.append(text.decode("utf-8", errors="replace"))
            else:
                decoded_parts.append(text)

        return " ".join(decoded_parts)

    def _has_dmarc_attachments(self, msg: email.message.Message) -> bool:
        """
        Check if the email has attachments that might be DMARC reports

        Args:
            msg: Email message object

        Returns:
            True if the email has potential DMARC report attachments
        """
        for part in msg.walk():
            content_disposition = part.get_content_disposition()
            if content_disposition == "attachment":
                filename = part.get_filename()
                if filename:
                    # Decode filename if needed
                    filename = self._decode_email_header(filename)

                    # Check file extension
                    if self._is_dmarc_filename(filename):
                        return True

                # Check content type
                content_type = part.get_content_type()
                if content_type in (
                    "application/zip",
                    "application/gzip",
                    "application/x-gzip",
                    "application/xml",
                    "text/xml",
                ):
                    return True

        return False

    @staticmethod
    def _is_dmarc_filename(filename: str) -> bool:
        lower = filename.lower()
        return (
            lower.endswith(".xml")
            or lower.endswith(".zip")
            or lower.endswith(".gz")
            or lower.endswith(".gzip")
        )

    @staticmethod
    def _append_detail(stats: Optional[Dict[str, Any]], **detail: str) -> None:
        """Append a compact attachment/message outcome to the import stats."""
        if stats is None:
            return
        append_import_detail(stats, **detail)

    def _store_report_if_new(
        self,
        report: Dict[str, Any],
        *,
        filename: str,
        stats: Optional[Dict[str, Any]],
        message_id: Optional[str],
    ) -> bool:
        domain = report.get("domain", "unknown")
        report_id = report.get("report_id", "")
        if report_id and (
            self.report_store.has_report(domain, report_id)
            or (self.db is not None and report_exists(self.db, domain, report_id))
        ):
            logger.info("Skipping duplicate DMARC report %s for %s", report_id, domain)
            if stats is not None:
                stats["duplicate_reports"] = stats.get("duplicate_reports", 0) + 1
            self._append_detail(
                stats,
                status="duplicate",
                message_id=message_id,
                filename=filename,
                domain=str(domain),
                report_id=str(report_id),
            )
            return False

        if self.db is not None:
            save_parsed_report(self.db, report)
        self.report_store.add_report(report)
        self._append_detail(
            stats,
            status="imported",
            message_id=message_id,
            filename=filename,
            domain=str(domain),
            report_id=str(report_id),
        )
        return True

    def _process_forensic_email(
        self,
        raw_email: bytes,
        *,
        stats: Optional[Dict[str, Any]],
        message_id: Optional[str],
    ) -> bool:
        try:
            report = ForensicParser.parse_bytes(
                raw_email,
                redaction_policy=get_forensic_redaction_policy(self.db),
            )
            report_id = str(report.get("report_id", ""))
            domain = str(report.get("reported_domain") or "unknown")

            if self.db is not None and forensic_report_exists(self.db, report_id):
                if stats is not None:
                    stats["duplicate_forensic_reports"] = (
                        stats.get("duplicate_forensic_reports", 0) + 1
                    )
                self._append_detail(
                    stats,
                    status="duplicate",
                    reason="duplicate_forensic_report",
                    message_id=message_id,
                    domain=domain,
                    report_id=report_id,
                )
                return False

            if self.db is None:
                self._append_detail(
                    stats,
                    status="skipped",
                    reason="forensic_report_requires_database",
                    message_id=message_id,
                    domain=domain,
                    report_id=report_id,
                )
                return False

            _row, created = save_forensic_report(self.db, report)
            if created:
                if stats is not None:
                    stats["forensic_reports_found"] = stats.get("forensic_reports_found", 0) + 1
                self._append_detail(
                    stats,
                    status="imported",
                    reason="forensic_report",
                    message_id=message_id,
                    domain=domain,
                    report_id=report_id,
                )
                return True

            if stats is not None:
                stats["duplicate_forensic_reports"] = stats.get("duplicate_forensic_reports", 0) + 1
            self._append_detail(
                stats,
                status="duplicate",
                reason="duplicate_forensic_report",
                message_id=message_id,
                domain=domain,
                report_id=report_id,
            )
            return False
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.error("Error processing forensic report email %s: %s", message_id, exc)
            if stats is not None:
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
            return False

    def _process_dmarc_attachment(
        self,
        part: email.message.Message,
        *,
        filename: str,
        stats: Optional[Dict[str, Any]],
        message_id: Optional[str],
    ) -> bool:
        try:
            content = part.get_payload(decode=True)
            if not content:
                self._append_detail(
                    stats,
                    status="skipped",
                    reason="empty_attachment",
                    message_id=message_id,
                    filename=filename,
                )
                return False

            report = DMARCParser.parse_file(content, filename)
            stored = self._store_report_if_new(
                report,
                filename=filename,
                stats=stats,
                message_id=message_id,
            )
            if stored:
                logger.info("Successfully processed DMARC report: %s", filename)
            return stored
        except Exception as exc:  # pylint: disable=broad-exception-caught
            logger.error("Error processing attachment %s: %s", filename, str(exc))
            if stats is not None:
                stats.setdefault("errors", []).append(
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
            return False

    def _process_attachments(
        self,
        msg: email.message.Message,
        stats: Optional[Dict[str, Any]] = None,
        message_id: Optional[str] = None,
    ) -> int:
        """
        Process email attachments that might be DMARC reports

        Args:
            msg: Email message object

        Returns:
            Number of DMARC reports found and processed
        """
        reports_found = 0

        for part in msg.walk():
            if part.get_content_disposition() != "attachment":
                continue

            filename = part.get_filename()
            if not filename:
                continue

            filename = self._decode_email_header(filename)
            if not self._is_dmarc_filename(filename):
                self._append_detail(
                    stats,
                    status="skipped",
                    reason="unsupported_attachment",
                    message_id=message_id,
                    filename=filename,
                )
                continue

            if self._process_dmarc_attachment(
                part,
                filename=filename,
                stats=stats,
                message_id=message_id,
            ):
                reports_found += 1

        return reports_found
