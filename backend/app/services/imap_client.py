import imaplib
import email
import os
import logging
import tempfile
from email.header import decode_header
from typing import List, Dict, Any, Optional, Tuple
from datetime import datetime, timedelta

from app.core.config import get_settings
from app.services.dmarc_parser import DMARCParser
from app.services.report_store import ReportStore

# Setup logger
logger = logging.getLogger(__name__)

class IMAPClient:
    """
    Client for retrieving DMARC reports from an IMAP mailbox
    """
    
    def __init__(self, 
                 server: str = None, 
                 port: int = None, 
                 username: str = None, 
                 password: str = None,
                 delete_emails: bool = False):
        """
        Initialize the IMAP client with credentials
        
        Args:
            server: IMAP server hostname (if None, uses settings)
            port: IMAP server port (if None, uses settings)
            username: IMAP username (if None, uses settings)
            password: IMAP password (if None, uses settings)
            delete_emails: Whether to delete emails after processing (default: False)
        """
        settings = get_settings()
        
        self.server = server or settings.IMAP_SERVER
        self.port = port or settings.IMAP_PORT
        self.username = username or settings.IMAP_USERNAME
        self.password = password or settings.IMAP_PASSWORD
        self.delete_emails = delete_emails
        
        self.report_store = ReportStore.get_instance()
        
        if not all([self.server, self.username, self.password]):
            logger.warning("IMAP credentials not fully configured")
    
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
            return False, "IMAP credentials not fully configured", {}
            
        try:
            # Create IMAP4 connection
            mail = imaplib.IMAP4_SSL(self.server, self.port)
            # Login
            mail.login(self.username, self.password)
            
            # List available mailboxes
            status, mailbox_list = mail.list()
            available_mailboxes = []
            
            if status == 'OK':
                for mailbox in mailbox_list:
                    if isinstance(mailbox, bytes):
                        try:
                            # Extract mailbox name from response
                            mailbox_str = mailbox.decode('utf-8')
                            # Extract the mailbox name (after the last quote)
                            parts = mailbox_str.split('"')
                            if len(parts) > 2:
                                mailbox_name = parts[-1].strip()
                                if mailbox_name.startswith(' '):
                                    mailbox_name = mailbox_name[1:]
                                available_mailboxes.append(mailbox_name)
                        except Exception:
                            pass
            
            # Select inbox and get message count
            status, data = mail.select('INBOX')
            message_count = 0
            unread_count = 0
            
            if status == 'OK':
                message_count = int(data[0])
                
                # Count unread messages
                status, data = mail.search(None, 'UNSEEN')
                if status == 'OK':
                    unread_count = len(data[0].split())
            
            # Gather some stats about potential DMARC reports
            dmarc_count = 0
            status, data = mail.search(None, 'SUBJECT "DMARC"')
            if status == 'OK':
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
                "timestamp": datetime.now().isoformat()
            }
            
            return True, "Connection successful", stats
        except Exception as e:
            logger.error(f"IMAP connection test failed: {str(e)}")
            return False, f"Connection failed: {str(e)}", {}
    
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
            return {
                "success": False, 
                "error": "IMAP credentials not configured", 
                "processed": 0
            }
        
        stats = {
            "success": True,
            "processed": 0,
            "reports_found": 0,
            "new_domains": [],
            "errors": []
        }
        
        try:
            # Connect to the mail server
            mail = imaplib.IMAP4_SSL(self.server, self.port)
            mail.login(self.username, self.password)
            mail.select('INBOX')
            
            # Calculate the date range for search
            date_since = (datetime.now() - timedelta(days=days)).strftime("%d-%b-%Y")
            
            # Search for all emails containing possible DMARC reports
            search_criteria = f'(SINCE {date_since})'
            status, data = mail.search(None, search_criteria)
            
            if status != 'OK':
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
                try:
                    # Fetch the email
                    status, msg_data = mail.fetch(email_id, '(RFC822)')
                    
                    if status != 'OK':
                        logger.error(f"Error fetching email ID {email_id}")
                        continue
                    
                    # Parse the email
                    raw_email = msg_data[0][1]
                    msg = email.message_from_bytes(raw_email)
                    
                    # Check if this email might contain DMARC reports
                    if self._is_dmarc_report_email(msg):
                        # Process attachments
                        reports_found = self._process_attachments(msg)
                        stats["reports_found"] += reports_found
                        
                        # Mark email as read
                        mail.store(email_id, '+FLAGS', '\\Seen')
                        
                        # Delete email if configured
                        if self.delete_emails:
                            mail.store(email_id, '+FLAGS', '\\Deleted')
                        
                        stats["processed"] += 1
                except Exception as e:
                    error_msg = f"Error processing email ID {email_id}: {str(e)}"
                    logger.error(error_msg)
                    stats["errors"].append(error_msg)
            
            # Actually remove emails marked for deletion
            if self.delete_emails:
                mail.expunge()
            
            # Logout
            mail.logout()
            
            # Identify new domains
            domains_after = set(self.report_store.get_domains())
            stats["new_domains"] = list(domains_after - domains_before)
            
            return stats
            
        except Exception as e:
            logger.error(f"Error fetching DMARC reports: {str(e)}")
            return {
                "success": False, 
                "error": f"Error connecting to mailbox: {str(e)}", 
                "processed": 0
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
            "dmarc", "aggregate", "report", "rua", 
            "authentication", "domain", "failure"
        ]
        
        # Common senders of DMARC reports
        dmarc_senders = [
            "noreply@", "dmarc-noreply@", "postmaster@",
            "microsoft.com", "google.com", "yahoo.com", 
            "hotmail.com", "outlook.com", "mail.ru"
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
                    decoded_parts.append(text.decode(encoding or 'utf-8', errors='replace'))
                else:
                    decoded_parts.append(text.decode('utf-8', errors='replace'))
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
            if content_disposition == 'attachment':
                filename = part.get_filename()
                if filename:
                    # Decode filename if needed
                    filename = self._decode_email_header(filename)
                    
                    # Check file extension
                    if (filename.lower().endswith('.xml') or 
                        filename.lower().endswith('.zip') or
                        filename.lower().endswith('.gz') or
                        filename.lower().endswith('.gzip')):
                        return True
                
                # Check content type
                content_type = part.get_content_type()
                if (content_type == 'application/zip' or
                    content_type == 'application/gzip' or
                    content_type == 'application/x-gzip' or
                    content_type == 'application/xml' or
                    content_type == 'text/xml'):
                    return True
        
        return False
    
    def _process_attachments(self, msg: email.message.Message) -> int:
        """
        Process email attachments that might be DMARC reports
        
        Args:
            msg: Email message object
            
        Returns:
            Number of DMARC reports found and processed
        """
        reports_found = 0
        
        for part in msg.walk():
            content_disposition = part.get_content_disposition()
            
            if content_disposition == 'attachment':
                filename = part.get_filename()
                if filename:
                    # Decode filename if needed
                    filename = self._decode_email_header(filename)
                    
                    # Check if it's a likely DMARC report file
                    if (filename.lower().endswith('.xml') or 
                        filename.lower().endswith('.zip') or
                        filename.lower().endswith('.gz') or
                        filename.lower().endswith('.gzip')):
                        
                        try:
                            # Get attachment content
                            content = part.get_payload(decode=True)
                            
                            # Parse the DMARC report
                            report = DMARCParser.parse_file(content, filename)
                            
                            # Add the report to the store
                            self.report_store.add_report(report)
                            
                            reports_found += 1
                            logger.info(f"Successfully processed DMARC report: {filename}")
                        except Exception as e:
                            logger.error(f"Error processing attachment {filename}: {str(e)}")
        
        return reports_found