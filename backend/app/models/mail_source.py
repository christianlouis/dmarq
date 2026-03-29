from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text

from app.core.database import Base


class MailSource(Base):
    """
    Mail source configuration model.

    Stores credentials and settings for a mail inbox used to retrieve DMARC
    aggregate reports.  The ``method`` field determines how the connection is
    made and which additional fields are relevant:

    - ``IMAP``       – standard IMAP4 (over SSL/TLS or STARTTLS)
    - ``POP3``       – POP3 inbox (stub for future implementation)
    - ``GMAIL_API``  – Gmail API with OAuth 2.0 (stub for future implementation)
    """

    __tablename__ = "mail_sources"

    id = Column(Integer, primary_key=True, index=True)

    # Human-readable label for the source
    name = Column(String, nullable=False)

    # Connection method – determines which fields are used at runtime
    method = Column(String, nullable=False, default="IMAP")  # IMAP | POP3 | GMAIL_API

    # Connection details (used by IMAP and POP3)
    server = Column(String, nullable=True)
    port = Column(Integer, nullable=True, default=993)
    username = Column(String, nullable=True)
    # NOTE: password is stored in plaintext.  In a production environment this
    # field should be encrypted at the application layer before persisting.
    password = Column(Text, nullable=True)
    use_ssl = Column(Boolean, default=True)
    folder = Column(String, default="INBOX")

    # Polling behaviour
    polling_interval = Column(Integer, default=60)  # minutes

    # Source lifecycle
    enabled = Column(Boolean, default=True, index=True)
    last_checked = Column(DateTime, nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f"<MailSource id={self.id} name={self.name!r} method={self.method!r}>"
