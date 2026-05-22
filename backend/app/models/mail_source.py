from datetime import datetime

from sqlalchemy import Boolean, Column, DateTime, Integer, String, Text
from sqlalchemy.orm import relationship

from app.core.credential_encryption import decrypt_secret, encrypt_secret, is_encrypted_secret
from app.core.database import Base


class MailSource(Base):
    """
    Mail source configuration model.

    Stores credentials and settings for a mail inbox used to retrieve DMARC
    aggregate reports.  The ``method`` field determines how the connection is
    made and which additional fields are relevant:

    - ``IMAP``       – standard IMAP4 (over SSL/TLS or STARTTLS)
    - ``POP3``       – POP3 inbox (stub for future implementation)
    - ``GMAIL_API``  – Gmail API with OAuth 2.0
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
    _password = Column("password", Text, nullable=True)
    use_ssl = Column(Boolean, default=True)
    folder = Column(String, default="INBOX")

    # Gmail API OAuth2 credentials (used by GMAIL_API method)
    gmail_client_id = Column(String, nullable=True)
    _gmail_client_secret = Column("gmail_client_secret", Text, nullable=True)
    _gmail_access_token = Column("gmail_access_token", Text, nullable=True)
    _gmail_refresh_token = Column("gmail_refresh_token", Text, nullable=True)
    # Email address of the authorised Gmail account
    gmail_email = Column(String, nullable=True)
    # JSON-encoded list of Gmail message IDs that have already been ingested
    gmail_ingested_ids = Column(Text, nullable=True, default="[]")

    # Polling behaviour
    polling_interval = Column(Integer, default=60)  # minutes

    # Source lifecycle
    enabled = Column(Boolean, default=True, index=True)
    last_checked = Column(DateTime, nullable=True)

    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    imports = relationship(
        "MailSourceImport",
        back_populates="mail_source",
        cascade="all, delete-orphan",
    )

    def __repr__(self):
        return f"<MailSource id={self.id} name={self.name!r} method={self.method!r}>"

    def encrypt_legacy_secrets(self) -> bool:
        """Encrypt any legacy plaintext secrets already stored on this row."""
        changed = False
        secret_fields = {
            "password": self._password,
            "gmail_client_secret": self._gmail_client_secret,
            "gmail_access_token": self._gmail_access_token,
            "gmail_refresh_token": self._gmail_refresh_token,
        }

        for public_name, stored_value in secret_fields.items():
            if stored_value and not is_encrypted_secret(stored_value):
                setattr(self, public_name, stored_value)
                changed = True

        return changed

    @property
    def password(self):
        """Return the decrypted IMAP password, if present."""
        return decrypt_secret(self._password)

    @password.setter
    def password(self, value):
        self._password = encrypt_secret(value)

    @property
    def gmail_client_secret(self):
        """Return the decrypted Gmail OAuth client secret, if present."""
        return decrypt_secret(self._gmail_client_secret)

    @gmail_client_secret.setter
    def gmail_client_secret(self, value):
        self._gmail_client_secret = encrypt_secret(value)

    @property
    def gmail_access_token(self):
        """Return the decrypted Gmail OAuth access token, if present."""
        return decrypt_secret(self._gmail_access_token)

    @gmail_access_token.setter
    def gmail_access_token(self, value):
        self._gmail_access_token = encrypt_secret(value)

    @property
    def gmail_refresh_token(self):
        """Return the decrypted Gmail OAuth refresh token, if present."""
        return decrypt_secret(self._gmail_refresh_token)

    @gmail_refresh_token.setter
    def gmail_refresh_token(self, value):
        self._gmail_refresh_token = encrypt_secret(value)
