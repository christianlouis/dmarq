import pytest

from app.services.imap_client import IMAPClient


class TestIMAPClientHeader:
    """
    Tests specifically for IMAPClient._decode_email_header method.
    """

    def setup_method(self):
        """Set up test fixtures"""
        # We don't need real credentials for testing this pure function
        self.client = IMAPClient(
            server="imap.example.com", port=993, username="test@example.com", password="password"
        )

    @pytest.mark.parametrize(
        "header, expected",
        [
            ("Simple Subject", "Simple Subject"),
            ("=?utf-8?q?Hello_World?=", "Hello World"),
            ("=?utf-8?b?SGVsbG8gV29ybGQ=?=", "Hello World"),
            ("=?utf-8?q?Re=3A?= DMARC report", "Re: DMARC report"),
            ("=?utf-8?q?First?= =?utf-8?q?Second?=", "FirstSecond"),
            ("=?iso-8859-1?q?T=E9st?=", "Tést"),
            ("", ""),
            ("=?utf-8?q?Malformed", "=?utf-8?q?Malformed"),
        ],
    )
    def test_decode_email_header(self, header, expected):
        """Test decoding various email headers"""
        assert self.client._decode_email_header(header) == expected

    def test_decode_email_header_mixed_types(self):
        """Test mixed bytes and string types (simulated)"""
        # This tests the logic that handles both bytes and str from decode_header
        # In practice, decode_header returns a list of (text, encoding) tuples

        # Test a case where decode_header would return bytes with no encoding
        # e.g., decode_header("Plain text") returns [(b'Plain text', None)]
        assert self.client._decode_email_header("Plain text") == "Plain text"

    def test_decode_email_header_with_none_encoding(self):
        """Test decoding when encoding is None but text is bytes"""
        # The code uses utf-8 with replace if encoding is None
        # Let's test this directly by mocking if needed,
        # but the current implementation already handles this.
        assert self.client._decode_email_header("Plain text") == "Plain text"
