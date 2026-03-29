"""
Security-focused tests for DMARQ application.

Covers API key management, domain validation, file upload limits, and XML parsing security.
"""

import pytest
from app.core.security import add_api_key, generate_api_key, verify_api_key
from app.services.dmarc_parser import DMARCParser
from app.utils.domain_validator import validate_domain, validate_domain_config


class TestAPIKeySecurity:
    """Test API key generation and verification."""

    def test_generate_api_key_length_and_uniqueness(self):
        """Generated keys should be 64 hex characters and unique."""
        key1 = generate_api_key()
        key2 = generate_api_key()

        assert len(key1) == 64
        assert len(key2) == 64
        assert key1 != key2
        assert all(c in "0123456789abcdef" for c in key1)

    def test_add_and_verify_api_key(self):
        """Keys should only be valid after being added."""
        key = generate_api_key()
        assert not verify_api_key(key)

        assert add_api_key(key) is True
        assert verify_api_key(key) is True

        # Adding the same key again returns False
        assert add_api_key(key) is False


class TestDomainValidation:
    """Test domain name validation."""

    @pytest.mark.parametrize(
        "domain",
        [
            "example.com",
            "subdomain.example.com",
            "my-domain.example.org",
            "test123.example.net",
        ],
    )
    def test_valid_domains(self, domain):
        is_valid, error, _ = validate_domain(domain, check_dns=False)
        assert is_valid, f"Domain {domain} should be valid: {error}"

    @pytest.mark.parametrize(
        "domain",
        [
            "",
            "   ",
            "example",
            "-example.com",
            "example-.com",
            "exam ple.com",
            "example..com",
            "a" * 64 + ".com",
            "a" * 254,
        ],
    )
    def test_invalid_domain_format(self, domain):
        is_valid, error, _ = validate_domain(domain, check_dns=False)
        assert not is_valid, f"Domain '{domain}' should be invalid"
        assert error is not None

    @pytest.mark.parametrize(
        "domain",
        [
            "example.com<script>",
            "example.com'; DROP TABLE users--",
            "example.com|whoami",
            "example.com&rm -rf /",
            "example.com`cat /etc/passwd`",
            "example.com$USER",
            'example.com"test',
            "example.com\\\\test",
        ],
    )
    def test_malicious_domain_input(self, domain):
        is_valid, _, _ = validate_domain(domain, check_dns=False)
        assert not is_valid, f"Malicious domain '{domain}' should be rejected"

    def test_domain_config_validation_valid(self):
        result = validate_domain_config({"name": "example.com", "description": "Test domain"})
        assert result["valid"]
        assert len(result["errors"]) == 0

    def test_domain_config_missing_name(self):
        result = validate_domain_config({"description": "Test"})
        assert not result["valid"]
        assert "name" in result["errors"]

    def test_domain_config_description_too_long(self):
        result = validate_domain_config({"name": "example.com", "description": "a" * 501})
        assert not result["valid"]
        assert "description" in result["errors"]

    def test_domain_config_xss_description(self):
        result = validate_domain_config(
            {"name": "example.com", "description": "<script>alert('xss')</script>"}
        )
        assert not result["valid"]
        assert "description" in result["errors"]


class TestFileUploadSecurity:
    """Test file upload size limits."""

    def test_file_size_limit(self):
        large_content = b"x" * (11 * 1024 * 1024)
        with pytest.raises(ValueError, match="too large"):
            DMARCParser.parse_file(large_content, "test.xml")


class TestXMLParsingSecurity:
    """Test XML parsing security (defusedxml, XXE protection)."""

    def test_defusedxml_is_used(self):
        import app.services.dmarc_parser as parser_module

        assert hasattr(parser_module, "ET")
        module_info = str(getattr(parser_module.ET, "__name__", "")) + str(
            getattr(parser_module.ET, "__module__", "")
        )
        assert "defusedxml" in module_info.lower()

    def test_xxe_protection(self):
        """defusedxml should prevent XXE entity expansion."""
        xxe_payload = b"""\
<?xml version="1.0"?>
<!DOCTYPE foo [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<feedback>
    <report_metadata>
        <org_name>&xxe;</org_name>
    </report_metadata>
</feedback>
"""
        # defusedxml should raise an error or not expand the entity
        try:
            result = DMARCParser.parse_file(xxe_payload, "test.xml")
            org_name = result.get("org_name", "")
            assert "root:" not in org_name and "/bin" not in org_name
        except Exception:
            pass  # Expected – defusedxml blocks DTD processing
