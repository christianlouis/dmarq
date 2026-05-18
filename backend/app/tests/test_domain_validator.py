import socket
from unittest.mock import patch

from app.utils.domain_validator import (
    DomainValidationError,
    validate_domain,
    validate_domain_config,
)


class TestValidateDomain:
    def test_valid_domain_without_dns_check(self):
        assert validate_domain("example.com", check_dns=False) == (True, None, None)

    def test_domain_longer_than_253_characters_is_rejected(self):
        domain = f"{'a' * 250}.com"

        valid, message, code = validate_domain(domain, check_dns=False)

        assert valid is False
        assert "too long" in message
        assert code == DomainValidationError.TOO_LONG

    def test_dns_resolution_failure_is_reported(self):
        with patch("app.utils.domain_validator.socket.gethostbyname", side_effect=socket.gaierror):
            valid, message, code = validate_domain("example.com", check_dns=True)

        assert valid is False
        assert "could not be resolved" in message
        assert code == DomainValidationError.DNS_RESOLUTION_FAILED


class TestValidateDomainConfig:
    def test_valid_config(self):
        result = validate_domain_config(
            {"name": "example.com", "description": "Primary reporting domain"}
        )

        assert result == {"valid": True, "errors": {}}

    def test_missing_name_is_invalid(self):
        result = validate_domain_config({"description": "No name"})

        assert result["valid"] is False
        assert result["errors"]["name"] == "Domain name is required"

    def test_invalid_domain_name_is_reported(self):
        result = validate_domain_config({"name": "bad domain"})

        assert result["valid"] is False
        assert "whitespace" in result["errors"]["name"]

    def test_unsafe_description_is_rejected(self):
        result = validate_domain_config({"name": "example.com", "description": "<script></script>"})

        assert result["valid"] is False
        assert "unsafe HTML" in result["errors"]["description"]

    def test_description_length_limit(self):
        result = validate_domain_config({"name": "example.com", "description": "a" * 501})

        assert result["valid"] is False
        assert "too long" in result["errors"]["description"]
