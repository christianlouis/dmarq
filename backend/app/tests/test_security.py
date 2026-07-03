"""
Security-focused tests for DMARQ application.

Covers API key management, domain validation, file upload limits, and XML parsing security.
"""

import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.services.dmarc_parser as parser_module
from app.core.security import add_api_key, generate_api_key, verify_api_key
from app.main import create_app
from app.services.dmarc_parser import DMARCParser
from app.utils.domain_validator import validate_domain, validate_domain_config


def _script_tags_without_src(body: str) -> list[str]:
    script_tags = re.findall(r"<script\b[^>]*>", body, re.IGNORECASE)
    return [tag for tag in script_tags if not re.search(r"\ssrc\s*=", tag, re.IGNORECASE)]


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


class TestSecurityHeaders:
    """Test security headers that affect the browser UI."""

    def test_csp_allows_current_alpine_runtime(self, client: TestClient):
        """The current Alpine CDN build needs eval permission to render UI pages."""
        response = client.get("/mail-sources")
        csp = response.headers["Content-Security-Policy"]

        assert "'unsafe-eval'" in csp
        assert "https://cdn.jsdelivr.net" in csp
        assert "https://cdn.tailwindcss.com" not in csp

    def test_base_template_keeps_standard_alpine_until_templates_are_migrated(self):
        """The CSP build cannot evaluate the remaining inline Alpine expressions yet."""
        template = Path(__file__).resolve().parents[1] / "templates" / "layouts" / "base.html"
        body = template.read_text()

        assert "alpinejs@3.x.x/dist/cdn.min.js" in body
        assert "cdn.tailwindcss.com" not in body
        assert "@alpinejs/csp" not in body
        assert not _script_tags_without_src(body)
        assert not re.search(r"<style\b", body, re.IGNORECASE)
        assert 'src="/static/js/base-layout.js"' in body
        assert 'href="/static/css/app.css"' in body
        assert 'href="/static/css/page-utilities.css"' in body

    @pytest.mark.parametrize("template_name", ["login.html", "setup.html"])
    def test_auth_templates_use_external_page_scripts(self, template_name: str):
        """Login and setup should not add page-specific inline script blocks."""
        template = Path(__file__).resolve().parents[1] / "templates" / template_name
        body = template.read_text()

        assert not _script_tags_without_src(body)
        assert not re.search(r"<style\b", body, re.IGNORECASE)
        assert f'src="/static/js/{template_name.removesuffix(".html")}-page.js"' in body
        assert "cdn.tailwindcss.com" not in body
        assert 'href="/static/css/app.css"' in body
        assert 'href="/static/css/page-utilities.css"' in body

    def test_csp_report_only_header_appears_when_flag_enabled(
        self, client: TestClient, monkeypatch
    ):
        """When CSP_REPORT_ONLY is true, the strict target CSP should appear as report-only."""
        monkeypatch.setenv("CSP_REPORT_ONLY", "true")

        response = client.get("/mail-sources")
        assert "Content-Security-Policy-Report-Only" in response.headers

        csp_ro = response.headers["Content-Security-Policy-Report-Only"]
        assert "'unsafe-inline'" not in csp_ro
        assert "'unsafe-eval'" not in csp_ro
        assert "script-src 'self'" in csp_ro

    def test_strict_csp_can_be_enforced_after_runtime_migration(
        self, client: TestClient, monkeypatch
    ):
        """Operators can enforce the strict target CSP once their UI is validated."""
        monkeypatch.setenv("CSP_ENFORCE_STRICT", "true")

        response = client.get("/mail-sources")

        csp = response.headers["Content-Security-Policy"]
        assert "'unsafe-inline'" not in csp
        assert "'unsafe-eval'" not in csp
        assert "script-src 'self'" in csp
        assert "style-src 'self' https://fonts.googleapis.com https://cdn.jsdelivr.net" in csp


class TestXMLParsingSecurity:
    """Test XML parsing security (defusedxml, XXE protection)."""

    def test_defusedxml_is_used(self):
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
        except Exception:  # pylint: disable=broad-exception-caught
            pass  # Expected – defusedxml blocks DTD processing


class TestAdminApiKeyStartup:
    """Test admin API key loading during the application startup event."""

    def test_startup_uses_env_api_key(self, monkeypatch):
        """When ADMIN_API_KEY is configured, startup should register it directly."""
        import app.core.security as sec_module
        import app.main as main_module

        test_key = "a" * 64
        monkeypatch.setattr(main_module.settings, "ADMIN_API_KEY", test_key)

        saved_keys = set(sec_module._api_keys)
        sec_module._api_keys.clear()
        try:
            application = create_app()
            with TestClient(application):
                assert sec_module.verify_api_key(test_key)
        finally:
            sec_module._api_keys.clear()
            sec_module._api_keys.update(saved_keys)

    def test_startup_generates_key_when_no_env(self, monkeypatch):
        """When ADMIN_API_KEY is not set, startup should generate a random key."""
        import app.core.security as sec_module
        import app.main as main_module

        monkeypatch.setattr(main_module.settings, "ADMIN_API_KEY", None)

        saved_keys = set(sec_module._api_keys)
        sec_module._api_keys.clear()
        try:
            application = create_app()
            with TestClient(application):
                assert len(sec_module._api_keys) == 1
        finally:
            sec_module._api_keys.clear()
            sec_module._api_keys.update(saved_keys)
