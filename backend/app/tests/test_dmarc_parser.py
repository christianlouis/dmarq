import io
import zipfile

import pytest

from app.services.dmarc_parser import DMARCParser
from app.tests.test_data import SAMPLE_XML, SAMPLE_XML_WITH_NAMESPACE


class TestDMARCParser:
    """Tests for the DMARC XML parser."""

    def test_parse_xml_report(self):
        """Test parsing a plain XML DMARC report."""
        xml_bytes = SAMPLE_XML.encode("utf-8")
        result = DMARCParser.parse_file(xml_bytes, "report.xml")

        # Report metadata (flat keys from _parse_xml)
        assert result["report_id"] == "123456789"
        assert result["org_name"] == "google.com"
        assert result["email"] == "noreply-dmarc-support@google.com"
        assert result["begin_timestamp"] == 1597449600
        assert result["end_timestamp"] == 1597535999

        # Policy published
        assert result["domain"] == "example.com"
        assert result["policy"]["p"] == "none"

        # Records
        assert len(result["records"]) == 1
        record = result["records"][0]
        assert record["source_ip"] == "203.0.113.1"
        assert record["count"] == 2
        assert record["disposition"] == "none"
        assert record["dkim_result"] == "pass"
        assert record["spf_result"] == "fail"
        assert record["header_from"] == "example.com"

        # Summary
        assert result["summary"]["total_count"] == 2
        assert result["summary"]["passed_count"] == 2  # dkim passed
        assert result["summary"]["failed_count"] == 0

    def test_parse_zip_report(self):
        """Test parsing a DMARC report inside a ZIP archive."""
        xml_bytes = SAMPLE_XML.encode("utf-8")

        zip_buffer = io.BytesIO()
        with zipfile.ZipFile(zip_buffer, "w") as zf:
            zf.writestr("report.xml", xml_bytes)
        zip_content = zip_buffer.getvalue()

        result = DMARCParser.parse_file(zip_content, "report.zip")

        assert result["report_id"] == "123456789"
        assert result["domain"] == "example.com"
        assert len(result["records"]) == 1

    def test_file_too_large(self):
        """Test that files exceeding the size limit are rejected."""
        large_content = b"x" * (11 * 1024 * 1024)  # 11 MB
        with pytest.raises(ValueError, match="too large"):
            DMARCParser.parse_file(large_content, "report.xml")

    def test_invalid_xml(self):
        """Test that invalid XML raises a ValueError."""
        with pytest.raises(ValueError, match="Error parsing DMARC XML"):
            DMARCParser.parse_file(b"not xml at all", "report.xml")

    def test_parse_xml_report_with_namespace(self):
        """Test parsing a DMARC XML report that uses an XML namespace (e.g. web.de/gmx.net)."""
        xml_bytes = SAMPLE_XML_WITH_NAMESPACE.encode("utf-8")
        result = DMARCParser.parse_file(xml_bytes, "report.xml")

        # Metadata
        assert result["report_id"] == "987654321"
        assert result["org_name"] == "web.de"
        assert result["email"] == "dmarc@web.de"
        assert result["begin_timestamp"] == 1597449600
        assert result["end_timestamp"] == 1597535999

        # Policy published
        assert result["domain"] == "example.com"
        assert result["policy"]["p"] == "reject"

        # Records
        assert len(result["records"]) == 1
        record = result["records"][0]
        assert record["source_ip"] == "198.51.100.5"
        assert record["count"] == 3
        assert record["disposition"] == "reject"
        assert record["dkim_result"] == "pass"
        assert record["spf_result"] == "pass"
        assert record["header_from"] == "example.com"

        # Summary
        assert result["summary"]["total_count"] == 3
        assert result["summary"]["passed_count"] == 3
        assert result["summary"]["failed_count"] == 0

    def test_unsupported_extension_returns_none(self):
        """Test that an unsupported file extension raises ValueError."""
        with pytest.raises(ValueError, match="Could not extract XML"):
            DMARCParser.parse_file(b"some content", "report.pdf")

    def test_bad_zip_file_returns_no_xml_content(self):
        """A corrupt ZIP should be handled as no extractable XML content."""
        with pytest.raises(ValueError, match="Could not extract XML"):
            DMARCParser.parse_file(b"not a zip file", "report.zip")

    def test_bad_gzip_file_returns_no_xml_content(self):
        """A corrupt GZIP should be handled as no extractable XML content."""
        with pytest.raises(ValueError, match="Could not extract XML"):
            DMARCParser.parse_file(b"not a gzip file", "report.gz")

    def test_parse_xml_without_report_metadata(self):
        """Missing report_metadata should not crash parsing otherwise valid XML."""
        xml = b"""
        <feedback>
            <policy_published>
                <domain>example.com</domain>
                <p>none</p>
            </policy_published>
        </feedback>
        """

        result = DMARCParser.parse_file(xml, "report.xml")

        assert result["domain"] == "example.com"
        assert result["records"] == []
        assert result["summary"]["total_count"] == 0

    def test_parse_rfc9990_style_report_variant(self):
        """RFC 9990-era namespaces and optional fields should parse without breaking legacy shape."""
        xml = b"""
        <feedback xmlns="urn:ietf:params:xml:ns:dmarc-2.0"
                  xmlns:vendor="https://reports.example.test/dmarc">
            <version>1.0</version>
            <report_metadata>
                <org_name>Example Receiver</org_name>
                <email>dmarc@example.test</email>
                <extra_contact_info>https://example.test/dmarc</extra_contact_info>
                <report_id>2026-05-23-example.org</report_id>
                <date_range>
                    <begin>1779494400</begin>
                    <end>1779580799</end>
                </date_range>
                <error>Multiple DMARC records were ignored before treewalk.</error>
                <generator>ExampleRUA 2.0</generator>
            </report_metadata>
            <policy_published>
                <domain>example.org</domain>
                <discovery_method>treewalk</discovery_method>
                <p>quarantine</p>
                <sp>reject</sp>
                <np>none</np>
                <fo>1</fo>
                <adkim>s</adkim>
                <aspf>r</aspf>
                <testing>y</testing>
            </policy_published>
            <extension>
                <vendor:receiver>mx1.example.test</vendor:receiver>
            </extension>
            <record>
                <row>
                    <source_ip>2001:db8::1</source_ip>
                    <count>5</count>
                    <policy_evaluated>
                        <disposition>quarantine</disposition>
                        <dkim>fail</dkim>
                        <spf>pass</spf>
                        <reason>
                            <type>local_policy</type>
                            <comment>trusted relay</comment>
                        </reason>
                    </policy_evaluated>
                </row>
                <identifiers>
                    <header_from>news.example.org</header_from>
                    <envelope_from>bounce.example.org</envelope_from>
                    <envelope_to>customer.example.net</envelope_to>
                </identifiers>
                <auth_results>
                    <dkim>
                        <domain>example.net</domain>
                        <selector>selector1</selector>
                        <result>fail</result>
                        <human_result>body hash did not verify</human_result>
                    </dkim>
                    <spf>
                        <domain>bounce.example.org</domain>
                        <scope>mfrom</scope>
                        <result>pass</result>
                        <human_result>sender authorized</human_result>
                    </spf>
                </auth_results>
                <vendor:source>mail-platform</vendor:source>
            </record>
        </feedback>
        """

        result = DMARCParser.parse_file(xml, "report.xml")

        assert result["variant"] == "rfc9990"
        assert result["schema_version"] == "1.0"
        assert result["xml_namespace"] == "urn:ietf:params:xml:ns:dmarc-2.0"
        assert result["report_id"] == "2026-05-23-example.org"
        assert result["generator"] == "ExampleRUA 2.0"
        assert result["errors"] == ["Multiple DMARC records were ignored before treewalk."]
        assert result["extensions"] == {"receiver": "mx1.example.test"}
        assert result["policy"] == {
            "p": "quarantine",
            "sp": "reject",
            "pct": "100",
            "np": "none",
            "fo": "1",
            "adkim": "s",
            "aspf": "r",
            "testing": "y",
            "discovery_method": "treewalk",
        }
        record = result["records"][0]
        assert record["source_ip"] == "2001:db8::1"
        assert record["count"] == 5
        assert record["envelope_from"] == "bounce.example.org"
        assert record["envelope_to"] == "customer.example.net"
        assert record["policy_override_reasons"] == [
            {"type": "local_policy", "comment": "trusted relay"}
        ]
        assert record["dkim"] == [
            {
                "domain": "example.net",
                "result": "fail",
                "selector": "selector1",
                "human_result": "body hash did not verify",
            }
        ]
        assert record["spf"] == [
            {
                "domain": "bounce.example.org",
                "scope": "mfrom",
                "result": "pass",
                "human_result": "sender authorized",
            }
        ]
        assert record["extensions"] == {"source": "mail-platform"}
        assert result["summary"]["total_count"] == 5
        assert result["summary"]["passed_count"] == 5

    def test_parse_report_with_bad_optional_numbers_uses_safe_defaults(self):
        """Real reports with malformed counts or timestamps should not crash parsing."""
        xml = b"""
        <feedback>
            <report_metadata>
                <org_name>Example Receiver</org_name>
                <email>dmarc@example.test</email>
                <report_id>bad-numbers</report_id>
                <date_range>
                    <begin>not-a-timestamp</begin>
                    <end>also-bad</end>
                </date_range>
            </report_metadata>
            <policy_published>
                <domain>example.com</domain>
                <p>none</p>
            </policy_published>
            <record>
                <row>
                    <source_ip>203.0.113.10</source_ip>
                    <count>not-a-count</count>
                    <policy_evaluated>
                        <disposition>none</disposition>
                        <dkim>pass</dkim>
                        <spf>pass</spf>
                    </policy_evaluated>
                </row>
            </record>
        </feedback>
        """

        result = DMARCParser.parse_file(xml, "report.xml")

        assert result["begin_timestamp"] == 0
        assert result["end_timestamp"] == 0
        assert result["records"][0]["count"] == 0
        assert result["summary"]["total_count"] == 0
