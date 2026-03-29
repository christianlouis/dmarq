import io
import zipfile

import pytest
from app.services.dmarc_parser import DMARCParser

SAMPLE_XML = """\
<?xml version="1.0" encoding="UTF-8" ?>
<feedback>
    <report_metadata>
        <org_name>google.com</org_name>
        <email>noreply-dmarc-support@google.com</email>
        <report_id>123456789</report_id>
        <date_range>
            <begin>1597449600</begin>
            <end>1597535999</end>
        </date_range>
    </report_metadata>
    <policy_published>
        <domain>example.com</domain>
        <adkim>r</adkim>
        <aspf>r</aspf>
        <p>none</p>
        <sp>none</sp>
        <pct>100</pct>
    </policy_published>
    <record>
        <row>
            <source_ip>203.0.113.1</source_ip>
            <count>2</count>
            <policy_evaluated>
                <disposition>none</disposition>
                <dkim>pass</dkim>
                <spf>fail</spf>
            </policy_evaluated>
        </row>
        <identifiers>
            <header_from>example.com</header_from>
        </identifiers>
        <auth_results>
            <dkim>
                <domain>example.com</domain>
                <result>pass</result>
                <selector>default</selector>
            </dkim>
            <spf>
                <domain>example.com</domain>
                <result>fail</result>
            </spf>
        </auth_results>
    </record>
</feedback>
"""


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
        with pytest.raises(ValueError):
            DMARCParser.parse_file(b"not xml at all", "report.xml")

    def test_unsupported_extension_returns_none(self):
        """Test that an unsupported file extension raises ValueError."""
        with pytest.raises(ValueError, match="Could not extract XML"):
            DMARCParser.parse_file(b"some content", "report.pdf")
