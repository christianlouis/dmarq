import io
import zipfile

from fastapi.testclient import TestClient

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


def _make_zip(xml_content: str) -> bytes:
    """Create a ZIP file containing the given XML content."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("report.xml", xml_content)
    return buf.getvalue()


def test_upload_report_success(client: TestClient):
    """Uploading a valid zipped DMARC report succeeds."""
    zip_bytes = _make_zip(SAMPLE_XML)
    response = client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_bytes, "application/zip")},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["success"] is True
    assert data["domain"] == "example.com"


def test_upload_populates_domains_list(client: TestClient):
    """After uploading a report, the domain appears in the reports/domains endpoint."""
    zip_bytes = _make_zip(SAMPLE_XML)
    client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_bytes, "application/zip")},
    )

    response = client.get("/api/v1/reports/domains")
    assert response.status_code == 200
    domains = response.json()
    assert any(d == "example.com" for d in domains)


def test_reports_domains_empty(client: TestClient):
    """GET /api/v1/reports/domains returns empty list when no reports uploaded."""
    response = client.get("/api/v1/reports/domains")
    assert response.status_code == 200
    assert response.json() == []


def test_reports_summary_empty(client: TestClient):
    """GET /api/v1/reports/summary returns empty list when no reports uploaded."""
    response = client.get("/api/v1/reports/summary")
    assert response.status_code == 200
    assert response.json() == []


def test_upload_and_get_domain_summary(client: TestClient):
    """After uploading a report, the domain summary endpoint returns correct data."""
    zip_bytes = _make_zip(SAMPLE_XML)
    client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_bytes, "application/zip")},
    )

    response = client.get("/api/v1/reports/domain/example.com/summary")
    assert response.status_code == 200
    data = response.json()
    assert data["domain"] == "example.com"
    assert data["total_count"] == 2
    assert data["reports_processed"] == 1
