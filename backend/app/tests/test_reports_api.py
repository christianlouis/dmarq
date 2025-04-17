import pytest
import io
import zipfile
import os
from fastapi.testclient import TestClient 
from sqlalchemy.orm import Session

from app.models.domain import Domain


def test_read_reports_empty(client: TestClient):
    """Test reading reports when none exist"""
    response = client.get("/api/v1/reports")
    assert response.status_code == 200
    data = response.json()
    assert data == []


def test_upload_report_no_domain(client: TestClient):
    """Test uploading a report when domain doesn't exist"""
    # Create a simple XML report
    xml_content = """<?xml version="1.0" encoding="UTF-8" ?>
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
            <domain>nonexistentdomain.com</domain>
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
                <header_from>nonexistentdomain.com</header_from>
            </identifiers>
            <auth_results>
                <dkim>
                    <domain>nonexistentdomain.com</domain>
                    <result>pass</result>
                    <selector>default</selector>
                </dkim>
                <spf>
                    <domain>nonexistentdomain.com</domain>
                    <result>fail</result>
                </spf>
            </auth_results>
        </record>
    </feedback>
    """
    
    # Create an in-memory zip file
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
        zip_file.writestr('report.xml', xml_content)
    zip_buffer.seek(0)
    
    # Upload the zip file
    response = client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_buffer, "application/zip")}
    )
    
    # Should return an error since domain doesn't exist
    assert response.status_code == 404
    data = response.json()
    assert "domain not found" in data["detail"].lower()


def test_upload_report_success(client: TestClient, db_session: Session):
    """Test successfully uploading a report"""
    # Create a domain first
    domain = Domain(name="example.com", active=True)
    db_session.add(domain)
    db_session.commit()
    
    # Create a simple XML report
    xml_content = """<?xml version="1.0" encoding="UTF-8" ?>
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
    
    # Create an in-memory zip file
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w') as zip_file:
        zip_file.writestr('report.xml', xml_content)
    zip_buffer.seek(0)
    
    # Upload the zip file
    response = client.post(
        "/api/v1/reports/upload",
        files={"file": ("report.zip", zip_buffer, "application/zip")}
    )
    
    # Should be successful
    assert response.status_code == 201
    data = response.json()
    assert data["success"] is True
    assert "report_id" in data
    
    # Check that the report was actually created
    response = client.get("/api/v1/reports")
    assert response.status_code == 200
    reports = response.json()
    assert len(reports) == 1
    assert reports[0]["report_id"] == "123456789"
    assert reports[0]["org_name"] == "google.com"