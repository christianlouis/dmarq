import os
import pytest
from unittest.mock import patch, MagicMock
import defusedxml.ElementTree as ET

from app.services.dmarc_parser import (
    DMARCParser,
    parse_aggregate_report_xml,
    parse_aggregate_report_zip,
)


class TestDMARCParser:
    
    def setup_method(self):
        """Set up test fixtures"""
        self.parser = DMARCParser()
        
        # Sample XML string for testing
        self.sample_xml = """<?xml version="1.0" encoding="UTF-8" ?>
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
    
    def test_parse_aggregate_report_xml(self):
        """Test parsing an XML aggregate report"""
        result = parse_aggregate_report_xml(self.sample_xml)
        
        # Verify report metadata
        assert result['report_metadata']['org_name'] == 'google.com'
        assert result['report_metadata']['email'] == 'noreply-dmarc-support@google.com'
        assert result['report_metadata']['report_id'] == '123456789'
        assert result['report_metadata']['begin_date'] == 1597449600
        assert result['report_metadata']['end_date'] == 1597535999
        
        # Verify policy published
        assert result['policy_published']['domain'] == 'example.com'
        assert result['policy_published']['policy'] == 'none'
        
        # Verify record data
        assert len(result['records']) == 1
        record = result['records'][0]
        assert record['source_ip'] == '203.0.113.1'
        assert record['count'] == 2
        assert record['policy_evaluated']['disposition'] == 'none'
        assert record['policy_evaluated']['dkim'] == 'pass'
        assert record['policy_evaluated']['spf'] == 'fail'
        assert record['identifiers']['header_from'] == 'example.com'
        
    @patch('app.services.dmarc_parser.zipfile.ZipFile')
    def test_parse_aggregate_report_zip(self, mock_zipfile):
        """Test parsing a zipped aggregate report"""
        # Setup mock zipfile extraction
        mock_zip_instance = MagicMock()
        mock_zipfile.return_value.__enter__.return_value = mock_zip_instance
        mock_zip_instance.namelist.return_value = ['report.xml']
        mock_zip_instance.read.return_value = self.sample_xml.encode('utf-8')
        
        result = parse_aggregate_report_zip('/fake/path/report.zip')
        
        # Assertions similar to test_parse_aggregate_report_xml
        assert result['report_metadata']['org_name'] == 'google.com'
        assert len(result['records']) == 1
        
    def test_extract_authentication_results(self):
        """Test extracting authentication results from report"""
        # Parse the sample XML
        root = ET.fromstring(self.sample_xml)
        record_elem = root.find('./record')
        
        auth_results = self.parser._extract_authentication_results(record_elem)
        
        # Verify DKIM results
        assert len(auth_results['dkim']) == 1
        assert auth_results['dkim'][0]['domain'] == 'example.com'
        assert auth_results['dkim'][0]['result'] == 'pass'
        assert auth_results['dkim'][0]['selector'] == 'default'
        
        # Verify SPF results
        assert len(auth_results['spf']) == 1
        assert auth_results['spf'][0]['domain'] == 'example.com'
        assert auth_results['spf'][0]['result'] == 'fail'