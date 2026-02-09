import os
import zipfile
import gzip
import io
from datetime import datetime
from typing import Any, Dict, List, Optional, Union
import defusedxml.ElementTree as ET
import logging

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Security constants for file upload protection
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10 MB
MAX_UNCOMPRESSED_SIZE = 100 * 1024 * 1024  # 100 MB for zip bomb protection
MAX_FILES_IN_ARCHIVE = 10  # Maximum number of files in a zip archive

class DMARCParser:
    """
    Parser for DMARC Aggregate Reports (XML format)
    """
    
    @staticmethod
    def parse_file(file_content: bytes, filename: str) -> Dict[str, Any]:
        """
        Parse a DMARC report file (XML, zip, or gzip) into a dictionary
        
        Args:
            file_content: The binary content of the file
            filename: The name of the file (used to determine type)
            
        Returns:
            Dict containing the parsed report data
            
        Raises:
            ValueError: If file is invalid, too large, or potentially malicious
        """
        # Security: Check file size
        if len(file_content) > MAX_FILE_SIZE:
            raise ValueError(f"File too large. Maximum size is {MAX_FILE_SIZE / (1024*1024):.1f} MB")
        
        # Determine file type and extract XML content
        xml_content = DMARCParser._extract_xml_content(file_content, filename)
        if not xml_content:
            raise ValueError("Could not extract XML content from file")
        
        # Security: Check uncompressed XML size
        if len(xml_content) > MAX_UNCOMPRESSED_SIZE:
            raise ValueError(
                f"Uncompressed content too large ({len(xml_content) / (1024*1024):.1f} MB). "
                f"Maximum is {MAX_UNCOMPRESSED_SIZE / (1024*1024):.1f} MB. "
                "Possible zip bomb attack detected."
            )
            
        # Parse the XML content
        return DMARCParser._parse_xml(xml_content)
    
    @staticmethod
    def _extract_xml_content(file_content: bytes, filename: str) -> Optional[bytes]:
        """
        Extract XML content from various file formats (ZIP, GZIP, or plain XML)
        
        Raises:
            ValueError: If archive contains too many files or is potentially malicious
        """
        # Try to handle as ZIP file
        if filename.lower().endswith('.zip'):
            try:
                with zipfile.ZipFile(io.BytesIO(file_content)) as z:
                    # Security: Check number of files in archive
                    file_list = z.infolist()
                    if len(file_list) > MAX_FILES_IN_ARCHIVE:
                        raise ValueError(
                            f"ZIP archive contains too many files ({len(file_list)}). "
                            f"Maximum is {MAX_FILES_IN_ARCHIVE}."
                        )
                    
                    # Security: Check for zip bomb by examining compression ratios
                    total_uncompressed = sum(f.file_size for f in file_list)
                    if total_uncompressed > MAX_UNCOMPRESSED_SIZE:
                        raise ValueError(
                            f"ZIP archive uncompressed size too large ({total_uncompressed / (1024*1024):.1f} MB). "
                            f"Maximum is {MAX_UNCOMPRESSED_SIZE / (1024*1024):.1f} MB. "
                            "Possible zip bomb attack detected."
                        )
                    
                    # Find the first XML file in the archive
                    for file_info in file_list:
                        if file_info.filename.lower().endswith('.xml'):
                            # Security: Double-check individual file size
                            if file_info.file_size > MAX_UNCOMPRESSED_SIZE:
                                raise ValueError(
                                    f"XML file in archive too large ({file_info.file_size / (1024*1024):.1f} MB)"
                                )
                            return z.read(file_info.filename)
            except zipfile.BadZipFile:
                pass
        
        # Try to handle as GZIP file
        if filename.lower().endswith('.gz') or filename.lower().endswith('.gzip'):
            try:
                return gzip.decompress(file_content)
            except gzip.BadGzipFile:
                pass
        
        # Assume it's plain XML
        if filename.lower().endswith('.xml'):
            return file_content
            
        return None
    
    @staticmethod
    def _parse_xml(xml_content: bytes) -> Dict[str, Any]:
        """
        Parse DMARC XML content according to RFC 7489
        """
        try:
            root = ET.fromstring(xml_content)
            report = {}
            
            # Parse report metadata
            metadata = root.find("report_metadata")
            if metadata is not None:
                report["report_id"] = metadata.findtext("report_id", "")
                report["org_name"] = metadata.findtext("org_name", "")
                report["email"] = metadata.findtext("email", "")
                
                # Parse date range
                date_range = metadata.find("date_range")
                if date_range is not None:
                    begin_ts = int(date_range.findtext("begin", 0))
                    end_ts = int(date_range.findtext("end", 0))
                    report["begin_date"] = datetime.fromtimestamp(begin_ts).isoformat()
                    report["end_date"] = datetime.fromtimestamp(end_ts).isoformat()
                    report["begin_timestamp"] = begin_ts
                    report["end_timestamp"] = end_ts
            
            # Parse policy published
            policy = root.find("policy_published")
            if policy is not None:
                report["domain"] = policy.findtext("domain", "")
                report["policy"] = {
                    "p": policy.findtext("p", "none"),
                    "sp": policy.findtext("sp", ""),
                    "pct": policy.findtext("pct", "100"),
                }
            
            # Parse records
            records = []
            for record_elem in root.findall("record"):
                record = {}
                
                # Parse row
                row = record_elem.find("row")
                if row is not None:
                    record["source_ip"] = row.findtext("source_ip", "")
                    record["count"] = int(row.findtext("count", 0))
                    
                    policy_evaluated = row.find("policy_evaluated")
                    if policy_evaluated is not None:
                        record["disposition"] = policy_evaluated.findtext("disposition", "none")
                        record["dkim_result"] = policy_evaluated.findtext("dkim", "").lower()
                        record["spf_result"] = policy_evaluated.findtext("spf", "").lower()
                
                # Parse identifiers
                identifiers = record_elem.find("identifiers")
                if identifiers is not None:
                    record["header_from"] = identifiers.findtext("header_from", "")
                
                # Parse auth results
                auth_results = record_elem.find("auth_results")
                if auth_results is not None:
                    # SPF results
                    spf_entries = []
                    for spf in auth_results.findall("spf"):
                        spf_entries.append({
                            "domain": spf.findtext("domain", ""),
                            "result": spf.findtext("result", "").lower()
                        })
                    if spf_entries:
                        record["spf"] = spf_entries
                    
                    # DKIM results
                    dkim_entries = []
                    for dkim in auth_results.findall("dkim"):
                        dkim_entries.append({
                            "domain": dkim.findtext("domain", ""),
                            "result": dkim.findtext("result", "").lower(),
                            "selector": dkim.findtext("selector", "")
                        })
                    if dkim_entries:
                        record["dkim"] = dkim_entries
                
                records.append(record)
            
            report["records"] = records
            
            # Calculate summary stats
            total_count = sum(r["count"] for r in records)
            
            # Count records that pass either SPF or DKIM (or both)
            passed_count = sum(r["count"] for r in records 
                              if r.get("spf_result") == "pass" or r.get("dkim_result") == "pass")
            
            failed_count = total_count - passed_count
            
            # Log parse results for debugging
            logger.info(f"Parsed DMARC report for domain: {report.get('domain')}")
            logger.info(f"Found {len(records)} record entries with {total_count} total messages")
            logger.info(f"Messages passed: {passed_count}, failed: {failed_count}")
            
            if len(records) > 0:
                # Log the first record for debugging
                logger.info(f"Sample record - SPF: {records[0].get('spf_result')}, DKIM: {records[0].get('dkim_result')}")
            
            report["summary"] = {
                "total_count": total_count,
                "passed_count": passed_count,
                "failed_count": failed_count,
                "pass_rate": (passed_count / total_count * 100) if total_count > 0 else 0
            }
            
            return report
            
        except Exception as e:
            logger.error(f"Error parsing DMARC XML: {str(e)}")
            raise ValueError(f"Error parsing DMARC XML: {str(e)}")