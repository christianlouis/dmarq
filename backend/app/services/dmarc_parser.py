import gzip
import io
import logging
import zipfile
from datetime import datetime
from typing import Any, Dict, List, Optional

from defusedxml.ElementTree import fromstring

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
            raise ValueError(
                f"File too large. Maximum size is {MAX_FILE_SIZE / (1024*1024):.1f} MB"
            )

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
    def _extract_from_zip(file_content: bytes) -> Optional[bytes]:
        """Extract the first XML file from a ZIP archive.

        Raises:
            ValueError: If the archive exceeds size/count security limits.
        """
        try:
            with zipfile.ZipFile(io.BytesIO(file_content)) as z:
                file_list = z.infolist()

                # Security: Check number of files in archive
                if len(file_list) > MAX_FILES_IN_ARCHIVE:
                    raise ValueError(
                        f"ZIP archive contains too many files ({len(file_list)}). "
                        f"Maximum is {MAX_FILES_IN_ARCHIVE}."
                    )

                # Security: Check for zip bomb by examining compression ratios
                total_uncompressed = sum(f.file_size for f in file_list)
                if total_uncompressed > MAX_UNCOMPRESSED_SIZE:
                    raise ValueError(
                        f"ZIP archive uncompressed size too large "
                        f"({total_uncompressed / (1024*1024):.1f} MB). "
                        f"Maximum is {MAX_UNCOMPRESSED_SIZE / (1024*1024):.1f} MB. "
                        "Possible zip bomb attack detected."
                    )

                # Find the first XML file in the archive
                for file_info in file_list:
                    if file_info.filename.lower().endswith(".xml"):
                        # Security: Double-check individual file size
                        if file_info.file_size > MAX_UNCOMPRESSED_SIZE:
                            raise ValueError(
                                f"XML file in archive too large "
                                f"({file_info.file_size / (1024*1024):.1f} MB)"
                            )
                        return z.read(file_info.filename)
        except zipfile.BadZipFile:
            pass
        return None

    @staticmethod
    def _extract_xml_content(file_content: bytes, filename: str) -> Optional[bytes]:
        """
        Extract XML content from various file formats (ZIP, GZIP, or plain XML)

        Raises:
            ValueError: If archive contains too many files or is potentially malicious
        """
        # Try to handle as ZIP file
        if filename.lower().endswith(".zip"):
            result = DMARCParser._extract_from_zip(file_content)
            if result is not None:
                return result

        # Try to handle as GZIP file
        if filename.lower().endswith(".gz") or filename.lower().endswith(".gzip"):
            try:
                return gzip.decompress(file_content)
            except gzip.BadGzipFile:
                pass

        # Assume it's plain XML
        if filename.lower().endswith(".xml"):
            return file_content

        return None

    @staticmethod
    def _strip_namespace(el) -> None:
        """Recursively remove XML namespace prefixes from element tags in-place."""
        if "}" in el.tag:
            el.tag = el.tag.split("}", 1)[1]
        for child in el:
            DMARCParser._strip_namespace(child)

    @staticmethod
    def _namespace(tag: str) -> str:
        """Return the XML namespace from an ElementTree tag."""
        return tag[1:].split("}", 1)[0] if tag.startswith("{") and "}" in tag else ""

    @staticmethod
    def _safe_int(value: Any, default: int = 0) -> int:
        """Parse integer fields without failing the entire report on bad optional data."""
        try:
            return int(value)
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _text(parent, name: str, default: str = "") -> str:
        """Return stripped child text for a parsed XML element."""
        return (parent.findtext(name, default) or default).strip()

    @staticmethod
    def _parse_text_list(parent, name: str) -> List[str]:
        """Return all non-empty child text values for repeated simple elements."""
        return [
            text
            for text in (DMARCParser._text(child, ".") for child in parent.findall(name))
            if text
        ]

    @staticmethod
    def _collect_extension_values(parent) -> Dict[str, Any]:
        """Capture namespaced extension values without coupling to vendor-specific schemas."""
        values: Dict[str, Any] = {}
        for child in list(parent):
            key = child.tag
            if len(child):
                values[key] = DMARCParser._collect_extension_values(child)
            else:
                values[key] = (child.text or "").strip()
        return values

    @staticmethod
    def _extension_value(element) -> Any:
        """Return a scalar or nested mapping for a vendor extension element."""
        if len(element):
            return DMARCParser._collect_extension_values(element)
        return (element.text or "").strip()

    @staticmethod
    def _detect_variant(root, xml_namespace: str) -> dict:
        """Identify the aggregate report format variant for debugging/import history."""
        version = DMARCParser._text(root, "version", "1.0")
        has_rfc9990_fields = any(
            root.find(path) is not None
            for path in (
                "report_metadata/generator",
                "policy_published/discovery_method",
                "policy_published/np",
                "policy_published/testing",
                "record/identifiers/envelope_to",
            )
        )
        if xml_namespace or has_rfc9990_fields:
            variant = "rfc9990"
        else:
            variant = "rfc7489-compatible"
        return {
            "variant": variant,
            "schema_version": version,
            "xml_namespace": xml_namespace,
        }

    @staticmethod
    def _parse_metadata(root) -> dict:
        """Parse the report_metadata section of a DMARC XML report."""
        report: dict = {}
        metadata = root.find("report_metadata")
        if metadata is not None:
            report["report_id"] = DMARCParser._text(metadata, "report_id")
            report["org_name"] = DMARCParser._text(metadata, "org_name")
            report["email"] = DMARCParser._text(metadata, "email")
            report["extra_contact_info"] = DMARCParser._text(metadata, "extra_contact_info")
            report["generator"] = DMARCParser._text(metadata, "generator")
            errors = DMARCParser._parse_text_list(metadata, "error")
            if errors:
                report["errors"] = errors

            date_range = metadata.find("date_range")
            if date_range is not None:
                begin_ts = DMARCParser._safe_int(date_range.findtext("begin", 0))
                end_ts = DMARCParser._safe_int(date_range.findtext("end", 0))
                report["begin_date"] = datetime.fromtimestamp(begin_ts).isoformat()
                report["end_date"] = datetime.fromtimestamp(end_ts).isoformat()
                report["begin_timestamp"] = begin_ts
                report["end_timestamp"] = end_ts
        return report

    @staticmethod
    def _parse_policy(root) -> dict:
        """Parse policy_published, including RFC 9990 optional fields."""
        policy = root.find("policy_published")
        if policy is None:
            return {}
        parsed = {
            "domain": DMARCParser._text(policy, "domain"),
            "policy": {
                "p": DMARCParser._text(policy, "p", "none"),
                "sp": DMARCParser._text(policy, "sp"),
                "pct": DMARCParser._text(policy, "pct", "100"),
                "np": DMARCParser._text(policy, "np"),
                "fo": DMARCParser._text(policy, "fo"),
                "adkim": DMARCParser._text(policy, "adkim"),
                "aspf": DMARCParser._text(policy, "aspf"),
                "testing": DMARCParser._text(policy, "testing"),
                "discovery_method": DMARCParser._text(policy, "discovery_method"),
            },
        }
        parsed["policy"] = {key: value for key, value in parsed["policy"].items() if value}
        parsed["policy"].setdefault("pct", "100")
        return parsed

    @staticmethod
    def _parse_policy_reasons(policy_evaluated) -> List[dict]:
        """Parse policy_evaluated/reason override data."""
        reasons = []
        for reason in policy_evaluated.findall("reason"):
            parsed = {
                "type": DMARCParser._text(reason, "type"),
                "comment": DMARCParser._text(reason, "comment"),
            }
            if parsed["type"] or parsed["comment"]:
                reasons.append(parsed)
        return reasons

    @staticmethod
    def _parse_row(record_elem) -> dict:
        """Parse the record row and policy_evaluated section."""
        parsed: dict = {}
        row = record_elem.find("row")
        if row is None:
            return parsed

        parsed["source_ip"] = DMARCParser._text(row, "source_ip")
        parsed["count"] = DMARCParser._safe_int(row.findtext("count", 0))
        policy_evaluated = row.find("policy_evaluated")
        if policy_evaluated is None:
            return parsed

        parsed["disposition"] = DMARCParser._text(policy_evaluated, "disposition", "none")
        parsed["dkim_result"] = DMARCParser._text(policy_evaluated, "dkim").lower()
        parsed["spf_result"] = DMARCParser._text(policy_evaluated, "spf").lower()
        reasons = DMARCParser._parse_policy_reasons(policy_evaluated)
        if reasons:
            parsed["policy_override_reasons"] = reasons
        return parsed

    @staticmethod
    def _parse_identifiers(record_elem) -> dict:
        """Parse identifier fields used for aggregate policy evaluation."""
        parsed: dict = {}
        identifiers = record_elem.find("identifiers")
        if identifiers is None:
            return parsed
        parsed["header_from"] = DMARCParser._text(identifiers, "header_from")
        parsed["envelope_from"] = DMARCParser._text(identifiers, "envelope_from")
        parsed["envelope_to"] = DMARCParser._text(identifiers, "envelope_to")
        return parsed

    @staticmethod
    def _parse_auth_results(record_elem) -> dict:
        """Parse uninterpreted DKIM/SPF authentication results."""
        parsed: dict = {}
        auth_results = record_elem.find("auth_results")
        if auth_results is None:
            return parsed

        spf_entries = [
            {
                "domain": DMARCParser._text(spf, "domain"),
                "scope": DMARCParser._text(spf, "scope"),
                "result": DMARCParser._text(spf, "result").lower(),
                "human_result": DMARCParser._text(spf, "human_result"),
            }
            for spf in auth_results.findall("spf")
        ]
        if spf_entries:
            parsed["spf"] = spf_entries

        dkim_entries = [
            {
                "domain": DMARCParser._text(dkim, "domain"),
                "result": DMARCParser._text(dkim, "result").lower(),
                "selector": DMARCParser._text(dkim, "selector"),
                "human_result": DMARCParser._text(dkim, "human_result"),
            }
            for dkim in auth_results.findall("dkim")
        ]
        if dkim_entries:
            parsed["dkim"] = dkim_entries
        return parsed

    @staticmethod
    def _parse_record_extensions(record_elem) -> dict:
        """Parse record-level extension elements."""
        extension_values = {}
        for child in record_elem:
            if child.tag not in {"row", "identifiers", "auth_results"}:
                extension_values[child.tag] = DMARCParser._extension_value(child)
        return {"extensions": extension_values} if extension_values else {}

    @staticmethod
    def _parse_record(record_elem) -> dict:
        """Parse a single <record> element into a dictionary."""
        record: dict = {}
        record.update(DMARCParser._parse_row(record_elem))
        record.update(DMARCParser._parse_identifiers(record_elem))
        record.update(DMARCParser._parse_auth_results(record_elem))
        record.update(DMARCParser._parse_record_extensions(record_elem))

        return record

    @staticmethod
    def _compute_summary(records: list) -> dict:
        """Compute aggregate pass/fail statistics for a list of records."""
        total_count = sum(r.get("count", 0) for r in records)
        passed_count = sum(
            r.get("count", 0)
            for r in records
            if r.get("spf_result") == "pass" or r.get("dkim_result") == "pass"
        )
        failed_count = total_count - passed_count
        return {
            "total_count": total_count,
            "passed_count": passed_count,
            "failed_count": failed_count,
            "pass_rate": (passed_count / total_count * 100) if total_count > 0 else 0,
        }

    @staticmethod
    def _parse_xml(xml_content: bytes) -> Dict[str, Any]:
        """
        Parse DMARC XML content according to RFC 7489
        """
        try:
            root = fromstring(xml_content)
            xml_namespace = DMARCParser._namespace(root.tag)
            DMARCParser._strip_namespace(root)

            report = DMARCParser._parse_metadata(root)
            report.update(DMARCParser._detect_variant(root, xml_namespace))

            # Parse policy published
            report.update(DMARCParser._parse_policy(root))

            extension = root.find("extension")
            if extension is not None:
                report["extensions"] = DMARCParser._collect_extension_values(extension)

            # Parse records
            records = [DMARCParser._parse_record(elem) for elem in root.findall("record")]
            report["records"] = records
            report["summary"] = DMARCParser._compute_summary(records)

            # Log parse results for debugging
            total_count = report["summary"]["total_count"]
            logger.info("Parsed DMARC report for domain: %s", report.get("domain"))
            logger.info("Found %s record entries with %s total messages", len(records), total_count)
            logger.info(
                "Messages passed: %s, failed: %s",
                report["summary"]["passed_count"],
                report["summary"]["failed_count"],
            )
            if records:
                logger.info(
                    "Sample record - SPF: %s, DKIM: %s",
                    records[0].get("spf_result"),
                    records[0].get("dkim_result"),
                )

            return report

        except Exception as e:
            logger.error("Error parsing DMARC XML: %s", str(e))
            raise ValueError(f"Error parsing DMARC XML: {str(e)}") from e
