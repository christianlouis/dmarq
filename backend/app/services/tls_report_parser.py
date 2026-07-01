"""Parser for SMTP TLS Reporting (TLS-RPT) JSON aggregates."""

from __future__ import annotations

import gzip
import hashlib
import io
import json
import zipfile
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

MAX_TLS_REPORT_SIZE = 10 * 1024 * 1024
MAX_TLS_UNCOMPRESSED_SIZE = 100 * 1024 * 1024
MAX_TLS_FILES_IN_ARCHIVE = 10


def _clean(value: Any) -> str:
    return " ".join(str(value or "").replace("\r", " ").replace("\n", " ").split())


def _safe_int(value: Any) -> int:
    try:
        return max(int(value or 0), 0)
    except (TypeError, ValueError):
        return 0


def _parse_datetime(value: Any) -> Optional[datetime]:
    text = _clean(value)
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is not None:
        parsed = parsed.astimezone(timezone.utc)
    return parsed.replace(tzinfo=None)


def _extract_json_from_zip(file_content: bytes) -> Optional[bytes]:
    try:
        with zipfile.ZipFile(io.BytesIO(file_content)) as archive:
            files = archive.infolist()
            if len(files) > MAX_TLS_FILES_IN_ARCHIVE:
                raise ValueError("TLS report archive contains too many files")
            if sum(item.file_size for item in files) > MAX_TLS_UNCOMPRESSED_SIZE:
                raise ValueError("TLS report archive is too large after decompression")
            for item in files:
                if item.filename.lower().endswith(".json"):
                    if item.file_size > MAX_TLS_UNCOMPRESSED_SIZE:
                        raise ValueError("TLS report JSON is too large after decompression")
                    return archive.read(item.filename)
    except zipfile.BadZipFile:
        return None
    return None


def _extract_json_content(file_content: bytes, filename: str) -> bytes:
    lower = filename.lower()
    if lower.endswith(".zip"):
        extracted = _extract_json_from_zip(file_content)
        if extracted is not None:
            return extracted
        raise ValueError("Could not extract JSON content from ZIP TLS report")
    if lower.endswith((".gz", ".gzip")):
        try:
            return gzip.decompress(file_content)
        except gzip.BadGzipFile as exc:
            raise ValueError("Invalid gzip TLS report") from exc
    if lower.endswith(".json"):
        return file_content
    raise ValueError("Invalid TLS report file type. Upload .json, .json.gz, or .zip.")


def _policy_domain(policy: Dict[str, Any]) -> str:
    return _clean(policy.get("policy-domain")).lower().strip(".")


def _normalize_failure(detail: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "result_type": _clean(detail.get("result-type") or "unknown").lower(),
        "failed_session_count": _safe_int(detail.get("failed-session-count")),
        "sending_mta_ip": _clean(detail.get("sending-mta-ip")),
        "receiving_mx_hostname": _clean(detail.get("receiving-mx-hostname")).lower(),
        "receiving_mx_helo": _clean(detail.get("receiving-mx-helo")),
        "receiving_ip": _clean(detail.get("receiving-ip")),
        "failure_reason_code": _clean(detail.get("failure-reason-code")),
        "additional_information": _clean(detail.get("additional-information")),
    }


def _load_payload(json_content: bytes) -> Dict[str, Any]:
    try:
        payload = json.loads(json_content.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError("TLS report is not valid JSON") from exc
    if not isinstance(payload, dict):
        raise ValueError("TLS report JSON must be an object")
    return payload


def _normalize_policy(item: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    policy = item.get("policy") or {}
    summary = item.get("summary") or {}
    if not isinstance(policy, dict) or not isinstance(summary, dict):
        return None
    domain = _policy_domain(policy)
    if not domain:
        return None
    failures = [
        _normalize_failure(detail)
        for detail in item.get("failure-details") or []
        if isinstance(detail, dict)
    ]
    return {
        "policy_domain": domain,
        "policy_type": _clean(policy.get("policy-type")).lower(),
        "policy": policy,
        "total_successful_sessions": _safe_int(summary.get("total-successful-session-count")),
        "total_failure_sessions": _safe_int(summary.get("total-failure-session-count")),
        "failures": failures,
    }


def _normalize_policies(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    policies = []
    for item in payload.get("policies") or []:
        if not isinstance(item, dict):
            continue
        policy = _normalize_policy(item)
        if policy is not None:
            policies.append(policy)
    if not policies:
        raise ValueError("TLS report does not contain any policy-domain entries")
    return policies


class TLSReportParser:
    """Parse TLS-RPT JSON while retaining only aggregate posture data."""

    @staticmethod
    def parse_file(file_content: bytes, filename: str) -> Dict[str, Any]:
        """Parse a TLS-RPT JSON, gzip, or zip attachment into normalized dictionaries."""
        if len(file_content) > MAX_TLS_REPORT_SIZE:
            raise ValueError("TLS report is too large")
        if not file_content:
            raise ValueError("TLS report is empty")

        json_content = _extract_json_content(file_content, filename)
        if len(json_content) > MAX_TLS_UNCOMPRESSED_SIZE:
            raise ValueError("TLS report is too large after decompression")

        payload = _load_payload(json_content)
        date_range = payload.get("date-range") or {}
        policies = _normalize_policies(payload)

        report_id = _clean(payload.get("report-id"))
        if not report_id:
            report_id = "tlsrpt-" + hashlib.sha256(json_content).hexdigest()[:24]
        return {
            "report_id": report_id,
            "org_name": _clean(payload.get("organization-name")),
            "contact_info": _clean(payload.get("contact-info")),
            "begin_date": _parse_datetime(date_range.get("start-datetime")),
            "end_date": _parse_datetime(date_range.get("end-datetime")),
            "policies": policies,
        }
