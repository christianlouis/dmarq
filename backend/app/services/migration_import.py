"""Read-only helpers for previewing historical DMARC platform exports."""

from __future__ import annotations

import csv
import io
import json
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Iterable, List, Optional

COLUMN_ALIASES = {
    "domain": {
        "domain",
        "header_from",
        "header from",
        "from domain",
        "policy_domain",
        "policy domain",
    },
    "report_id": {"report_id", "report id", "reportid", "id"},
    "begin_date": {"begin_date", "begin date", "date begin", "start", "start date", "period begin"},
    "end_date": {"end_date", "end date", "date end", "end", "end date", "period end", "date"},
    "source_ip": {"source_ip", "source ip", "ip", "ip address", "sender ip", "source"},
    "count": {"count", "messages", "message count", "volume", "total", "total messages"},
    "dkim": {"dkim", "dkim_result", "dkim result", "dkim aligned", "dkim pass"},
    "spf": {"spf", "spf_result", "spf result", "spf aligned", "spf pass"},
    "disposition": {"disposition", "policy disposition", "applied policy"},
    "policy": {"policy", "dmarc policy", "p", "policy_p"},
    "org_name": {"org_name", "org name", "reporter", "reporting org", "provider"},
}

PASS_VALUES = {"pass", "passed", "true", "yes", "1", "aligned", "ok"}
POLICY_VALUES = {"none", "quarantine", "reject"}
MAX_PREVIEW_CONTENT_BYTES = 1_000_000


@dataclass(frozen=True)
class MigrationImportRow:
    """Normalized read-only row from a historical export."""

    domain: Optional[str] = None
    report_id: Optional[str] = None
    begin_date: Optional[str] = None
    end_date: Optional[str] = None
    source_ip: Optional[str] = None
    count: int = 0
    dkim: Optional[str] = None
    spf: Optional[str] = None
    disposition: Optional[str] = None
    policy: Optional[str] = None
    org_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Return API-safe row data."""
        return {
            "domain": self.domain,
            "report_id": self.report_id,
            "begin_date": self.begin_date,
            "end_date": self.end_date,
            "source_ip": self.source_ip,
            "count": self.count,
            "dkim": self.dkim,
            "spf": self.spf,
            "disposition": self.disposition,
            "policy": self.policy,
            "org_name": self.org_name,
        }


def preview_migration_import(
    *,
    domain: str,
    content: str,
    source_format: str = "auto",
    max_rows: int = 50,
) -> Dict[str, Any]:
    """Parse a CSV/JSON vendor export into a read-only migration preview."""
    rows, detected_format = _load_rows(content, source_format)
    preview_rows = rows[:max_rows]
    detected_columns = _detected_columns(preview_rows)
    aliases = _column_aliases(detected_columns)
    normalized_rows: List[MigrationImportRow] = []
    warnings: List[str] = []
    rejected_count = 0

    for raw_row in preview_rows:
        normalized = _normalize_row(raw_row, aliases)
        if not normalized.source_ip and normalized.count == 0:
            rejected_count += 1
            warnings.append("Ignored a row without a sending source or message count.")
            continue
        normalized_rows.append(normalized)

    truncated_count = max(0, len(rows) - len(preview_rows))
    ignored_count = rejected_count + truncated_count
    domain_mismatches = sorted(
        {
            row.domain
            for row in normalized_rows
            if row.domain and row.domain.lower() != domain.lower()
        }
    )
    if domain_mismatches:
        warnings.append(
            "Export contains rows for other domains: " + ", ".join(domain_mismatches[:5])
        )
    if len(rows) > max_rows:
        warnings.append(f"Preview limited to the first {max_rows} rows.")

    missing_columns = _missing_recommended_columns(aliases)
    if missing_columns:
        warnings.append("Missing recommended columns: " + ", ".join(missing_columns))

    return {
        "format": detected_format,
        "row_count": len(rows),
        "normalized_count": len(normalized_rows),
        "ignored_count": ignored_count,
        "rejected_count": rejected_count,
        "truncated_count": truncated_count,
        "detected_columns": detected_columns,
        "mapped_columns": aliases,
        "warnings": warnings,
        "baseline": _build_baseline(normalized_rows),
        "sample_rows": [row.to_dict() for row in normalized_rows[:10]],
    }


def _load_rows(content: str, source_format: str) -> tuple[List[Dict[str, Any]], str]:
    normalized_format = (source_format or "auto").strip().lower()
    if normalized_format not in {"auto", "csv", "json"}:
        raise ValueError("format must be auto, csv, or json")

    text = content.strip()
    if not text:
        raise ValueError("import content is empty")
    if len(text.encode("utf-8")) > MAX_PREVIEW_CONTENT_BYTES:
        raise ValueError("import content is too large for preview")

    if normalized_format == "json" or (normalized_format == "auto" and text[:1] in {"[", "{"}):
        return _load_json_rows(text), "json"
    return _load_csv_rows(text), "csv"


def _load_csv_rows(text: str) -> List[Dict[str, Any]]:
    reader = csv.DictReader(io.StringIO(text))
    if not reader.fieldnames:
        raise ValueError("CSV content must include a header row")
    return [dict(row) for row in reader]


def _load_json_rows(text: str) -> List[Dict[str, Any]]:
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"JSON content could not be parsed: {exc.msg}") from exc

    if isinstance(data, list):
        rows = data
    elif isinstance(data, dict):
        rows = _first_list_value(data, ["rows", "reports", "data", "items", "records"])
        if rows is None:
            rows = [data]
    else:
        raise ValueError("JSON content must be an object or list")

    if not all(isinstance(row, dict) for row in rows):
        raise ValueError("JSON rows must be objects")
    return [dict(row) for row in rows]


def _first_list_value(data: Dict[str, Any], keys: Iterable[str]) -> Optional[List[Any]]:
    for key in keys:
        value = data.get(key)
        if isinstance(value, list):
            return value
    return None


def _detected_columns(rows: List[Dict[str, Any]]) -> List[str]:
    columns: List[str] = []
    for row in rows:
        for key in row:
            key_str = str(key)
            if key_str not in columns:
                columns.append(key_str)
    return columns


def _column_aliases(columns: List[str]) -> Dict[str, str]:
    normalized_columns = {_normalize_column_name(column): column for column in columns}
    aliases: Dict[str, str] = {}
    for canonical, candidates in COLUMN_ALIASES.items():
        for candidate in candidates:
            column = normalized_columns.get(_normalize_column_name(candidate))
            if column:
                aliases[canonical] = column
                break
    return aliases


def _normalize_column_name(value: str) -> str:
    return " ".join(value.replace("_", " ").replace("-", " ").strip().lower().split())


def _normalize_row(row: Dict[str, Any], aliases: Dict[str, str]) -> MigrationImportRow:
    return MigrationImportRow(
        domain=_clean_text(_row_value(row, aliases, "domain")),
        report_id=_clean_text(_row_value(row, aliases, "report_id")),
        begin_date=_clean_date(_row_value(row, aliases, "begin_date")),
        end_date=_clean_date(_row_value(row, aliases, "end_date")),
        source_ip=_clean_text(_row_value(row, aliases, "source_ip")),
        count=_clean_int(_row_value(row, aliases, "count")),
        dkim=_clean_result(_row_value(row, aliases, "dkim")),
        spf=_clean_result(_row_value(row, aliases, "spf")),
        disposition=_clean_text(_row_value(row, aliases, "disposition")),
        policy=_clean_policy(_row_value(row, aliases, "policy")),
        org_name=_clean_text(_row_value(row, aliases, "org_name")),
    )


def _row_value(row: Dict[str, Any], aliases: Dict[str, str], key: str) -> Any:
    column = aliases.get(key)
    if column is None:
        return None
    return row.get(column)


def _clean_text(value: Any) -> Optional[str]:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _clean_date(value: Any) -> Optional[str]:
    text = _clean_text(value)
    if text is None:
        return None
    if text.isdigit():
        try:
            return datetime.fromtimestamp(int(text), tz=timezone.utc).date().isoformat()
        except (OverflowError, ValueError):
            return text
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date().isoformat()
    except ValueError:
        return text


def _clean_int(value: Any) -> int:
    if value is None:
        return 0
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return max(0, int(value))
    text = str(value).strip().replace(",", "")
    try:
        return max(0, int(float(text)))
    except ValueError:
        return 0


def _clean_result(value: Any) -> Optional[str]:
    text = _clean_text(value)
    if text is None:
        return None
    normalized = text.lower()
    if normalized in PASS_VALUES:
        return "pass"
    if normalized in {"fail", "failed", "false", "no", "0", "unaligned"}:
        return "fail"
    return normalized


def _clean_policy(value: Any) -> Optional[str]:
    text = _clean_text(value)
    if text is None:
        return None
    normalized = text.lower().removeprefix("p=").strip()
    return normalized if normalized in POLICY_VALUES else text


def _missing_recommended_columns(aliases: Dict[str, str]) -> List[str]:
    recommended = ["source_ip", "count", "dkim", "spf", "policy"]
    return [column for column in recommended if column not in aliases]


def _build_baseline(rows: List[MigrationImportRow]) -> Dict[str, Any]:
    total_emails = sum(row.count for row in rows)
    aligned_emails = sum(row.count for row in rows if row.dkim == "pass" or row.spf == "pass")
    source_count = len({row.source_ip for row in rows if row.source_ip})
    report_ids = {row.report_id for row in rows if row.report_id}
    policy_counts = Counter(row.policy for row in rows if row.policy)
    start_dates = [row.begin_date for row in rows if row.begin_date]
    end_dates = [row.end_date for row in rows if row.end_date]
    return {
        "report_count": len(report_ids) if report_ids else len(rows),
        "total_emails": total_emails,
        "source_count": source_count,
        "compliance_rate": round((aligned_emails / total_emails * 100), 2) if total_emails else 0.0,
        "policy": policy_counts.most_common(1)[0][0] if policy_counts else None,
        "date_start": min(start_dates) if start_dates else None,
        "date_end": max(end_dates) if end_dates else None,
    }
