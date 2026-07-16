import threading
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

ACTIVE_SELECTOR_WINDOW_DAYS = 7
RECENT_SELECTOR_WINDOW_DAYS = 30
SECONDS_PER_DAY = 86_400


def _auth_status_from_counts(pass_count: int, fail_count: int, unknown_count: int = 0) -> str:
    """Return a compact status label for aggregated authentication results."""
    if pass_count > 0 and fail_count > 0:
        return "mixed"
    if pass_count > 0:
        return "pass"
    if fail_count > 0:
        return "fail"
    if unknown_count > 0:
        return "unknown"
    return "none"


def _dominant_result(counts: Dict[str, int], default: str = "none") -> str:
    """Return the highest-volume result from a result/count mapping."""
    if not counts:
        return default
    return max(counts.items(), key=lambda item: item[1])[0]


def _add_unique(target: List[str], value: Any) -> None:
    """Append a non-empty string value once, preserving first-seen order."""
    if value is None:
        return
    text = str(value).strip()
    if text and text not in target:
        target.append(text)


def _new_source_stats() -> Dict[str, Any]:
    return {
        "count": 0,
        "spf_pass_count": 0,
        "spf_fail_count": 0,
        "spf_unknown_count": 0,
        "dkim_pass_count": 0,
        "dkim_fail_count": 0,
        "dkim_unknown_count": 0,
        "dmarc_pass_count": 0,
        "dmarc_fail_count": 0,
        "disposition_counts": {},
        "spf_result": "none",
        "dkim_result": "none",
        "dmarc_result": "none",
        "disposition": "none",
        "spf_domains": [],
        "dkim_domains": [],
        "dkim_selectors": [],
        "header_from_domains": [],
        "envelope_from_domains": [],
        "extensions": {},
        "first_seen": None,
        "last_seen": None,
        "active_days": 0,
        "report_count": 0,
        "volume_history": [],
        "_active_dates": set(),
        "_report_ids": set(),
        "_volume_by_date": {},
    }


def _merge_source_metadata(source: Dict[str, Any], record: Dict[str, Any]) -> None:
    _add_unique(source["header_from_domains"], record.get("header_from"))
    _add_unique(source["envelope_from_domains"], record.get("envelope_from"))
    for spf_auth in record.get("spf") or []:
        if isinstance(spf_auth, dict):
            _add_unique(source["spf_domains"], spf_auth.get("domain"))
    for dkim_auth in record.get("dkim") or []:
        if isinstance(dkim_auth, dict):
            _add_unique(source["dkim_domains"], dkim_auth.get("domain"))
            _add_unique(source["dkim_selectors"], dkim_auth.get("selector"))
    for key, value in (record.get("extensions") or {}).items():
        if key not in source["extensions"] and value is not None:
            source["extensions"][str(key)] = str(value)


def _timestamp_from_value(value: Any) -> Optional[int]:
    """Return a Unix timestamp from common parsed-report date shapes."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        timestamp = int(value)
        return timestamp if timestamp > 0 else None
    text = str(value).strip()
    if not text:
        return None
    if text.isdigit():
        timestamp = int(text)
        return timestamp if timestamp > 0 else None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        else:
            parsed = parsed.astimezone(timezone.utc)
        return int(parsed.timestamp())
    except ValueError:
        return None


def _report_time_window(report: Dict[str, Any]) -> tuple[Optional[int], Optional[int]]:
    """Return begin/end timestamps for the observation window represented by a report."""
    begin = _timestamp_from_value(report.get("begin_timestamp"))
    if begin is None:
        begin = _timestamp_from_value(report.get("begin_date"))
    end = _timestamp_from_value(report.get("end_timestamp"))
    if end is None:
        end = _timestamp_from_value(report.get("end_date"))
    return begin, end


def _now_timestamp() -> int:
    return int(datetime.now(timezone.utc).timestamp())


def _observed_report_window(
    report: Dict[str, Any], *, now: Optional[int] = None
) -> tuple[Optional[int], Optional[int]]:
    """Return a source-observation window, clamped so UI recency never points ahead."""
    begin, end = _report_time_window(report)
    observed_start = begin if begin is not None else end
    observed_end = end if end is not None else begin
    current_time = int(now if now is not None else _now_timestamp())
    if observed_start is not None and observed_start > current_time:
        observed_start = current_time
    if observed_end is not None and observed_end > current_time:
        observed_end = current_time
    if observed_start is not None and observed_end is not None and observed_start > observed_end:
        observed_start = observed_end
    return observed_start, observed_end


def _date_bucket(timestamp: Optional[int]) -> Optional[str]:
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).date().isoformat()


def _timestamp_iso(timestamp: Optional[int]) -> Optional[str]:
    if timestamp is None:
        return None
    return datetime.fromtimestamp(timestamp, tz=timezone.utc).isoformat()


def _dkim_domain_matches(entry_domain: Any, monitored_domain: str) -> bool:
    """Keep aligned or potentially relaxed-aligned DKIM evidence for this domain."""
    value = str(entry_domain or "").strip().strip(".").lower()
    normalized_domain = monitored_domain.strip().strip(".").lower()
    if not value:
        return True
    return value == normalized_domain or value.endswith(f".{normalized_domain}")


def _selector_classification(entry: Dict[str, Any], now: int) -> tuple[str, str]:
    last_seen = entry.get("last_seen")
    active_cutoff = now - ACTIVE_SELECTOR_WINDOW_DAYS * SECONDS_PER_DAY
    recent_cutoff = now - RECENT_SELECTOR_WINDOW_DAYS * SECONDS_PER_DAY
    current_failures = int(entry.get("current_failure_count") or 0)
    current_passes = int(entry.get("current_pass_count") or 0)

    if last_seen is not None and int(last_seen) >= active_cutoff and current_failures > 0:
        return (
            "active_failing",
            f"Observed with {current_failures} failing messages in the last "
            f"{ACTIVE_SELECTOR_WINDOW_DAYS} days.",
        )
    if last_seen is not None and int(last_seen) >= active_cutoff and current_passes > 0:
        return (
            "active_passing",
            f"Observed passing DKIM in the last {ACTIVE_SELECTOR_WINDOW_DAYS} days; "
            "no current selector failure needs DNS remediation.",
        )
    if last_seen is not None and int(last_seen) >= recent_cutoff:
        return (
            "recently_observed",
            f"Observed within the last {RECENT_SELECTOR_WINDOW_DAYS} days, but not in "
            f"the active {ACTIVE_SELECTOR_WINDOW_DAYS}-day failure window.",
        )
    report_count = int(entry.get("report_count") or len(entry.get("_report_ids") or []))
    if report_count > 0:
        return (
            "historical",
            "Only historical report evidence remains; confirm the sender is still used "
            "before considering a DNS change.",
        )
    return (
        "manually_configured",
        "Configured by an operator without matching report evidence; keep it visible for "
        "review, but do not treat it as an active failure.",
    )


def _new_selector_evidence(selector: str) -> Dict[str, Any]:
    return {
        "selector": selector,
        "first_seen": None,
        "last_seen": None,
        "message_count": 0,
        "current_failure_count": 0,
        "current_pass_count": 0,
        "_report_ids": set(),
        "_record_keys": set(),
    }


def _selector_results_from_record(record: Dict[str, Any], domain: str) -> Dict[str, set[str]]:
    results: Dict[str, set[str]] = {}
    for auth in record.get("dkim") or []:
        if not isinstance(auth, dict) or not _dkim_domain_matches(auth.get("domain"), domain):
            continue
        selector = str(auth.get("selector") or "").strip()
        if selector:
            results.setdefault(selector, set()).add(
                str(auth.get("result") or "unknown").strip().lower()
            )
    return results


def _update_selector_evidence(
    row: Dict[str, Any],
    *,
    count: int,
    report_id: str,
    record_key: tuple[Any, int],
    observed_start: Optional[int],
    observed_end: Optional[int],
    active_cutoff: int,
    results: set[str],
) -> None:
    if record_key not in row["_record_keys"]:
        row["_record_keys"].add(record_key)
        row["message_count"] += count
    if report_id:
        row["_report_ids"].add(report_id)
    if observed_start is not None:
        row["first_seen"] = (
            observed_start
            if row["first_seen"] is None
            else min(int(row["first_seen"]), observed_start)
        )
    if observed_end is not None:
        row["last_seen"] = (
            observed_end if row["last_seen"] is None else max(int(row["last_seen"]), observed_end)
        )
    if observed_end is None or observed_end < active_cutoff:
        return
    if "fail" in results:
        row["current_failure_count"] += count
    elif "pass" in results:
        row["current_pass_count"] += count


def _update_source_window(
    source: Dict[str, Any],
    report: Dict[str, Any],
    count: int,
    dmarc_passed: bool,
) -> None:
    observed_start, observed_end = _observed_report_window(report)

    if observed_start is not None:
        current_first = source.get("first_seen")
        source["first_seen"] = (
            observed_start if current_first is None else min(int(current_first), observed_start)
        )
    if observed_end is not None:
        current_last = source.get("last_seen")
        source["last_seen"] = (
            observed_end if current_last is None else max(int(current_last), observed_end)
        )

    report_id = str(report.get("report_id") or "").strip()
    if report_id:
        source["_report_ids"].add(report_id)
        source["report_count"] = len(source["_report_ids"])

    bucket = _date_bucket(observed_end)
    if bucket is None:
        return
    source["_active_dates"].add(bucket)
    source["active_days"] = len(source["_active_dates"])
    day_stats = source["_volume_by_date"].setdefault(
        bucket,
        {"date": bucket, "count": 0, "passed": 0, "failed": 0},
    )
    day_stats["count"] += count
    if dmarc_passed:
        day_stats["passed"] += count
    else:
        day_stats["failed"] += count


def _source_public_entry(ip: str, data: Dict[str, Any]) -> Dict[str, Any]:
    public_entry = {key: value for key, value in data.items() if not key.startswith("_")}
    volume_by_date = data.get("_volume_by_date") or {}
    public_entry["volume_history"] = [
        volume_by_date[date_key] for date_key in sorted(volume_by_date)
    ]
    return {
        "source_ip": ip,
        **public_entry,
    }


def _update_source_from_record(
    source: Dict[str, Any],
    record: Dict[str, Any],
    report: Dict[str, Any],
) -> None:
    count = int(record.get("count") or 0)
    spf_result = record.get("spf_result", "unknown") or "unknown"
    dkim_result = record.get("dkim_result", "unknown") or "unknown"
    disposition = record.get("disposition", "none") or "none"

    source["count"] += count

    if spf_result == "pass":
        source["spf_pass_count"] += count
    elif spf_result == "fail":
        source["spf_fail_count"] += count
    else:
        source["spf_unknown_count"] += count

    if dkim_result == "pass":
        source["dkim_pass_count"] += count
    elif dkim_result == "fail":
        source["dkim_fail_count"] += count
    else:
        source["dkim_unknown_count"] += count

    dmarc_passed = spf_result == "pass" or dkim_result == "pass"
    if dmarc_passed:
        source["dmarc_pass_count"] += count
    else:
        source["dmarc_fail_count"] += count

    disposition_counts = source["disposition_counts"]
    disposition_counts[disposition] = disposition_counts.get(disposition, 0) + count

    source["spf_result"] = _auth_status_from_counts(
        source["spf_pass_count"],
        source["spf_fail_count"],
        source["spf_unknown_count"],
    )
    source["dkim_result"] = _auth_status_from_counts(
        source["dkim_pass_count"],
        source["dkim_fail_count"],
        source["dkim_unknown_count"],
    )
    source["dmarc_result"] = _auth_status_from_counts(
        source["dmarc_pass_count"],
        source["dmarc_fail_count"],
    )
    source["disposition"] = _dominant_result(disposition_counts)
    _update_source_window(source, report, count, dmarc_passed)
    _merge_source_metadata(source, record)


class ReportStore:
    """
    In-memory store for DMARC reports
    (for Milestone 1, will be replaced with database in Milestone 3)
    """

    _instance = None
    _lock = threading.Lock()

    @classmethod
    def get_instance(cls) -> "ReportStore":
        """
        Get singleton instance of the report store
        """
        if cls._instance is None:
            with cls._lock:
                if cls._instance is None:
                    cls._instance = ReportStore()
        return cls._instance

    def __init__(self):
        """
        Initialize empty report store
        """
        # Domain -> list of reports
        self.domain_reports: Dict[str, List[Dict[str, Any]]] = {}
        # Domain -> summary stats
        self.domain_summary: Dict[str, Dict[str, Any]] = {}
        # Domain -> sources (sending IPs)
        self.domain_sources: Dict[str, Dict[str, Dict[str, Any]]] = {}

    def has_report(self, domain: str, report_id: str) -> bool:
        """
        Check whether a report with the given report_id already exists for a domain.

        Args:
            domain: Domain name
            report_id: Report identifier from the DMARC report metadata

        Returns:
            True if the report already exists, False otherwise
        """
        return any(r.get("report_id") == report_id for r in self.domain_reports.get(domain, []))

    def _recompute_domain_stats(self, domain: str) -> None:
        """
        Recompute summary stats and source data for a domain from its current report list.

        Args:
            domain: Domain name whose stats should be recalculated
        """
        reports = self.domain_reports.get(domain, [])

        summary: Dict[str, Any] = {
            "total_count": 0,
            "passed_count": 0,
            "failed_count": 0,
            "reports_processed": len(reports),
        }
        sources: Dict[str, Dict[str, Any]] = {}

        for report in reports:
            report_summary = report.get("summary", {})
            summary["total_count"] += report_summary.get("total_count", 0)
            summary["passed_count"] += report_summary.get("passed_count", 0)
            summary["failed_count"] += report_summary.get("failed_count", 0)

            if "policy" in report:
                summary["policy"] = report["policy"]

            for record in report.get("records", []):
                source_ip = record.get("source_ip", "unknown")
                if source_ip not in sources:
                    sources[source_ip] = _new_source_stats()
                _update_source_from_record(sources[source_ip], record, report)

        total = summary["total_count"]
        summary["compliance_rate"] = (
            round(summary["passed_count"] / total * 100, 1) if total > 0 else 0
        )

        self.domain_summary[domain] = summary
        self.domain_sources[domain] = sources

    def add_report(self, report: Dict[str, Any]) -> None:
        """
        Add a new report to the store

        Args:
            report: Parsed DMARC report from DMARCParser
        """
        domain = report.get("domain", "unknown")

        # Initialize data structures if this is a new domain
        if domain not in self.domain_reports:
            self.domain_reports[domain] = []
            self.domain_summary[domain] = {
                "total_count": 0,
                "passed_count": 0,
                "failed_count": 0,
                "reports_processed": 0,
            }
            self.domain_sources[domain] = {}

        # Add the new report
        self.domain_reports[domain].append(report)

        # Recompute all summary stats from the full list to keep them consistent
        self._recompute_domain_stats(domain)

    def get_domains(self) -> List[str]:
        """
        Get list of all domains with reports
        """
        return list(self.domain_reports.keys())

    def get_domain_summary(self, domain: str) -> Dict[str, Any]:
        """
        Get summary statistics for a domain

        Args:
            domain: Domain name

        Returns:
            Dictionary with summary stats or empty dict if domain not found
        """
        return self.domain_summary.get(domain, {})

    def get_all_domain_summaries(self) -> Dict[str, Dict[str, Any]]:
        """
        Get summary statistics for all domains

        Returns:
            Dictionary mapping domain names to their summary stats
        """
        return self.domain_summary

    def get_report_by_id(self, report_id: str) -> Optional[Dict[str, Any]]:
        """
        Find a report by its report_id across all domains.

        Args:
            report_id: Report identifier from the DMARC report metadata

        Returns:
            The report dictionary if found, None otherwise
        """
        for reports in self.domain_reports.values():
            for report in reports:
                if report.get("report_id") == report_id:
                    return report
        return None

    def get_domain_reports(self, domain: str, limit: Optional[int] = None) -> List[Dict[str, Any]]:
        """
        Get all reports for a domain

        Args:
            domain: Domain name
            limit: Optional limit on number of reports to return

        Returns:
            List of reports or empty list if domain not found
        """
        reports = self.domain_reports.get(domain, [])

        # Sort reports by date (most recent first)
        sorted_reports = sorted(reports, key=lambda r: r.get("end_date", 0), reverse=True)

        # Calculate pass rate for each report
        for report in sorted_reports:
            total = report.get("summary", {}).get("total_count", 0)
            passed = report.get("summary", {}).get("passed_count", 0)
            if total > 0:
                report["pass_rate"] = round((passed / total) * 100, 1)
            else:
                report["pass_rate"] = 0

        # Apply limit if provided
        if limit is not None:
            return sorted_reports[:limit]
        return sorted_reports

    def get_domain_selector_evidence(
        self,
        domain: str,
        *,
        manual_selectors: Optional[List[str]] = None,
        now: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Derive selector activity and failure evidence from aggregate reports."""
        current_time = int(now if now is not None else _now_timestamp())
        active_cutoff = current_time - ACTIVE_SELECTOR_WINDOW_DAYS * SECONDS_PER_DAY
        evidence: Dict[str, Dict[str, Any]] = {}

        for report in self.get_domain_reports(domain):
            observed_start, observed_end = _observed_report_window(report, now=current_time)
            report_id = str(report.get("report_id") or "").strip()
            for record_index, record in enumerate(report.get("records") or []):
                count = max(0, int(record.get("count") or 0))
                for selector, results in _selector_results_from_record(record, domain).items():
                    row = evidence.setdefault(selector, _new_selector_evidence(selector))
                    _update_selector_evidence(
                        row,
                        count=count,
                        report_id=report_id,
                        record_key=(report_id or id(report), record_index),
                        observed_start=observed_start,
                        observed_end=observed_end,
                        active_cutoff=active_cutoff,
                        results=results,
                    )

        manual = list(dict.fromkeys(str(value).strip() for value in manual_selectors or []))
        for selector in manual:
            if not selector:
                continue
            evidence.setdefault(selector, _new_selector_evidence(selector))

        manual_set = set(manual)
        priority = {
            "active_failing": 0,
            "active_passing": 1,
            "recently_observed": 2,
            "historical": 3,
            "manually_configured": 4,
        }
        rows: List[Dict[str, Any]] = []
        for selector, raw in evidence.items():
            classification, reason = _selector_classification(raw, current_time)
            rows.append(
                {
                    "selector": selector,
                    "classification": classification,
                    "classification_reason": reason,
                    "first_seen": raw["first_seen"],
                    "first_seen_at": _timestamp_iso(raw["first_seen"]),
                    "last_seen": raw["last_seen"],
                    "last_seen_at": _timestamp_iso(raw["last_seen"]),
                    "report_count": len(raw["_report_ids"]),
                    "message_count": int(raw["message_count"]),
                    "current_failure_count": int(raw["current_failure_count"]),
                    "current_pass_count": int(raw["current_pass_count"]),
                    "manual_configured": selector in manual_set,
                    "active_window_days": ACTIVE_SELECTOR_WINDOW_DAYS,
                    "recent_window_days": RECENT_SELECTOR_WINDOW_DAYS,
                }
            )
        rows.sort(
            key=lambda row: (
                priority.get(str(row["classification"]), 99),
                -int(row.get("last_seen") or 0),
                str(row["selector"]),
            )
        )
        return rows

    def get_domain_sources(self, domain: str, days: int = 30) -> List[Dict[str, Any]]:
        """
        Get sending sources for a domain

        Args:
            domain: Domain name
            days: Number of days to look back

        Returns:
            List of source entries or empty list if domain not found
        """
        if domain not in self.domain_sources:
            return []

        # For Milestone 1, we don't filter by date
        # In a future milestone, we'll add date-based filtering
        sources = []
        for ip, data in self.domain_sources[domain].items():
            sources.append(_source_public_entry(ip, data))

        # Sort sources by count (highest first)
        return sorted(sources, key=lambda s: s["count"], reverse=True)

    def clear(self) -> None:
        """
        Clear all data in the store
        """
        self.domain_reports = {}
        self.domain_summary = {}
        self.domain_sources = {}

    def delete_report(self, domain: str, report_id: str) -> bool:
        """
        Delete a single report from the store and recompute domain statistics.

        If the domain has no remaining reports after deletion, the domain entry
        is removed entirely from all internal data structures.

        Args:
            domain: Domain name
            report_id: Report identifier to delete

        Returns:
            True if the report was found and deleted, False otherwise
        """
        reports = self.domain_reports.get(domain, [])
        original_len = len(reports)
        self.domain_reports[domain] = [r for r in reports if r.get("report_id") != report_id]

        if len(self.domain_reports[domain]) == original_len:
            # Nothing was removed
            return False

        if not self.domain_reports[domain]:
            # Domain has no remaining reports – clean up entirely
            self.domain_reports.pop(domain, None)
            self.domain_summary.pop(domain, None)
            self.domain_sources.pop(domain, None)
        else:
            self._recompute_domain_stats(domain)

        return True

    def delete_domain_with_cleanup(self, domain: str) -> bool:
        """
        Delete a domain and all its associated data

        Args:
            domain: Domain name to delete

        Returns:
            True if domain was deleted, False otherwise
        """
        if domain not in self.domain_reports:
            return False

        try:
            # Remove all data for this domain
            self.domain_reports.pop(domain, None)
            self.domain_summary.pop(domain, None)
            self.domain_sources.pop(domain, None)
            return True
        except Exception:  # pylint: disable=broad-exception-caught
            # If any exception occurs during deletion, return False
            return False
