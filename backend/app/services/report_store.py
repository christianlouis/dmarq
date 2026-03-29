import threading
from typing import Any, Dict, List, Optional


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
                    sources[source_ip] = {
                        "count": 0,
                        "spf_result": "unknown",
                        "dkim_result": "unknown",
                        "disposition": "none",
                    }
                sources[source_ip]["count"] += record.get("count", 0)
                sources[source_ip]["spf_result"] = record.get("spf", "unknown")
                sources[source_ip]["dkim_result"] = record.get("dkim", "unknown")
                sources[source_ip]["disposition"] = record.get("disposition", "none")

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
            source_entry = {"source_ip": ip, **data}
            sources.append(source_entry)

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
