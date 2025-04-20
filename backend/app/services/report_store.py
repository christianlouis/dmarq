from typing import Dict, List, Any, Optional
import threading
from datetime import datetime, timedelta

class ReportStore:
    """
    In-memory store for DMARC reports 
    (for Milestone 1, will be replaced with database in Milestone 3)
    """
    
    _instance = None
    _lock = threading.Lock()
    
    @classmethod
    def get_instance(cls) -> 'ReportStore':
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
        
        # Update summary stats for this domain
        summary = report.get("summary", {})
        self.domain_summary[domain]["total_count"] += summary.get("total_count", 0)
        self.domain_summary[domain]["passed_count"] += summary.get("passed_count", 0)
        self.domain_summary[domain]["failed_count"] += summary.get("failed_count", 0)
        self.domain_summary[domain]["reports_processed"] += 1
        
        # Set policy from the latest report
        if "policy" in report:
            self.domain_summary[domain]["policy"] = report["policy"]
        
        # Update source data
        report_records = report.get("records", [])
        for record in report_records:
            source_ip = record.get("source_ip", "unknown")
            if source_ip not in self.domain_sources[domain]:
                self.domain_sources[domain][source_ip] = {
                    "count": 0,
                    "spf_result": "unknown",
                    "dkim_result": "unknown",
                    "disposition": "none"
                }
            
            # Update source counts and results
            self.domain_sources[domain][source_ip]["count"] += record.get("count", 0)
            self.domain_sources[domain][source_ip]["spf_result"] = record.get("spf", "unknown") 
            self.domain_sources[domain][source_ip]["dkim_result"] = record.get("dkim", "unknown")
            self.domain_sources[domain][source_ip]["disposition"] = record.get("disposition", "none")
        
        # Calculate compliance rate (percentage of passing emails)
        if self.domain_summary[domain]["total_count"] > 0:
            pass_rate = (
                self.domain_summary[domain]["passed_count"] / 
                self.domain_summary[domain]["total_count"] * 100
            )
            self.domain_summary[domain]["compliance_rate"] = round(pass_rate, 1)
        else:
            self.domain_summary[domain]["compliance_rate"] = 0
    
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
        sorted_reports = sorted(
            reports, 
            key=lambda r: r.get("end_date", 0), 
            reverse=True
        )
        
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
            source_entry = {
                "source_ip": ip,
                **data
            }
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
        except Exception:
            # If any exception occurs during deletion, return False
            return False