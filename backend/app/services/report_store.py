from typing import Dict, List, Any
import threading

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
        
        # Add the new report
        self.domain_reports[domain].append(report)
        
        # Update summary stats for this domain
        summary = report.get("summary", {})
        self.domain_summary[domain]["total_count"] += summary.get("total_count", 0)
        self.domain_summary[domain]["passed_count"] += summary.get("passed_count", 0)
        self.domain_summary[domain]["failed_count"] += summary.get("failed_count", 0)
        self.domain_summary[domain]["reports_processed"] += 1
        
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
    
    def get_domain_reports(self, domain: str) -> List[Dict[str, Any]]:
        """
        Get all reports for a domain
        
        Args:
            domain: Domain name
            
        Returns:
            List of reports or empty list if domain not found
        """
        return self.domain_reports.get(domain, [])