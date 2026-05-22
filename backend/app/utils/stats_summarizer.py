import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy import case, func
from sqlalchemy.orm import Session

from app.models.domain import Domain
from app.models.report import DMARCReport, ReportRecord

# Setup logger
logger = logging.getLogger(__name__)


def _auth_status_from_counts(pass_count: int, fail_count: int) -> str:
    """Return pass, fail, mixed, or none from aggregate pass/fail counts."""
    if pass_count > 0 and fail_count > 0:
        return "mixed"
    if pass_count > 0:
        return "pass"
    if fail_count > 0:
        return "fail"
    return "none"


class StatsSummarizer:
    """
    Utility class for summarizing and caching dashboard statistics
    to improve performance with large datasets.
    """

    def __init__(self, cache_dir: str = None):
        """
        Initialize the stats summarizer with optional cache directory

        Args:
            cache_dir: Directory to store cached statistics (defaults to tmp/stats)
        """
        if cache_dir is None:
            # Default cache directory is tmp/stats under the project root
            self.cache_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))),
                "tmp",
                "stats",
            )
        else:
            self.cache_dir = cache_dir

        # Create cache directory if it doesn't exist
        os.makedirs(self.cache_dir, exist_ok=True)

    def get_cached_summary(
        self,
        domain_id: Optional[str] = None,
        max_age_minutes: int = 60,
        period_days: int = 30,
    ) -> Optional[Dict[str, Any]]:
        """
        Get cached summary statistics if available and not too old

        Args:
            domain_id: Optional domain ID to get domain-specific stats
                       If None, gets global summary
            max_age_minutes: Maximum age of cache in minutes
            period_days: Number of days used for time-based trend data

        Returns:
            Cached statistics or None if not available or too old
        """
        cache_file = self._get_cache_filename(domain_id, period_days)

        try:
            if not os.path.exists(cache_file):
                return None

            # Check file modification time
            mtime = os.path.getmtime(cache_file)
            file_age = datetime.now() - datetime.fromtimestamp(mtime)

            # If cache is too old, return None
            if file_age > timedelta(minutes=max_age_minutes):
                return None

            # Read cache file
            with open(cache_file, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.warning("Error reading cache file %s: %s", cache_file, str(e))
            return None

    def save_summary(
        self, stats: Dict[str, Any], domain_id: Optional[str] = None, period_days: int = 30
    ) -> bool:
        """
        Save summary statistics to cache

        Args:
            stats: Dictionary of statistics to cache
            domain_id: Optional domain ID for domain-specific stats
            period_days: Number of days used for time-based trend data

        Returns:
            True if save was successful, False otherwise
        """
        cache_file = self._get_cache_filename(domain_id, period_days)

        try:
            # Add timestamp
            stats["cached_at"] = datetime.now().isoformat()

            # Write to cache file
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(stats, f)

            return True
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error("Error writing cache file %s: %s", cache_file, str(e))
            return False

    def invalidate_cache(self, domain_id: Optional[str] = None) -> None:
        """
        Invalidate cache for a domain or all domains

        Args:
            domain_id: Optional domain ID to invalidate specific domain cache
                       If None, invalidates global summary cache
        """
        if domain_id is None:
            self._remove_cache_files("global_summary")
        else:
            safe_domain = domain_id.replace(".", "_").replace("/", "_")
            self._remove_cache_files(f"domain_{safe_domain}")

    def _remove_cache_files(self, prefix: str) -> None:
        """Remove cached summary files that begin with the provided prefix."""
        for filename in os.listdir(self.cache_dir):
            if filename.startswith(prefix) and filename.endswith(".json"):
                os.remove(os.path.join(self.cache_dir, filename))

    def _get_cache_filename(
        self, domain_id: Optional[str] = None, period_days: int = 30
    ) -> str:
        """
        Get the filename for a cache file

        Args:
            domain_id: Optional domain ID for domain-specific cache
            period_days: Number of days used for time-based trend data

        Returns:
            Path to the cache file
        """
        period_days = max(1, int(period_days or 30))
        if domain_id is None:
            return os.path.join(self.cache_dir, f"global_summary_{period_days}d.json")
        # Sanitize domain_id to use as filename
        safe_domain = domain_id.replace(".", "_").replace("/", "_")
        return os.path.join(self.cache_dir, f"domain_{safe_domain}_{period_days}d.json")

    def calculate_summary_statistics(
        self, db: Session, domain_id: Optional[str] = None, period_days: int = 30
    ) -> Dict[str, Any]:
        """
        Calculate summary statistics from the database

        Args:
            db: Database session
            domain_id: Optional domain ID to calculate domain-specific stats
            period_days: Number of days used for time-based trend data

        Returns:
            Dictionary with summary statistics
        """
        period_days = max(1, int(period_days or 30))

        # First check if we have cached stats
        cached_stats = self.get_cached_summary(domain_id, period_days=period_days)
        if cached_stats:
            return cached_stats

        if domain_id is None:
            stats = self._calculate_global_statistics(db, period_days)
        else:
            stats = self._calculate_domain_statistics(db, domain_id, period_days)

        # Cache the statistics
        self.save_summary(stats, domain_id, period_days)

        return stats

    def _calculate_global_statistics(self, db: Session, period_days: int = 30) -> Dict[str, Any]:
        """Calculate global statistics across all domains from the database."""
        # Count total domains
        total_domains = db.query(func.count(Domain.id)).scalar() or 0

        # Aggregate email counts from report records
        totals = db.query(
            func.coalesce(func.sum(ReportRecord.count), 0).label("total_emails"),
        ).first()
        total_emails = int(totals.total_emails) if totals else 0

        # Count compliant emails (DKIM pass OR SPF pass)
        compliant_emails = (
            db.query(func.coalesce(func.sum(ReportRecord.count), 0))
            .filter((ReportRecord.dkim == "pass") | (ReportRecord.spf == "pass"))
            .scalar()
        )
        compliant_emails = int(compliant_emails) if compliant_emails else 0

        # Count reports processed
        reports_processed = db.query(func.count(DMARCReport.id)).scalar() or 0

        # Compliance rate
        compliance_rate = 0.0
        if total_emails > 0:
            compliance_rate = round((compliant_emails / total_emails) * 100, 1)

        # Top sending sources by volume
        top_sources = self._get_top_sources(db)

        # Compliance trend over recent days
        compliance_trend = self._get_compliance_trend(db, days=period_days)

        return {
            "total_domains": total_domains,
            "total_emails": total_emails,
            "compliant_emails": compliant_emails,
            "compliance_rate": compliance_rate,
            "reports_processed": reports_processed,
            "top_sources": top_sources,
            "compliance_trend": compliance_trend,
        }

    def _calculate_domain_statistics(
        self, db: Session, domain_id: str, period_days: int = 30
    ) -> Dict[str, Any]:
        """Calculate statistics for a specific domain from the database."""
        # Look up the domain by name
        domain = db.query(Domain).filter(Domain.name == domain_id).first()
        if not domain:
            return {
                "domain": domain_id,
                "total_emails": 0,
                "compliant_emails": 0,
                "compliance_rate": 0.0,
                "reports_processed": 0,
                "sources": [],
                "compliance_trend": [],
            }

        # Aggregate email counts for this domain
        total_emails = (
            db.query(func.coalesce(func.sum(ReportRecord.count), 0))
            .join(DMARCReport, ReportRecord.report_id == DMARCReport.id)
            .filter(DMARCReport.domain_id == domain.id)
            .scalar()
        )
        total_emails = int(total_emails) if total_emails else 0

        # Count compliant emails for this domain
        compliant_emails = (
            db.query(func.coalesce(func.sum(ReportRecord.count), 0))
            .join(DMARCReport, ReportRecord.report_id == DMARCReport.id)
            .filter(DMARCReport.domain_id == domain.id)
            .filter((ReportRecord.dkim == "pass") | (ReportRecord.spf == "pass"))
            .scalar()
        )
        compliant_emails = int(compliant_emails) if compliant_emails else 0

        # Count reports for this domain
        reports_processed = (
            db.query(func.count(DMARCReport.id)).filter(DMARCReport.domain_id == domain.id).scalar()
        ) or 0

        # Compliance rate
        compliance_rate = 0.0
        if total_emails > 0:
            compliance_rate = round((compliant_emails / total_emails) * 100, 1)

        # Top sources for this domain
        sources = self._get_domain_sources(db, domain.id)

        # Compliance trend for this domain
        compliance_trend = self._get_compliance_trend(db, domain.id, days=period_days)

        return {
            "domain": domain_id,
            "total_emails": total_emails,
            "compliant_emails": compliant_emails,
            "compliance_rate": compliance_rate,
            "reports_processed": reports_processed,
            "sources": sources,
            "compliance_trend": compliance_trend,
        }

    def _get_top_sources(self, db: Session, limit: int = 10) -> List[Dict[str, Any]]:
        """Get top sending sources by email volume across all domains."""
        results = (
            db.query(
                ReportRecord.source_ip,
                func.sum(ReportRecord.count).label("total_count"),
                func.sum(case((ReportRecord.spf == "pass", ReportRecord.count), else_=0)).label(
                    "spf_pass_count"
                ),
                func.sum(case((ReportRecord.spf == "fail", ReportRecord.count), else_=0)).label(
                    "spf_fail_count"
                ),
                func.sum(case((ReportRecord.dkim == "pass", ReportRecord.count), else_=0)).label(
                    "dkim_pass_count"
                ),
                func.sum(case((ReportRecord.dkim == "fail", ReportRecord.count), else_=0)).label(
                    "dkim_fail_count"
                ),
                func.sum(
                    case(
                        (
                            (ReportRecord.dkim == "pass") | (ReportRecord.spf == "pass"),
                            ReportRecord.count,
                        ),
                        else_=0,
                    )
                ).label("dmarc_pass_count"),
            )
            .group_by(ReportRecord.source_ip)
            .order_by(func.sum(ReportRecord.count).desc())
            .limit(limit)
            .all()
        )

        return [
            {
                "ip": row.source_ip,
                "count": int(row.total_count),
                "spf_pass_count": int(row.spf_pass_count or 0),
                "spf_fail_count": int(row.spf_fail_count or 0),
                "dkim_pass_count": int(row.dkim_pass_count or 0),
                "dkim_fail_count": int(row.dkim_fail_count or 0),
                "dmarc_pass_count": int(row.dmarc_pass_count or 0),
                "dmarc_fail_count": int(row.total_count) - int(row.dmarc_pass_count or 0),
                "spf": _auth_status_from_counts(
                    int(row.spf_pass_count or 0), int(row.spf_fail_count or 0)
                ),
                "dkim": _auth_status_from_counts(
                    int(row.dkim_pass_count or 0), int(row.dkim_fail_count or 0)
                ),
                "dmarc": _auth_status_from_counts(
                    int(row.dmarc_pass_count or 0),
                    int(row.total_count) - int(row.dmarc_pass_count or 0),
                ),
            }
            for row in results
        ]

    def _get_domain_sources(
        self, db: Session, domain_db_id: int, limit: int = 10
    ) -> List[Dict[str, Any]]:
        """Get top sending sources for a specific domain."""
        results = (
            db.query(
                ReportRecord.source_ip,
                func.sum(ReportRecord.count).label("total_count"),
                func.sum(case((ReportRecord.spf == "pass", ReportRecord.count), else_=0)).label(
                    "spf_pass_count"
                ),
                func.sum(case((ReportRecord.spf == "fail", ReportRecord.count), else_=0)).label(
                    "spf_fail_count"
                ),
                func.sum(case((ReportRecord.dkim == "pass", ReportRecord.count), else_=0)).label(
                    "dkim_pass_count"
                ),
                func.sum(case((ReportRecord.dkim == "fail", ReportRecord.count), else_=0)).label(
                    "dkim_fail_count"
                ),
                func.sum(
                    case(
                        (
                            (ReportRecord.dkim == "pass") | (ReportRecord.spf == "pass"),
                            ReportRecord.count,
                        ),
                        else_=0,
                    )
                ).label("dmarc_pass_count"),
            )
            .join(DMARCReport, ReportRecord.report_id == DMARCReport.id)
            .filter(DMARCReport.domain_id == domain_db_id)
            .group_by(ReportRecord.source_ip)
            .order_by(func.sum(ReportRecord.count).desc())
            .limit(limit)
            .all()
        )

        return [
            {
                "ip": row.source_ip,
                "count": int(row.total_count),
                "spf_pass_count": int(row.spf_pass_count or 0),
                "spf_fail_count": int(row.spf_fail_count or 0),
                "dkim_pass_count": int(row.dkim_pass_count or 0),
                "dkim_fail_count": int(row.dkim_fail_count or 0),
                "dmarc_pass_count": int(row.dmarc_pass_count or 0),
                "dmarc_fail_count": int(row.total_count) - int(row.dmarc_pass_count or 0),
                "spf": _auth_status_from_counts(
                    int(row.spf_pass_count or 0), int(row.spf_fail_count or 0)
                ),
                "dkim": _auth_status_from_counts(
                    int(row.dkim_pass_count or 0), int(row.dkim_fail_count or 0)
                ),
                "dmarc": _auth_status_from_counts(
                    int(row.dmarc_pass_count or 0),
                    int(row.total_count) - int(row.dmarc_pass_count or 0),
                ),
            }
            for row in results
        ]

    def _get_compliance_trend(
        self, db: Session, domain_db_id: Optional[int] = None, days: int = 30
    ) -> List[Dict[str, Any]]:
        """
        Calculate compliance trend over recent days from report data.

        Groups reports by their date range and calculates daily compliance rates.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        cutoff_ts = int(cutoff.timestamp())

        # Build the base query for records within the time window
        query = (
            db.query(
                DMARCReport.begin_date,
                func.sum(ReportRecord.count).label("total"),
                func.sum(
                    case(
                        (
                            (ReportRecord.dkim == "pass") | (ReportRecord.spf == "pass"),
                            ReportRecord.count,
                        ),
                        else_=0,
                    )
                ).label("passed"),
            )
            .join(ReportRecord, ReportRecord.report_id == DMARCReport.id)
            .filter(DMARCReport.begin_date >= cutoff_ts)
        )

        if domain_db_id is not None:
            query = query.filter(DMARCReport.domain_id == domain_db_id)

        results = query.group_by(DMARCReport.begin_date).order_by(DMARCReport.begin_date).all()

        # Convert timestamps to dates and aggregate per day
        daily: Dict[str, Dict[str, int]] = {}
        for row in results:
            date_str = datetime.fromtimestamp(row.begin_date, tz=timezone.utc).strftime("%Y-%m-%d")
            if date_str not in daily:
                daily[date_str] = {"total": 0, "passed": 0}
            daily[date_str]["total"] += int(row.total)
            daily[date_str]["passed"] += int(row.passed)

        trend = []
        for date_str in sorted(daily.keys()):
            data = daily[date_str]
            total = data["total"]
            passed = data["passed"]
            failed = max(0, total - passed)
            compliance_rate = round((passed / total) * 100, 1) if total > 0 else 0.0
            failure_rate = round((failed / total) * 100, 1) if total > 0 else 0.0
            trend.append(
                {
                    "date": date_str,
                    "total": total,
                    "volume": total,
                    "passed": passed,
                    "failed": failed,
                    "rate": compliance_rate,
                    "compliance_rate": compliance_rate,
                    "failure_rate": failure_rate,
                }
            )

        return trend
