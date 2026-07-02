import json
import logging
import os
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from hashlib import sha256
from typing import Any, Dict, List, Optional

from sqlalchemy import case, func
from sqlalchemy.orm import Session

from app.core.redaction import sanitize_for_log
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


@dataclass(frozen=True)
class _ReportWindow:
    """Normalized reporting window passed through stats queries."""

    period_days: int
    start_ts: Optional[int] = None
    end_ts: Optional[int] = None


@dataclass(frozen=True)
class _DomainStatsContext:
    """Resolved domain and window context for domain-specific summaries."""

    domain_name: str
    domain_pk: int
    window: _ReportWindow
    workspace_id: Optional[int] = None


@dataclass(frozen=True)
class _DomainStatsTotals:
    """Aggregate counters used to build a domain statistics response."""

    total_emails: int
    compliant_emails: int
    reports_processed: int


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
        cache_key: Optional[str] = None,
        workspace_id: Optional[int] = None,
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
        cache_file = self._get_cache_filename(
            domain_id,
            period_days,
            cache_key=cache_key,
            workspace_id=workspace_id,
        )

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
            logger.warning(
                "Error reading stats cache file %s: %s",
                sanitize_for_log(os.path.basename(cache_file)),
                sanitize_for_log(e),
            )
            return None

    def save_summary(
        self,
        stats: Dict[str, Any],
        domain_id: Optional[str] = None,
        period_days: int = 30,
        cache_key: Optional[str] = None,
        workspace_id: Optional[int] = None,
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
        cache_file = self._get_cache_filename(
            domain_id,
            period_days,
            cache_key=cache_key,
            workspace_id=workspace_id,
        )

        try:
            # Add timestamp
            stats["cached_at"] = datetime.now().isoformat()

            # Write to cache file
            with open(cache_file, "w", encoding="utf-8") as f:
                json.dump(stats, f)

            return True
        except Exception as e:  # pylint: disable=broad-exception-caught
            logger.error(
                "Error writing stats cache file %s: %s",
                sanitize_for_log(os.path.basename(cache_file)),
                sanitize_for_log(e),
            )
            return False

    def invalidate_cache(
        self,
        domain_id: Optional[str] = None,
        workspace_id: Optional[int] = None,
    ) -> None:
        """
        Invalidate cache for a domain or all domains

        Args:
            domain_id: Optional domain ID to invalidate specific domain cache
                       If None, invalidates global summary cache
        """
        self._remove_cache_files(self._cache_scope_prefix(domain_id, workspace_id))

    def _remove_cache_files(self, prefix: str) -> None:
        """Remove cached summary files that begin with the provided prefix."""
        for filename in os.listdir(self.cache_dir):
            if filename.startswith(prefix) and filename.endswith(".json"):
                os.remove(os.path.join(self.cache_dir, filename))

    @staticmethod
    def _hash_cache_part(value: object) -> str:
        """Return a short deterministic cache identifier for user-controlled input."""
        return sha256(str(value).encode("utf-8")).hexdigest()[:16]

    def _cache_scope_prefix(
        self,
        domain_id: Optional[str] = None,
        workspace_id: Optional[int] = None,
    ) -> str:
        """Return the stable filename prefix for a workspace/domain cache scope."""
        workspace_part = (
            f"workspace_{self._hash_cache_part(workspace_id)}"
            if workspace_id is not None
            else "workspace_all"
        )
        if domain_id is None:
            return f"{workspace_part}_global_summary"
        return f"{workspace_part}_domain_{self._hash_cache_part(domain_id)}"

    def _get_cache_filename(
        self,
        domain_id: Optional[str] = None,
        period_days: int = 30,
        cache_key: Optional[str] = None,
        workspace_id: Optional[int] = None,
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
        suffix = f"{period_days}d"
        if cache_key:
            suffix = f"{suffix}_key_{self._hash_cache_part(cache_key)}"
        prefix = self._cache_scope_prefix(domain_id, workspace_id)
        return os.path.join(self.cache_dir, f"{prefix}_{suffix}.json")

    def calculate_summary_statistics(
        self,
        db: Session,
        domain_id: Optional[str] = None,
        period_days: int = 30,
        start_ts: Optional[int] = None,
        end_ts: Optional[int] = None,
        cache_key: Optional[str] = None,
        workspace_id: Optional[int] = None,
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
        window = _ReportWindow(period_days=period_days, start_ts=start_ts, end_ts=end_ts)

        use_cache = bool(cache_key) or (start_ts is None and end_ts is None)
        if use_cache:
            cached_stats = self.get_cached_summary(
                domain_id,
                period_days=period_days,
                cache_key=cache_key,
                workspace_id=workspace_id,
            )
            if cached_stats and "change_summary" in cached_stats:
                return cached_stats

        if domain_id is None:
            stats = self._calculate_global_statistics(
                db,
                window.period_days,
                window.start_ts,
                window.end_ts,
                workspace_id=workspace_id,
            )
        else:
            stats = self._calculate_domain_statistics(
                db,
                domain_id,
                window,
                workspace_id=workspace_id,
            )

        if use_cache:
            self.save_summary(
                stats,
                domain_id,
                period_days,
                cache_key=cache_key,
                workspace_id=workspace_id,
            )

        return stats

    def _window_start_ts(
        self,
        period_days: int,
        start_ts: Optional[int] = None,
    ) -> int:
        if start_ts is not None:
            return int(start_ts)
        cutoff = datetime.now(timezone.utc) - timedelta(days=period_days)
        return int(cutoff.timestamp())

    def _apply_report_window(
        self,
        query,
        period_days: int,
        start_ts: Optional[int] = None,
        end_ts: Optional[int] = None,
    ):
        if start_ts is None and end_ts is None:
            return query
        query = query.filter(DMARCReport.begin_date >= self._window_start_ts(period_days, start_ts))
        if end_ts is not None:
            query = query.filter(DMARCReport.begin_date < int(end_ts))
        return query

    def _calculate_global_statistics(
        self,
        db: Session,
        period_days: int = 30,
        start_ts: Optional[int] = None,
        end_ts: Optional[int] = None,
        workspace_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Calculate global statistics across all domains from the database."""
        # Count total domains
        domain_query = db.query(func.count(Domain.id))
        if workspace_id is not None:
            domain_query = domain_query.filter(Domain.workspace_id == workspace_id)
        total_domains = int(domain_query.scalar() or 0)

        # Aggregate email counts from report records
        totals_query = db.query(
            func.coalesce(func.sum(ReportRecord.count), 0).label("total_emails")
        ).join(DMARCReport, ReportRecord.report_id == DMARCReport.id)
        if workspace_id is not None:
            totals_query = totals_query.join(Domain, DMARCReport.domain_id == Domain.id).filter(
                Domain.workspace_id == workspace_id
            )
        totals = self._apply_report_window(
            totals_query,
            period_days,
            start_ts,
            end_ts,
        ).first()
        total_emails = int(totals.total_emails) if totals else 0

        # Count compliant emails (DKIM pass OR SPF pass)
        compliant_query = (
            db.query(func.coalesce(func.sum(ReportRecord.count), 0))
            .join(DMARCReport, ReportRecord.report_id == DMARCReport.id)
            .filter((ReportRecord.dkim == "pass") | (ReportRecord.spf == "pass"))
        )
        if workspace_id is not None:
            compliant_query = compliant_query.join(
                Domain, DMARCReport.domain_id == Domain.id
            ).filter(Domain.workspace_id == workspace_id)
        compliant_emails = self._apply_report_window(
            compliant_query,
            period_days,
            start_ts,
            end_ts,
        ).scalar()
        compliant_emails = int(compliant_emails) if compliant_emails else 0

        # Count reports processed
        reports_query = db.query(func.count(DMARCReport.id))
        if workspace_id is not None:
            reports_query = reports_query.join(Domain, DMARCReport.domain_id == Domain.id).filter(
                Domain.workspace_id == workspace_id
            )
        reports_processed = (
            self._apply_report_window(
                reports_query,
                period_days,
                start_ts,
                end_ts,
            ).scalar()
            or 0
        )

        # Compliance rate
        compliance_rate = 0.0
        if total_emails > 0:
            compliance_rate = round((compliant_emails / total_emails) * 100, 1)

        # Top sending sources by volume
        top_sources = self._get_top_sources(
            db,
            period_days=period_days,
            start_ts=start_ts,
            end_ts=end_ts,
            workspace_id=workspace_id,
        )

        # Compliance trend over recent days
        compliance_trend = self._get_compliance_trend(
            db,
            days=period_days,
            start_ts=start_ts,
            end_ts=end_ts,
            workspace_id=workspace_id,
        )

        # Recently changed source and compliance signals
        change_summary = self._get_change_summary(
            db,
            days=period_days,
            trend=compliance_trend,
            start_ts=start_ts,
            end_ts=end_ts,
            workspace_id=workspace_id,
        )

        return {
            "total_domains": total_domains,
            "total_emails": total_emails,
            "compliant_emails": compliant_emails,
            "compliance_rate": compliance_rate,
            "reports_processed": reports_processed,
            "top_sources": top_sources,
            "compliance_trend": compliance_trend,
            "change_summary": change_summary,
        }

    def _calculate_domain_statistics(
        self,
        db: Session,
        domain_id: str,
        window: _ReportWindow,
        workspace_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Calculate statistics for a specific domain from the database."""
        domain = self._find_domain(db, domain_id, workspace_id)
        if not domain:
            return self._empty_domain_statistics(domain_id)

        context = _DomainStatsContext(
            domain_name=domain_id,
            domain_pk=domain.id,
            window=window,
            workspace_id=workspace_id,
        )
        totals = self._domain_email_totals(db, context)
        compliance_trend = self._domain_compliance_trend(db, context)
        change_summary = self._domain_change_summary(db, context, compliance_trend)

        return {
            "domain": context.domain_name,
            "total_emails": totals.total_emails,
            "compliant_emails": totals.compliant_emails,
            "compliance_rate": self._compliance_rate(
                totals.total_emails,
                totals.compliant_emails,
            ),
            "reports_processed": totals.reports_processed,
            "sources": self._domain_sources(db, context),
            "compliance_trend": compliance_trend,
            "change_summary": change_summary,
        }

    def _find_domain(
        self,
        db: Session,
        domain_name: str,
        workspace_id: Optional[int] = None,
    ) -> Optional[Domain]:
        domain_query = db.query(Domain).filter(Domain.name == domain_name)
        if workspace_id is not None:
            domain_query = domain_query.filter(Domain.workspace_id == workspace_id)
        return domain_query.first()

    def _empty_domain_statistics(self, domain_name: str) -> Dict[str, Any]:
        return {
            "domain": domain_name,
            "total_emails": 0,
            "compliant_emails": 0,
            "compliance_rate": 0.0,
            "reports_processed": 0,
            "sources": [],
            "compliance_trend": [],
            "change_summary": [],
        }

    def _count_domain_reports(
        self,
        db: Session,
        domain_pk: int,
        window: _ReportWindow,
    ) -> int:
        query = db.query(func.count(DMARCReport.id)).filter(DMARCReport.domain_id == domain_pk)
        return int(self._apply_domain_window(query, window).scalar() or 0)

    def _apply_domain_window(self, query, window: _ReportWindow):
        return self._apply_report_window(query, window.period_days, window.start_ts, window.end_ts)

    def _domain_email_totals(
        self,
        db: Session,
        context: _DomainStatsContext,
    ) -> _DomainStatsTotals:
        totals_query = (
            db.query(
                func.coalesce(func.sum(ReportRecord.count), 0).label("total"),
                func.coalesce(
                    func.sum(
                        case(
                            (
                                (ReportRecord.dkim == "pass") | (ReportRecord.spf == "pass"),
                                ReportRecord.count,
                            ),
                            else_=0,
                        )
                    ),
                    0,
                ).label("compliant"),
            )
            .join(DMARCReport, ReportRecord.report_id == DMARCReport.id)
            .filter(DMARCReport.domain_id == context.domain_pk)
        )
        row = self._apply_domain_window(totals_query, context.window).first()

        return _DomainStatsTotals(
            total_emails=int(row.total) if row else 0,
            compliant_emails=int(row.compliant) if row else 0,
            reports_processed=self._count_domain_reports(
                db,
                context.domain_pk,
                context.window,
            ),
        )

    def _domain_sources(
        self,
        db: Session,
        context: _DomainStatsContext,
    ) -> List[Dict[str, Any]]:
        return self._get_domain_sources(
            db,
            context.domain_pk,
            period_days=context.window.period_days,
            start_ts=context.window.start_ts,
            end_ts=context.window.end_ts,
        )

    def _domain_compliance_trend(
        self,
        db: Session,
        context: _DomainStatsContext,
    ) -> List[Dict[str, Any]]:
        return self._get_compliance_trend(
            db,
            context.domain_pk,
            days=context.window.period_days,
            start_ts=context.window.start_ts,
            end_ts=context.window.end_ts,
            workspace_id=context.workspace_id,
        )

    def _domain_change_summary(
        self,
        db: Session,
        context: _DomainStatsContext,
        compliance_trend: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        return self._get_change_summary(
            db,
            context.domain_pk,
            days=context.window.period_days,
            trend=compliance_trend,
            start_ts=context.window.start_ts,
            end_ts=context.window.end_ts,
            workspace_id=context.workspace_id,
        )

    def _compliance_rate(self, total_emails: int, compliant_emails: int) -> float:
        if total_emails <= 0:
            return 0.0
        return round((compliant_emails / total_emails) * 100, 1)

    def _get_top_sources(
        self,
        db: Session,
        limit: int = 10,
        period_days: int = 30,
        start_ts: Optional[int] = None,
        end_ts: Optional[int] = None,
        workspace_id: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Get top sending sources by email volume across all domains."""
        query = db.query(
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
        ).join(DMARCReport, ReportRecord.report_id == DMARCReport.id)
        if workspace_id is not None:
            query = query.join(Domain, DMARCReport.domain_id == Domain.id).filter(
                Domain.workspace_id == workspace_id
            )
        results = (
            self._apply_report_window(query, period_days, start_ts, end_ts)
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
        self,
        db: Session,
        domain_db_id: int,
        limit: int = 10,
        period_days: int = 30,
        start_ts: Optional[int] = None,
        end_ts: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Get top sending sources for a specific domain."""
        query = (
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
        )
        results = (
            self._apply_report_window(query, period_days, start_ts, end_ts)
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
        self,
        db: Session,
        domain_db_id: Optional[int] = None,
        days: int = 30,
        start_ts: Optional[int] = None,
        end_ts: Optional[int] = None,
        workspace_id: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """
        Calculate compliance trend over recent days from report data.

        Groups reports by their date range and calculates daily compliance rates.
        """
        cutoff_ts = self._window_start_ts(days, start_ts)

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
        if end_ts is not None:
            query = query.filter(DMARCReport.begin_date < int(end_ts))

        if domain_db_id is not None:
            query = query.filter(DMARCReport.domain_id == domain_db_id)
        if workspace_id is not None:
            query = query.join(Domain, DMARCReport.domain_id == Domain.id).filter(
                Domain.workspace_id == workspace_id
            )

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

    def _get_change_summary(
        self,
        db: Session,
        domain_db_id: Optional[int] = None,
        days: int = 30,
        trend: Optional[List[Dict[str, Any]]] = None,
        limit: int = 5,
        start_ts: Optional[int] = None,
        end_ts: Optional[int] = None,
        workspace_id: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """Return notable source and compliance changes for the reporting window."""
        days = max(1, int(days or 30))
        cutoff_ts = self._window_start_ts(days, start_ts)
        changes: List[Dict[str, Any]] = []

        current_query = (
            db.query(
                Domain.name.label("domain"),
                ReportRecord.source_ip.label("source_ip"),
                func.sum(ReportRecord.count).label("message_count"),
            )
            .join(DMARCReport, ReportRecord.report_id == DMARCReport.id)
            .join(Domain, DMARCReport.domain_id == Domain.id)
            .filter(DMARCReport.begin_date >= cutoff_ts)
        )
        if end_ts is not None:
            current_query = current_query.filter(DMARCReport.begin_date < int(end_ts))
        previous_query = (
            db.query(Domain.name.label("domain"), ReportRecord.source_ip.label("source_ip"))
            .join(DMARCReport, ReportRecord.report_id == DMARCReport.id)
            .join(Domain, DMARCReport.domain_id == Domain.id)
            .filter(DMARCReport.begin_date < cutoff_ts)
        )

        if domain_db_id is not None:
            current_query = current_query.filter(DMARCReport.domain_id == domain_db_id)
            previous_query = previous_query.filter(DMARCReport.domain_id == domain_db_id)
        if workspace_id is not None:
            current_query = current_query.filter(Domain.workspace_id == workspace_id)
            previous_query = previous_query.filter(Domain.workspace_id == workspace_id)

        previous_sources = {(row.domain, row.source_ip) for row in previous_query.distinct().all()}
        current_sources = (
            current_query.group_by(Domain.name, ReportRecord.source_ip)
            .order_by(func.sum(ReportRecord.count).desc())
            .all()
        )

        for row in current_sources:
            source_key = (row.domain, row.source_ip)
            if source_key in previous_sources:
                continue
            changes.append(
                {
                    "type": "new_source",
                    "severity": "warning",
                    "title": "New sending source",
                    "domain": row.domain,
                    "source_ip": row.source_ip,
                    "message_count": int(row.message_count or 0),
                    "detail": (
                        f"{row.source_ip} first appeared for {row.domain} in the last "
                        f"{days} days with {int(row.message_count or 0)} messages."
                    ),
                    "action": (
                        "Review whether this source is legitimate before changing SPF or DKIM."
                    ),
                }
            )
            if len(changes) >= limit:
                break

        compliance_drop = self._build_compliance_drop_change(trend or [])
        if compliance_drop:
            changes.append(compliance_drop)

        return changes

    @staticmethod
    def _build_compliance_drop_change(trend: List[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
        """Return a change item when the latest compliance point drops sharply."""
        if len(trend) < 2:
            return None

        previous = trend[-2]
        current = trend[-1]
        previous_rate = float(previous.get("compliance_rate", previous.get("rate", 0)) or 0)
        current_rate = float(current.get("compliance_rate", current.get("rate", 0)) or 0)
        drop = round(previous_rate - current_rate, 1)
        failed = int(current.get("failed", 0) or 0)

        if drop < 10 or failed <= 0:
            return None

        return {
            "type": "compliance_drop",
            "severity": "error" if drop >= 25 else "warning",
            "title": "Compliance dropped",
            "date": current.get("date"),
            "previous_rate": previous_rate,
            "current_rate": current_rate,
            "drop": drop,
            "failed": failed,
            "detail": (
                f"Compliance fell from {previous_rate}% to {current_rate}% "
                f"on {current.get('date')}."
            ),
            "action": "Review sources from that date and prioritize any new or failing senders.",
        }
