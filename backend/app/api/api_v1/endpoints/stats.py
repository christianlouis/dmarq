from typing import Dict, Any, List, Optional
from fastapi import APIRouter, Depends, Query, Path
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.utils.stats_summarizer import StatsSummarizer

router = APIRouter()

@router.get("/dashboard")
async def get_dashboard_statistics(
    db: Session = Depends(get_db),
    force_refresh: bool = Query(False, title="Force refresh of statistics"),
    period_days: int = Query(30, title="Period in days for time-based statistics")
) -> Dict[str, Any]:
    """
    Get optimized statistics for the dashboard using cached data when possible.
    This endpoint provides efficient access to statistics for large datasets.
    
    Args:
        force_refresh: If True, invalidate cache and recalculate statistics
        period_days: Period in days for time-based statistics (default: 30)
    
    Returns:
        Dictionary with dashboard statistics
    """
    # Initialize statistics summarizer
    stats_summarizer = StatsSummarizer()
    
    # If force refresh, invalidate cache
    if force_refresh:
        stats_summarizer.invalidate_cache()
    
    # Get statistics (from cache or calculate if needed)
    stats = stats_summarizer.calculate_summary_statistics(db)
    
    # Add version and timestamp
    stats["api_version"] = "1.0"
    stats["period_days"] = period_days
    
    return stats

@router.get("/domain/{domain_id}")
async def get_domain_statistics(
    domain_id: str = Path(..., title="The domain ID or name"),
    db: Session = Depends(get_db),
    force_refresh: bool = Query(False, title="Force refresh of statistics"),
    period_days: int = Query(30, title="Period in days for time-based statistics")
) -> Dict[str, Any]:
    """
    Get optimized statistics for a specific domain using cached data when possible.
    
    Args:
        domain_id: The domain ID or name
        force_refresh: If True, invalidate cache and recalculate statistics
        period_days: Period in days for time-based statistics (default: 30)
    
    Returns:
        Dictionary with domain statistics
    """
    # Initialize statistics summarizer
    stats_summarizer = StatsSummarizer()
    
    # If force refresh, invalidate domain cache
    if force_refresh:
        stats_summarizer.invalidate_cache(domain_id)
    
    # Get domain statistics (from cache or calculate if needed)
    stats = stats_summarizer.calculate_summary_statistics(db, domain_id)
    
    # Add version and timestamp
    stats["api_version"] = "1.0"
    stats["period_days"] = period_days
    
    return stats