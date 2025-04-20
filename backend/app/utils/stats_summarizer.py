from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging
import json
import os

# Setup logger
logger = logging.getLogger(__name__)

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
            self.cache_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "tmp", "stats")
        else:
            self.cache_dir = cache_dir
            
        # Create cache directory if it doesn't exist
        os.makedirs(self.cache_dir, exist_ok=True)
    
    def get_cached_summary(self, domain_id: Optional[str] = None, max_age_minutes: int = 60) -> Optional[Dict[str, Any]]:
        """
        Get cached summary statistics if available and not too old
        
        Args:
            domain_id: Optional domain ID to get domain-specific stats
                       If None, gets global summary
            max_age_minutes: Maximum age of cache in minutes
            
        Returns:
            Cached statistics or None if not available or too old
        """
        cache_file = self._get_cache_filename(domain_id)
        
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
            with open(cache_file, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Error reading cache file {cache_file}: {str(e)}")
            return None
    
    def save_summary(self, stats: Dict[str, Any], domain_id: Optional[str] = None) -> bool:
        """
        Save summary statistics to cache
        
        Args:
            stats: Dictionary of statistics to cache
            domain_id: Optional domain ID for domain-specific stats
            
        Returns:
            True if save was successful, False otherwise
        """
        cache_file = self._get_cache_filename(domain_id)
        
        try:
            # Add timestamp
            stats["cached_at"] = datetime.now().isoformat()
            
            # Write to cache file
            with open(cache_file, 'w') as f:
                json.dump(stats, f)
            
            return True
        except Exception as e:
            logger.error(f"Error writing cache file {cache_file}: {str(e)}")
            return False
    
    def invalidate_cache(self, domain_id: Optional[str] = None) -> None:
        """
        Invalidate cache for a domain or all domains
        
        Args:
            domain_id: Optional domain ID to invalidate specific domain cache
                       If None, invalidates global summary cache
        """
        if domain_id is None:
            # Invalidate all caches
            cache_file = self._get_cache_filename()
            if os.path.exists(cache_file):
                os.remove(cache_file)
        else:
            # Invalidate specific domain cache
            cache_file = self._get_cache_filename(domain_id)
            if os.path.exists(cache_file):
                os.remove(cache_file)
    
    def _get_cache_filename(self, domain_id: Optional[str] = None) -> str:
        """
        Get the filename for a cache file
        
        Args:
            domain_id: Optional domain ID for domain-specific cache
            
        Returns:
            Path to the cache file
        """
        if domain_id is None:
            return os.path.join(self.cache_dir, "global_summary.json")
        else:
            # Sanitize domain_id to use as filename
            safe_domain = domain_id.replace(".", "_").replace("/", "_")
            return os.path.join(self.cache_dir, f"domain_{safe_domain}.json")
    
    def calculate_summary_statistics(self, db, domain_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Calculate summary statistics from the database
        
        Args:
            db: Database session
            domain_id: Optional domain ID to calculate domain-specific stats
            
        Returns:
            Dictionary with summary statistics
        """
        # In a real implementation, this would query the database
        # using SQLAlchemy models and calculate statistics
        # For now, we'll return mock statistics
        
        # First check if we have cached stats
        cached_stats = self.get_cached_summary(domain_id)
        if cached_stats:
            return cached_stats
            
        # If no cached stats, calculate from database
        # In a real implementation, this would be done with SQL queries
        # optimized for performance with large datasets
        
        # For now, mock statistics
        if domain_id is None:
            # Global statistics
            stats = {
                "total_domains": 5,
                "total_emails": 1250,
                "compliant_emails": 1100,
                "compliance_rate": 88.0,
                "reports_processed": 25,
                "top_sources": [
                    {"ip": "192.168.1.1", "count": 150},
                    {"ip": "10.0.0.1", "count": 120},
                    {"ip": "172.16.0.1", "count": 100}
                ],
                "compliance_trend": [
                    {"date": "2025-04-13", "rate": 85.5},
                    {"date": "2025-04-14", "rate": 86.2},
                    {"date": "2025-04-15", "rate": 86.8},
                    {"date": "2025-04-16", "rate": 87.3},
                    {"date": "2025-04-17", "rate": 87.9},
                    {"date": "2025-04-18", "rate": 88.4},
                    {"date": "2025-04-19", "rate": 88.0}
                ]
            }
        else:
            # Domain-specific statistics
            stats = {
                "domain": domain_id,
                "total_emails": 250,
                "compliant_emails": 220,
                "compliance_rate": 88.0,
                "reports_processed": 5,
                "sources": [
                    {"ip": "192.168.1.1", "count": 100, "spf": "pass", "dkim": "pass"},
                    {"ip": "10.0.0.1", "count": 80, "spf": "pass", "dkim": "fail"},
                    {"ip": "172.16.0.1", "count": 70, "spf": "fail", "dkim": "pass"}
                ],
                "compliance_trend": [
                    {"date": "2025-04-13", "rate": 85.0},
                    {"date": "2025-04-14", "rate": 86.0},
                    {"date": "2025-04-15", "rate": 87.0},
                    {"date": "2025-04-16", "rate": 87.5},
                    {"date": "2025-04-17", "rate": 88.0},
                    {"date": "2025-04-18", "rate": 88.5},
                    {"date": "2025-04-19", "rate": 88.0}
                ]
            }
            
        # Cache the statistics
        self.save_summary(stats, domain_id)
        
        return stats