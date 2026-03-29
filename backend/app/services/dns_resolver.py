"""
DNS resolver service for DMARC, SPF, and DKIM record lookups.

Provides an extensible provider architecture so that DNS data can be fetched
either via the system resolver (dnspython) or via the Cloudflare DNS API for
future Cloudflare integration.
"""

import asyncio
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

logger = logging.getLogger(__name__)

# Well-known DKIM selectors tried when no selectors are configured
COMMON_DKIM_SELECTORS: List[str] = [
    "default",
    "google",
    "mail",
    "selector1",
    "selector2",
    "dkim",
    "k1",
    "key1",
    "mta",
    "email",
    "smtp",
    "s1",
    "s2",
    "pm",
    "mandrill",
    "sendgrid",
]

# Seconds to wait for a single DNS query before giving up
DNS_TIMEOUT: float = 5.0


@dataclass
class DomainDNSResult:
    """Aggregated DNS authentication record results for one domain."""

    dmarc: bool = False
    dmarc_record: Optional[str] = None
    spf: bool = False
    spf_record: Optional[str] = None
    dkim: bool = False
    dkim_selector: Optional[str] = None
    dkim_record: Optional[str] = None
    # Track which selectors were tried so callers can surface this information
    selectors_checked: List[str] = field(default_factory=list)


class BaseDNSProvider(ABC):
    """
    Abstract base class for DNS providers.

    Subclasses implement ``lookup_txt`` and inherit the higher-level helper
    methods for DMARC, SPF, and DKIM checks so that provider-specific
    differences stay confined to a single method.
    """

    @abstractmethod
    async def lookup_txt(self, name: str) -> List[str]:
        """Return TXT record strings for *name*.

        Raises ``LookupError`` on failure (NXDOMAIN, timeout, network error
        etc.).  Returns an empty list when the name exists but has no TXT
        records.
        """

    # ------------------------------------------------------------------
    # High-level record checks built on top of lookup_txt
    # ------------------------------------------------------------------

    async def check_dmarc(self, domain: str) -> Tuple[bool, Optional[str]]:
        """Return *(found, record_string)* for the domain's DMARC TXT record."""
        try:
            records = await self.lookup_txt(f"_dmarc.{domain}")
            for record in records:
                if record.lower().startswith("v=dmarc1"):
                    return True, record
        except LookupError as exc:
            logger.debug("DMARC lookup failed for %s: %s", domain, exc)
        return False, None

    async def check_spf(self, domain: str) -> Tuple[bool, Optional[str]]:
        """Return *(found, record_string)* for the domain's SPF TXT record."""
        try:
            records = await self.lookup_txt(domain)
            for record in records:
                if record.lower().startswith("v=spf1"):
                    return True, record
        except LookupError as exc:
            logger.debug("SPF lookup failed for %s: %s", domain, exc)
        return False, None

    async def check_dkim(
        self, domain: str, selectors: List[str]
    ) -> Tuple[bool, Optional[str], Optional[str]]:
        """Return *(found, selector, record_string)* for the first working DKIM selector."""
        for selector in selectors:
            try:
                records = await self.lookup_txt(f"{selector}._domainkey.{domain}")
                for record in records:
                    if "v=dkim1" in record.lower() or "p=" in record.lower():
                        return True, selector, record
            except LookupError as exc:
                logger.debug(
                    "DKIM lookup failed for selector=%s domain=%s: %s", selector, domain, exc
                )
        return False, None, None

    async def check_domain(
        self, domain: str, selectors: Optional[List[str]] = None
    ) -> DomainDNSResult:
        """Run DMARC, SPF, and DKIM checks concurrently for *domain*.

        *selectors* are tried first; common well-known selectors are appended
        as a fallback so that a domain with no explicitly configured selectors
        can still be verified.
        """
        # Deduplicate while preserving priority order (manual selectors first)
        all_selectors: List[str] = list(selectors or [])
        for s in COMMON_DKIM_SELECTORS:
            if s not in all_selectors:
                all_selectors.append(s)

        dmarc_coro = self.check_dmarc(domain)
        spf_coro = self.check_spf(domain)
        dkim_coro = self.check_dkim(domain, all_selectors)

        (dmarc_ok, dmarc_record), (spf_ok, spf_record), (dkim_ok, dkim_sel, dkim_record) = (
            await asyncio.gather(dmarc_coro, spf_coro, dkim_coro)
        )

        return DomainDNSResult(
            dmarc=dmarc_ok,
            dmarc_record=dmarc_record,
            spf=spf_ok,
            spf_record=spf_record,
            dkim=dkim_ok,
            dkim_selector=dkim_sel,
            dkim_record=dkim_record,
            selectors_checked=all_selectors,
        )


class SystemDNSProvider(BaseDNSProvider):
    """DNS provider that resolves records via the system resolver using dnspython."""

    async def lookup_txt(self, name: str) -> List[str]:
        """Resolve TXT records using dnspython's async resolver."""
        # Import here so the module can be imported even if dnspython is absent
        # (tests can mock this method directly without needing the library).
        import dns.asyncresolver  # type: ignore[import]
        import dns.exception  # type: ignore[import]

        try:
            answers = await dns.asyncresolver.resolve(
                name, "TXT", lifetime=DNS_TIMEOUT, raise_on_no_answer=False
            )
            result: List[str] = []
            if answers:
                for rdata in answers:
                    for string in rdata.strings:
                        result.append(string.decode("utf-8", errors="replace"))
            return result
        except dns.exception.DNSException as exc:
            raise LookupError(f"TXT lookup failed for {name}: {exc}") from exc


class CloudflareDNSProvider(BaseDNSProvider):
    """DNS provider using Cloudflare's DNS-over-HTTPS (DoH) endpoint.

    This provider resolves DNS queries via Cloudflare's public DoH API
    (``1.1.1.1`` / ``cloudflare-dns.com``).  When *api_token* and *zone_id*
    are supplied, future versions will also support reading and writing DNS
    records directly through the Cloudflare REST API, enabling automated DNS
    synchronisation.

    Current status
    --------------
    * DoH-based lookups are fully functional.
    * Direct Cloudflare API integration (zone management, record sync) is
      reserved for a future release.
    """

    #: Cloudflare DNS-over-HTTPS endpoint (JSON wire format)
    CLOUDFLARE_DOH_URL: str = "https://cloudflare-dns.com/dns-query"
    #: Cloudflare REST API base URL (for future zone-management support)
    CLOUDFLARE_API_BASE: str = "https://api.cloudflare.com/client/v4"

    def __init__(
        self,
        api_token: Optional[str] = None,
        zone_id: Optional[str] = None,
    ) -> None:
        """
        Parameters
        ----------
        api_token:
            Cloudflare API token.  Required for future DNS record management;
            not needed for read-only DoH lookups.
        zone_id:
            Cloudflare zone identifier.  Required for future DNS record
            management.
        """
        self.api_token = api_token
        self.zone_id = zone_id

    async def lookup_txt(self, name: str) -> List[str]:
        """Resolve TXT records via Cloudflare's DoH endpoint (JSON format)."""
        import httpx  # type: ignore[import]

        params = {"name": name, "type": "TXT"}
        headers = {"Accept": "application/dns-json"}
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    self.CLOUDFLARE_DOH_URL,
                    params=params,
                    headers=headers,
                    timeout=DNS_TIMEOUT,
                )
                response.raise_for_status()
                data = response.json()
                records: List[str] = []
                for answer in data.get("Answer", []):
                    if answer.get("type") == 16:  # TXT record type
                        # Cloudflare wraps TXT values in double-quotes
                        txt = answer.get("data", "").strip('"')
                        records.append(txt)
                return records
        except Exception as exc:
            raise LookupError(f"Cloudflare DoH lookup failed for {name}: {exc}") from exc


def get_default_provider() -> BaseDNSProvider:
    """Return the default DNS provider (system resolver).

    In a future release this function will inspect application settings and
    return a ``CloudflareDNSProvider`` when Cloudflare credentials are
    configured.
    """
    return SystemDNSProvider()


def extract_dmarc_policy(dmarc_record: Optional[str]) -> Optional[str]:
    """Parse the *p=* tag from a DMARC TXT record string.

    Returns the policy value (e.g. ``"none"``, ``"quarantine"``,
    ``"reject"``) or ``None`` if the record is absent or unparsable.
    """
    if not dmarc_record:
        return None
    for part in dmarc_record.split(";"):
        part = part.strip()
        if part.lower().startswith("p="):
            return part[2:].strip().lower()
    return None
