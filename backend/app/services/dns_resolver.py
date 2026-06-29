"""
DNS resolver service for DMARC, SPF, DKIM, and PTR record lookups.

Provides an extensible provider architecture so that DNS data can be fetched
either via the system resolver (dnspython) or via the Cloudflare DNS API for
future Cloudflare integration.
"""

import asyncio
import ipaddress
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


def _sanitize_for_log(value: str) -> str:
    """Remove newline and carriage-return characters to prevent log injection."""
    return value.replace("\r", "").replace("\n", "")


def _ip_to_arpa_name(ip: str) -> str:
    """Convert an IP address string to its reverse-DNS ARPA lookup name.

    E.g. ``"1.2.3.4"`` → ``"4.3.2.1.in-addr.arpa"``
         ``"2001:db8::1"`` → ``"...ip6.arpa"``

    Raises ``ValueError`` for invalid IP address strings.
    """
    addr = ipaddress.ip_address(ip)
    if isinstance(addr, ipaddress.IPv4Address):
        parts = ip.split(".")
        return ".".join(reversed(parts)) + ".in-addr.arpa"
    # IPv6: expand, strip colons, reverse nibbles
    expanded = addr.exploded.replace(":", "")
    return ".".join(reversed(expanded)) + ".ip6.arpa"


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

DMARC_POLICY_VALUES = {"none", "quarantine", "reject"}
DMARCBIS_ACTIVE_TAGS = {
    "adkim",
    "aspf",
    "fo",
    "np",
    "p",
    "psd",
    "rua",
    "ruf",
    "sp",
    "t",
    "v",
}


@dataclass
class DomainDNSResult:
    """Aggregated DNS authentication record results for one domain."""

    dmarc: bool = False
    dmarc_record: Optional[str] = None
    spf: bool = False
    spf_record: Optional[str] = None
    dkim: bool = False
    # All selectors that resolved to a valid DKIM record (may be multiple)
    dkim_selectors: List[str] = field(default_factory=list)
    dkim_record: Optional[str] = None
    # Track which selectors were tried so callers can surface this information
    selectors_checked: List[str] = field(default_factory=list)
    dmarc_policy_domain: Optional[str] = None
    dmarc_discovery_method: Optional[str] = None
    dmarc_tags: Dict[str, str] = field(default_factory=dict)
    dmarc_warnings: List[str] = field(default_factory=list)
    dmarc_suggestions: List[str] = field(default_factory=list)


def _normalize_dns_name(domain: str) -> str:
    return domain.strip().strip(".").lower()


def _is_valid_dmarc_uri_list(value: str) -> bool:
    uris = [part.strip() for part in value.split(",") if part.strip()]
    if not uris:
        return False
    return all(bool(urlparse(uri).scheme) for uri in uris)


def _dmarc_uri_domains(value: Optional[str]) -> List[Tuple[str, str]]:
    destinations: List[Tuple[str, str]] = []
    for item in (value or "").split(","):
        uri = item.strip()
        if not uri:
            continue
        parsed = urlparse(uri)
        mailbox = parsed.path.split("!", 1)[0]
        if parsed.scheme.lower() != "mailto" or "@" not in mailbox:
            destinations.append((uri, ""))
            continue
        destinations.append((uri, mailbox.rsplit("@", 1)[-1].strip(".").lower()))
    return destinations


def parse_dmarc_record_tags(dmarc_record: Optional[str]) -> Dict[str, str]:
    """Parse active RFC 9989 DMARC policy tags from a TXT record.

    RFC 9989 requires ``v=DMARC1`` to be the first tag and keeps the version
    value case-sensitive. Unknown tags are ignored. Historic tags such as
    ``pct``, ``rf``, and ``ri`` are intentionally not returned here.
    """
    if not dmarc_record:
        return {}

    parts = [part.strip() for part in dmarc_record.split(";") if part.strip()]
    if not parts or "=" not in parts[0]:
        return {}

    first_name, first_value = (item.strip() for item in parts[0].split("=", 1))
    if first_name.lower() != "v" or first_value != "DMARC1":
        return {}

    tags: Dict[str, str] = {"v": first_value}
    for part in parts[1:]:
        if "=" not in part:
            continue
        name, value = (item.strip() for item in part.split("=", 1))
        name = name.lower()
        if name in DMARCBIS_ACTIVE_TAGS and name not in tags:
            tags[name] = value.strip()
    return tags


def _valid_policy_value(value: Optional[str]) -> Optional[str]:
    normalized = (value or "").strip().lower()
    return normalized if normalized in DMARC_POLICY_VALUES else None


def _record_has_valid_policy_or_reporting(tags: Dict[str, str]) -> bool:
    if _valid_policy_value(tags.get("p")):
        return True
    rua = tags.get("rua")
    return bool(rua and _is_valid_dmarc_uri_list(rua))


def _select_valid_dmarc_record(records: List[str]) -> Tuple[Optional[str], Dict[str, str]]:
    """Return a single valid DMARC record, discarding ambiguous targets."""
    valid_records: List[Tuple[str, Dict[str, str]]] = []
    for record in records:
        tags = parse_dmarc_record_tags(record)
        if tags and _record_has_valid_policy_or_reporting(tags):
            valid_records.append((record, tags))

    if len(valid_records) != 1:
        return None, {}
    return valid_records[0]


def _tree_walk_domains(domain: str) -> List[str]:
    labels = [label for label in _normalize_dns_name(domain).split(".") if label]
    if len(labels) <= 1:
        return []

    domains: List[str] = []
    if len(labels) <= 8:
        target_labels = labels[1:]
    else:
        target_labels = labels[-7:]
    while len(target_labels) > 1 and len(domains) < 7:
        domains.append(".".join(target_labels))
        target_labels = target_labels[1:]
    return domains


def effective_dmarc_policy(tags: Dict[str, str]) -> Optional[str]:
    """Return the RFC 9989 effective base policy from parsed tags.

    Records with a valid reporting URI but without a valid ``p`` tag are treated
    as monitoring mode, matching RFC 9989 policy discovery behavior.
    """
    policy = _valid_policy_value(tags.get("p"))
    if policy:
        return policy
    if tags.get("rua") and _is_valid_dmarc_uri_list(tags["rua"]):
        return "none"
    return None


def _lint_dmarc_tags(
    tags: Dict[str, str],
    *,
    checked_domain: str,
    policy_domain: Optional[str],
    discovery_method: Optional[str],
) -> Tuple[List[str], List[str]]:
    warnings: List[str] = []
    suggestions: List[str] = []
    if not tags:
        return ["No valid DMARC policy record was discovered."], [
            "Publish v=DMARC1 with p=none and a rua address before tightening policy."
        ]

    if discovery_method == "treewalk" and policy_domain:
        suggestions.append(
            f"DMARC policy for {checked_domain} is inherited from {policy_domain} via tree walk."
        )
    if not _valid_policy_value(tags.get("p")) and not tags.get("rua"):
        warnings.append("DMARC record has neither a valid p tag nor a rua reporting URI.")
    if not tags.get("rua"):
        suggestions.append("Add rua=mailto:... so aggregate reports can reach DMARQ.")

    warnings.extend(_lint_policy_tags(tags))
    warnings.extend(_lint_alignment_tags(tags))
    warnings.extend(_lint_yes_no_tags(tags))
    warnings.extend(_lint_failure_options(tags))
    return warnings, suggestions


def _lint_policy_tags(tags: Dict[str, str]) -> List[str]:
    warnings: List[str] = []
    for tag in ("p", "sp", "np"):
        value = tags.get(tag)
        if value and not _valid_policy_value(value):
            warnings.append(f"DMARC {tag} tag uses unsupported policy value {value!r}.")
    return warnings


def _lint_alignment_tags(tags: Dict[str, str]) -> List[str]:
    warnings: List[str] = []
    for tag in ("adkim", "aspf"):
        value = (tags.get(tag) or "").lower()
        if value and value not in {"r", "s"}:
            warnings.append(f"DMARC {tag} tag should be r or s.")
    return warnings


def _lint_yes_no_tags(tags: Dict[str, str]) -> List[str]:
    warnings: List[str] = []
    for tag in ("psd", "t"):
        value = (tags.get(tag) or "").lower()
        if value and value not in {"y", "n"}:
            warnings.append(f"DMARC {tag} tag should be y or n.")
    return warnings


def _lint_failure_options(tags: Dict[str, str]) -> List[str]:
    fo = tags.get("fo")
    if fo:
        allowed = {"0", "1", "d", "s"}
        invalid = [part for part in fo.split(":") if part not in allowed]
        if invalid:
            return ["DMARC fo tag contains unsupported failure options."]
    return []


async def _lint_external_reporting_destinations(
    provider: "BaseDNSProvider",
    tags: Dict[str, str],
    *,
    policy_domain: Optional[str],
) -> List[str]:
    if not policy_domain:
        return []

    warnings: List[str] = []
    for tag in ("rua", "ruf"):
        for uri, destination_domain in _dmarc_uri_domains(tags.get(tag)):
            if not destination_domain:
                warnings.append(f"DMARC {tag} URI {uri!r} is not a supported mailto URI.")
                continue
            if destination_domain == policy_domain:
                continue

            auth_name = f"{policy_domain}._report._dmarc.{destination_domain}"
            try:
                records = await provider.lookup_txt(auth_name)
            except LookupError:
                records = []
            if not any(record.strip().lower().startswith("v=dmarc1") for record in records):
                warnings.append(
                    f"External {tag} destination {destination_domain} is missing "
                    f"authorization TXT at {auth_name}."
                )
    return warnings


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

    async def _lookup_valid_dmarc_at(self, domain: str) -> Tuple[Optional[str], Dict[str, str]]:
        """Return a valid DMARC record and parsed tags for one policy domain."""
        try:
            records = await self.lookup_txt(f"_dmarc.{domain}")
            return _select_valid_dmarc_record(records)
        except LookupError as exc:
            logger.debug("DMARC lookup failed for %s: %s", _sanitize_for_log(domain), exc)
        return None, {}

    async def discover_dmarc_policy(
        self, domain: str
    ) -> Tuple[bool, Optional[str], Optional[str], Optional[str], Dict[str, str]]:
        """Discover the applicable RFC 9989 DMARC policy record."""
        normalized_domain = _normalize_dns_name(domain)
        record, tags = await self._lookup_valid_dmarc_at(normalized_domain)
        if record:
            return True, record, normalized_domain, "author", tags

        for candidate in _tree_walk_domains(normalized_domain):
            record, tags = await self._lookup_valid_dmarc_at(candidate)
            if record:
                return True, record, candidate, "treewalk", tags

        return False, None, None, None, {}

    async def check_dmarc(self, domain: str) -> Tuple[bool, Optional[str]]:
        """Return *(found, record_string)* for the applicable DMARC TXT record."""
        found, record, _, _, _ = await self.discover_dmarc_policy(domain)
        if found:
            return True, record
        return False, None

    async def check_spf(self, domain: str) -> Tuple[bool, Optional[str]]:
        """Return *(found, record_string)* for the domain's SPF TXT record."""
        try:
            records = await self.lookup_txt(domain)
            for record in records:
                if record.lower().startswith("v=spf1"):
                    return True, record
        except LookupError as exc:
            logger.debug("SPF lookup failed for %s: %s", _sanitize_for_log(domain), exc)
        return False, None

    async def lookup_ptr(self, ip: str) -> Optional[str]:
        """Return the PTR (reverse DNS) hostname for *ip*, or ``None`` if unavailable.

        The base implementation always returns ``None``.  Concrete providers
        override this to perform an actual DNS PTR lookup so that existing
        test doubles (which only implement ``lookup_txt``) keep working without
        modification.
        """
        return None

    async def lookup_cname(self, name: str) -> Optional[str]:
        """Return the CNAME target for *name*, or ``None`` if unavailable.

        Provider test doubles that only support TXT lookups can keep using the
        base implementation. DNS guidance treats ``None`` as "no visible CNAME"
        instead of a lookup failure.
        """
        return None

    async def check_dkim(
        self, domain: str, selectors: List[str]
    ) -> Tuple[bool, List[str], Optional[str]]:
        """Return *(found, matching_selectors, first_record_string)* for all working DKIM selectors.

        All selectors in *selectors* are checked and every one that resolves to
        a valid DKIM TXT record is collected.  The boolean is ``True`` when at
        least one selector resolved.  *first_record_string* is the record text
        for the first matching selector (useful for display purposes).
        """
        matching_selectors: List[str] = []
        first_record: Optional[str] = None
        for selector in selectors:
            try:
                records = await self.lookup_txt(f"{selector}._domainkey.{domain}")
                for record in records:
                    if "v=dkim1" in record.lower() or "p=" in record.lower():
                        matching_selectors.append(selector)
                        if first_record is None:
                            first_record = record
                        break
            except LookupError as exc:
                logger.debug(
                    "DKIM lookup failed for selector=%s domain=%s: %s",
                    selector,
                    _sanitize_for_log(domain),
                    exc,
                )
        return bool(matching_selectors), matching_selectors, first_record

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

        dmarc_coro = self.discover_dmarc_policy(domain)
        spf_coro = self.check_spf(domain)
        dkim_coro = self.check_dkim(domain, all_selectors)

        (
            (dmarc_ok, dmarc_record, dmarc_policy_domain, dmarc_discovery_method, dmarc_tags),
            (spf_ok, spf_record),
            (dkim_ok, dkim_sels, dkim_record),
        ) = await asyncio.gather(dmarc_coro, spf_coro, dkim_coro)

        dmarc_tags = dmarc_tags or {}
        warnings, suggestions = _lint_dmarc_tags(
            dmarc_tags,
            checked_domain=_normalize_dns_name(domain),
            policy_domain=dmarc_policy_domain,
            discovery_method=dmarc_discovery_method,
        )
        warnings.extend(
            await _lint_external_reporting_destinations(
                self,
                dmarc_tags,
                policy_domain=dmarc_policy_domain,
            )
        )
        dmarc_policy = effective_dmarc_policy(dmarc_tags)
        if dmarc_policy:
            dmarc_tags = {**dmarc_tags, "p": dmarc_policy}

        return DomainDNSResult(
            dmarc=dmarc_ok,
            dmarc_record=dmarc_record,
            spf=spf_ok,
            spf_record=spf_record,
            dkim=dkim_ok,
            dkim_selectors=dkim_sels,
            dkim_record=dkim_record,
            selectors_checked=all_selectors,
            dmarc_policy_domain=dmarc_policy_domain,
            dmarc_discovery_method=dmarc_discovery_method,
            dmarc_tags=dmarc_tags,
            dmarc_warnings=warnings,
            dmarc_suggestions=suggestions,
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
                    result.append(
                        "".join(
                            string.decode("utf-8", errors="replace") for string in rdata.strings
                        )
                    )
            return result
        except dns.exception.DNSException as exc:
            raise LookupError(f"TXT lookup failed for {name}: {exc}") from exc

    async def lookup_ptr(self, ip: str) -> Optional[str]:
        """Resolve a PTR record for *ip* via the system resolver."""
        import dns.asyncresolver  # type: ignore[import]
        import dns.exception  # type: ignore[import]

        try:
            ptr_name = _ip_to_arpa_name(ip)
            answers = await dns.asyncresolver.resolve(
                ptr_name, "PTR", lifetime=DNS_TIMEOUT, raise_on_no_answer=False
            )
            if answers:
                for rdata in answers:
                    return str(rdata).rstrip(".")
        except (dns.exception.DNSException, ValueError):
            pass
        return None

    async def lookup_cname(self, name: str) -> Optional[str]:
        """Resolve a CNAME record for *name* via the system resolver."""
        import dns.asyncresolver  # type: ignore[import]
        import dns.exception  # type: ignore[import]

        try:
            answers = await dns.asyncresolver.resolve(
                name, "CNAME", lifetime=DNS_TIMEOUT, raise_on_no_answer=False
            )
            if answers:
                for rdata in answers:
                    return str(rdata.target).rstrip(".")
        except dns.exception.DNSException as exc:
            logger.debug("CNAME lookup failed for %s: %s", _sanitize_for_log(name), exc)
        return None


class CloudflareDNSProvider(BaseDNSProvider):
    """DNS provider using Cloudflare DoH and, when configured, the REST API.

    Public DNS lookups continue to use Cloudflare's DNS-over-HTTPS endpoint.
    If an API token is supplied, the provider can also discover account zones
    and read managed DNS records directly from the Cloudflare REST API.
    """

    #: Cloudflare DNS-over-HTTPS endpoint (JSON wire format)
    CLOUDFLARE_DOH_URL: str = "https://cloudflare-dns.com/dns-query"
    #: Cloudflare REST API base URL
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
            Cloudflare API token. Required for zone discovery and managed
            DNS record reads; not needed for read-only DoH lookups.
        zone_id:
            Optional Cloudflare zone identifier used as a preferred zone.
        """
        self.api_token = api_token
        self.zone_id = zone_id

    def _auth_headers(self) -> Dict[str, str]:
        if not self.api_token:
            raise LookupError("Cloudflare API token is not configured")
        return {
            "Authorization": f"Bearer {self.api_token}",
            "Accept": "application/json",
        }

    async def _api_get(
        self,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Call Cloudflare's REST API and return the decoded response."""
        import httpx  # type: ignore[import]

        url = f"{self.CLOUDFLARE_API_BASE}{path}"
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    url,
                    params=params,
                    headers=self._auth_headers(),
                    timeout=DNS_TIMEOUT,
                )
                response.raise_for_status()
                data = response.json()
        except (httpx.RequestError, httpx.HTTPStatusError, httpx.TimeoutException) as exc:
            raise LookupError(f"Cloudflare API request failed for {path}: {exc}") from exc

        if not data.get("success", False):
            errors = data.get("errors") or []
            message = "; ".join(str(error.get("message", error)) for error in errors[:3])
            raise LookupError(message or f"Cloudflare API request failed for {path}")
        return data

    async def list_zones(self) -> List[Dict[str, Any]]:
        """Return all zones visible to the configured Cloudflare API token."""
        zones: List[Dict[str, Any]] = []
        page = 1
        while True:
            data = await self._api_get(
                "/zones",
                params={"page": page, "per_page": 50, "status": "active"},
            )
            result = data.get("result") or []
            if not isinstance(result, list):
                return zones
            zones.extend(result)
            info = data.get("result_info") or {}
            total_pages = int(info.get("total_pages") or 1)
            if page >= total_pages:
                return zones
            page += 1

    async def find_zone_for_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Return the best matching Cloudflare zone for *domain*."""
        zones = await self.list_zones()
        domain_lc = domain.rstrip(".").lower()
        matches = [
            zone
            for zone in zones
            if isinstance(zone.get("name"), str)
            and (
                domain_lc == zone["name"].lower() or domain_lc.endswith(f".{zone['name'].lower()}")
            )
        ]
        if not matches:
            return None
        return sorted(matches, key=lambda zone: len(zone.get("name", "")), reverse=True)[0]

    async def list_dns_records(
        self,
        *,
        zone_id: Optional[str] = None,
        name: Optional[str] = None,
        record_type: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """Return DNS records for a Cloudflare zone."""
        resolved_zone_id = zone_id or self.zone_id
        if not resolved_zone_id:
            raise LookupError("Cloudflare zone ID is not configured")

        records: List[Dict[str, Any]] = []
        page = 1
        while True:
            params: Dict[str, Any] = {"page": page, "per_page": 100}
            if name:
                params["name"] = name
            if record_type:
                params["type"] = record_type

            data = await self._api_get(
                f"/zones/{resolved_zone_id}/dns_records",
                params=params,
            )
            result = data.get("result") or []
            if not isinstance(result, list):
                return records
            records.extend(result)
            info = data.get("result_info") or {}
            total_pages = int(info.get("total_pages") or 1)
            if page >= total_pages:
                return records
            page += 1

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
        except (httpx.RequestError, httpx.HTTPStatusError, httpx.TimeoutException) as exc:
            raise LookupError(f"Cloudflare DoH lookup failed for {name}: {exc}") from exc

    async def lookup_ptr(self, ip: str) -> Optional[str]:
        """Resolve a PTR record for *ip* via Cloudflare's DoH endpoint."""
        import httpx  # type: ignore[import]

        try:
            ptr_name = _ip_to_arpa_name(ip)
        except ValueError:
            return None

        params = {"name": ptr_name, "type": "PTR"}
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
                for answer in data.get("Answer", []):
                    if answer.get("type") == 12:  # PTR record type
                        return answer.get("data", "").rstrip(".")
        except (httpx.RequestError, httpx.HTTPStatusError, httpx.TimeoutException):
            pass
        return None

    async def lookup_cname(self, name: str) -> Optional[str]:
        """Resolve a CNAME record for *name* via Cloudflare's DoH endpoint."""
        import httpx  # type: ignore[import]

        params = {"name": name, "type": "CNAME"}
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
                for answer in data.get("Answer", []):
                    if answer.get("type") == 5:  # CNAME record type
                        return answer.get("data", "").rstrip(".")
        except (httpx.RequestError, httpx.HTTPStatusError, httpx.TimeoutException):
            pass
        return None


class DemoDNSProvider(BaseDNSProvider):
    """Deterministic DNS provider for the opt-in public demo mode."""

    def __init__(self) -> None:
        self._records = {
            "dmarq.org": ["v=spf1 include:_spf.mail.example -all"],
            "_dmarc.dmarq.org": [
                (
                    "v=DMARC1; p=quarantine; sp=reject; adkim=s; aspf=r; "
                    "rua=mailto:dmarc@dmarq.org,mailto:dmarc@reports.dmarq.net"
                )
            ],
            "dmarq.org._report._dmarc.reports.dmarq.net": ["v=DMARC1"],
            "selector1._domainkey.dmarq.org": [
                "v=DKIM1; k=rsa; p="
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtestselector1demo"
                "keymaterialforshowcasingahealthyselectornotforproductionuseonly"
                "andlongenoughtoavoidweakkeywarnings1234567890abcdef"
            ],
            "news._domainkey.dmarq.org": ["v=DKIM1; k=rsa; p=DEMONEWS"],
            "zendesk._domainkey.dmarq.org": [
                "v=DKIM1; k=rsa; p="
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzendesksupportdemo"
                "keymaterialforshowcasingahealthyselectornotforproductionuseonly"
                "andlongenoughtoavoidweakkeywarningsabcdef1234567890"
            ],
            "_mta-sts.dmarq.org": ["v=STSv1; id=20260625"],
            "_smtp._tls.dmarq.org": ["v=TLSRPTv1; rua=mailto:tlsrpt@dmarq.org"],
            "default._bimi.dmarq.org": [
                "v=BIMI1; l=https://demo.dmarq.org/static/demo-bimi.svg; a="
            ],
            "dmarq.com": ["v=spf1 include:_spf.mail.example +all"],
            "_dmarc.dmarq.com": [
                "v=DMARC1; p=none; rua=mailto:dmarc@reports.dmarq.org!50m; adkim=r; aspf=r"
            ],
            "google._domainkey.dmarq.com": [
                "v=DKIM1; k=rsa; p="
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgoggledemo"
                "keymaterialforshowcasingahealthyselectornotforproductionuseonly"
                "andlongenoughtoavoidweakkeywarnings0987654321fedcba"
            ],
            "stripe._domainkey.dmarq.com": [
                "v=DKIM1; k=rsa; p="
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAstripedemo"
                "keymaterialforshowcasingahealthyselectornotforproductionuseonly"
                "andlongenoughtoavoidweakkeywarningsfedcba0987654321"
            ],
            "_smtp._tls.dmarq.com": ["v=TLSRPTv1"],
        }
        self._cname_records = {
            "mailchimp._domainkey.dmarq.com": "missing-mcsv._domainkey.mcsv.net",
        }

    async def lookup_txt(self, name: str) -> List[str]:
        normalized = _normalize_dns_name(name)
        if normalized in self._records:
            return list(self._records[normalized])
        raise LookupError(f"Demo DNS record not found for {name}")

    async def lookup_ptr(self, ip: str) -> Optional[str]:
        ptr_records = {
            "203.0.113.10": "primary-saas.mail.dmarq.org",
            "203.0.113.44": "mail123.mcsv.net",
            "198.51.100.23": "support-mail.zendesk.com",
            "192.0.2.66": "legacy-crm.demo.dmarq.org",
            "203.0.113.75": "mail-qv1-f75.google.com",
            "198.51.100.88": "campaign.mcsv.net",
            "192.0.2.114": "smtp.stripe.com",
            "198.51.100.199": "unknown-forwarder.demo.dmarq.com",
        }
        return ptr_records.get(ip)

    async def lookup_cname(self, name: str) -> Optional[str]:
        normalized = _normalize_dns_name(name)
        return self._cname_records.get(normalized)


def _decrypt_setting_value(value: Optional[str]) -> Optional[str]:
    if not value:
        return value
    try:
        from app.core.credential_encryption import decrypt_secret

        return decrypt_secret(value)
    except Exception:
        return value


def _setting_value(db: Any, key: str) -> Optional[str]:
    if db is None:
        return None
    try:
        from app.models.setting import Setting

        row = db.query(Setting).filter(Setting.key == key).first()
        return row.value if row is not None else None
    except Exception:
        return None


def get_default_provider(db: Any = None) -> BaseDNSProvider:
    """Return the configured default DNS provider."""
    from app.core.config import get_settings

    settings = get_settings()
    if settings.DEMO_MODE:
        return DemoDNSProvider()

    resolver = (_setting_value(db, "dns.resolver") or "").strip().lower()
    if resolver == "cloudflare":
        api_token = _decrypt_setting_value(_setting_value(db, "cloudflare.api_token"))
        zone_id = _setting_value(db, "cloudflare.zone_id")
        return CloudflareDNSProvider(
            api_token=api_token or settings.CLOUDFLARE_API_TOKEN,
            zone_id=zone_id or settings.CLOUDFLARE_ZONE_ID,
        )
    return SystemDNSProvider()


def extract_dmarc_policy(dmarc_record: Optional[str]) -> Optional[str]:
    """Parse the effective RFC 9989 base policy from a DMARC TXT record string.

    Returns the policy value (e.g. ``"none"``, ``"quarantine"``,
    ``"reject"``) or ``None`` if the record is absent or unparsable.
    """
    return effective_dmarc_policy(parse_dmarc_record_tags(dmarc_record))
