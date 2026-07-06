"""Read-only DANE/TLSA posture checks for monitored mail domains."""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import json
import re
import smtplib
import socket
import ssl
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import List, Optional, Tuple

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.dns_cache import DNSCache
from app.services.dns_cache import DEFAULT_DNS_CACHE_TTL_SECONDS
from app.services.dns_resolver import BaseDNSProvider

_CACHE_KEY = "dane-v1"
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")
_VALID_CERTIFICATE_USAGES = {0, 1, 2, 3}
_VALID_SELECTORS = {0, 1}
_VALID_MATCHING_TYPES = {0, 1, 2}
_LIVE_TLSA_CACHE_SUFFIX = "live-tlsa-v1"
_MAX_LIVE_TLSA_HOSTS = 3
_SMTP_TIMEOUT_SECONDS = 5.0


@dataclass
class TLSARecord:
    """One TLSA record observed for an MX host."""

    query_name: str
    mx_host: str
    record: str
    certificate_usage: Optional[int] = None
    selector: Optional[int] = None
    matching_type: Optional[int] = None
    association_data: Optional[str] = None
    valid: bool = False
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


@dataclass
class TLSASuggestion:
    """TLSA value derived from a live SMTP STARTTLS certificate."""

    query_name: str
    mx_host: str
    record: str = ""
    certificate_usage: int = 3
    selector: int = 1
    matching_type: int = 1
    association_data: str = ""
    status: str = "unavailable"
    source: str = "smtp-starttls-live-certificate"
    error: Optional[str] = None


@dataclass
class DANEResult:
    """Operator-facing DANE/TLSA posture evidence."""

    status: str = "fail"
    port: int = 25
    mx_hosts: List[str] = field(default_factory=list)
    records: List[TLSARecord] = field(default_factory=list)
    suggested_records: List[TLSASuggestion] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _is_fresh(row: DNSCache, ttl_seconds: int, now: datetime) -> bool:
    return row.checked_at >= now - timedelta(seconds=ttl_seconds)


def _record_from_json(value: dict) -> TLSARecord:
    return TLSARecord(
        query_name=str(value.get("query_name") or ""),
        mx_host=str(value.get("mx_host") or ""),
        record=str(value.get("record") or ""),
        certificate_usage=value.get("certificate_usage"),
        selector=value.get("selector"),
        matching_type=value.get("matching_type"),
        association_data=value.get("association_data"),
        valid=bool(value.get("valid")),
        errors=list(value.get("errors") or []),
        warnings=list(value.get("warnings") or []),
    )


def _suggestion_from_json(value: dict) -> TLSASuggestion:
    return TLSASuggestion(
        query_name=str(value.get("query_name") or ""),
        mx_host=str(value.get("mx_host") or ""),
        record=str(value.get("record") or ""),
        certificate_usage=int(value.get("certificate_usage") or 3),
        selector=int(value.get("selector") or 1),
        matching_type=int(value.get("matching_type") or 1),
        association_data=str(value.get("association_data") or ""),
        status=str(value.get("status") or "unavailable"),
        source=str(value.get("source") or "smtp-starttls-live-certificate"),
        error=value.get("error"),
    )


def _result_from_json(value: str) -> DANEResult:
    data = json.loads(value)
    return DANEResult(
        status=str(data.get("status") or "fail"),
        port=int(data.get("port") or 25),
        mx_hosts=list(data.get("mx_hosts") or []),
        records=[_record_from_json(row) for row in data.get("records") or []],
        suggested_records=[
            _suggestion_from_json(row) for row in data.get("suggested_records") or []
        ],
        errors=list(data.get("errors") or []),
        warnings=list(data.get("warnings") or []),
    )


def _safe_int(value: str) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def parse_tlsa_record(record: str, *, query_name: str, mx_host: str) -> TLSARecord:
    """Parse a TLSA record and return normalized lint evidence."""
    result = TLSARecord(query_name=query_name, mx_host=mx_host, record=record)
    parts = record.split(maxsplit=3)
    if len(parts) < 4:
        result.errors.append(
            "TLSA records must contain certificate usage, selector, matching type, and data."
        )
        return result

    usage = _safe_int(parts[0])
    selector = _safe_int(parts[1])
    matching_type = _safe_int(parts[2])
    association_data = re.sub(r"\s+", "", parts[3])
    result.certificate_usage = usage
    result.selector = selector
    result.matching_type = matching_type
    result.association_data = association_data

    if usage not in _VALID_CERTIFICATE_USAGES:
        result.errors.append("TLSA certificate usage must be 0, 1, 2, or 3.")
    if selector not in _VALID_SELECTORS:
        result.errors.append("TLSA selector must be 0 for full certificate or 1 for SPKI.")
    if matching_type not in _VALID_MATCHING_TYPES:
        result.errors.append("TLSA matching type must be 0, 1, or 2.")
    if not association_data:
        result.errors.append("TLSA association data is empty.")
    elif not _HEX_RE.match(association_data):
        result.errors.append("TLSA association data must be hexadecimal.")
    elif len(association_data) % 2:
        result.errors.append("TLSA association data must contain complete bytes.")

    if usage in {0, 1}:
        result.warnings.append(
            "PKIX TLSA usages still depend on public CA validation; usage 3 is common for DANE-EE."
        )
    if matching_type == 0:
        result.warnings.append(
            "Full-certificate TLSA values are bulky and rotate whenever the certificate changes."
        )

    result.valid = not result.errors
    return result


def _is_public_smtp_address(address: str) -> bool:
    try:
        return ipaddress.ip_address(address).is_global
    except ValueError:
        return False


def _resolve_public_smtp_address(mx_host: str, port: int) -> str:
    candidates = socket.getaddrinfo(mx_host, port, type=socket.SOCK_STREAM)
    for candidate in candidates:
        sockaddr = candidate[4]
        if sockaddr and _is_public_smtp_address(str(sockaddr[0])):
            return str(sockaddr[0])
    raise OSError("MX host did not resolve to a public SMTP address.")


def _derive_tlsa_suggestion_sync(mx_host: str, port: int, timeout: float) -> TLSASuggestion:
    query_name = f"_{port}._tcp.{mx_host}"
    try:
        from cryptography import x509
        from cryptography.exceptions import UnsupportedAlgorithm
        from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    except ImportError as exc:  # pragma: no cover - dependency is present in packaged builds
        return TLSASuggestion(
            query_name=query_name,
            mx_host=mx_host,
            error=f"cryptography dependency is unavailable: {exc}",
        )

    try:
        smtp_address = _resolve_public_smtp_address(mx_host, port)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with smtplib.SMTP(smtp_address, port, timeout=timeout) as smtp:
            smtp.ehlo_or_helo_if_needed()
            if not smtp.has_extn("starttls"):
                return TLSASuggestion(
                    query_name=query_name,
                    mx_host=mx_host,
                    error="SMTP server did not advertise STARTTLS.",
                )
            smtp.starttls(context=context)
            if smtp.sock is None:
                return TLSASuggestion(
                    query_name=query_name,
                    mx_host=mx_host,
                    error="STARTTLS completed without an accessible socket.",
                )
            certificate_der = smtp.sock.getpeercert(binary_form=True)
    except (OSError, smtplib.SMTPException, ssl.SSLError, TimeoutError) as exc:
        return TLSASuggestion(query_name=query_name, mx_host=mx_host, error=str(exc))

    if not certificate_der:
        return TLSASuggestion(
            query_name=query_name,
            mx_host=mx_host,
            error="SMTP server did not return a certificate.",
        )

    try:
        certificate = x509.load_der_x509_certificate(certificate_der)
        spki_der = certificate.public_key().public_bytes(
            Encoding.DER,
            PublicFormat.SubjectPublicKeyInfo,
        )
    except (UnsupportedAlgorithm, ValueError) as exc:
        return TLSASuggestion(
            query_name=query_name,
            mx_host=mx_host,
            error=f"SMTP certificate could not be parsed: {exc}",
        )

    digest = hashlib.sha256(spki_der).hexdigest()
    return TLSASuggestion(
        query_name=query_name,
        mx_host=mx_host,
        record=f"3 1 1 {digest}",
        association_data=digest,
        status="ready",
    )


async def _derive_tlsa_suggestions(
    mx_hosts: List[str],
    *,
    port: int,
    timeout: float = _SMTP_TIMEOUT_SECONDS,
) -> List[TLSASuggestion]:
    limited_hosts = mx_hosts[:_MAX_LIVE_TLSA_HOSTS]
    if not limited_hosts:
        return []
    results = await asyncio.gather(
        *(
            asyncio.to_thread(_derive_tlsa_suggestion_sync, mx_host, port, timeout)
            for mx_host in limited_hosts
        ),
        return_exceptions=True,
    )
    suggestions: List[TLSASuggestion] = []
    for mx_host, result in zip(limited_hosts, results):
        if isinstance(result, TLSASuggestion):
            suggestions.append(result)
            continue
        suggestions.append(
            TLSASuggestion(
                query_name=f"_{port}._tcp.{mx_host}",
                mx_host=mx_host,
                error=f"Live TLSA suggestion failed: {result}",
            )
        )
    return suggestions


def _compare_live_tlsa_suggestions(result: DANEResult) -> None:
    ready_by_host = {
        suggestion.mx_host: suggestion
        for suggestion in result.suggested_records
        if suggestion.status == "ready" and suggestion.association_data
    }
    if not ready_by_host:
        return

    mismatched_hosts: List[str] = []
    for record in result.records:
        if not (
            record.valid
            and record.certificate_usage == 3
            and record.selector == 1
            and record.matching_type == 1
            and record.association_data
        ):
            continue
        suggestion = ready_by_host.get(record.mx_host)
        if suggestion and record.association_data.lower() != suggestion.association_data.lower():
            record.warnings.append(
                "TLSA 3 1 1 value does not match the live SMTP STARTTLS certificate SPKI hash."
            )
            mismatched_hosts.append(record.mx_host)

    if mismatched_hosts:
        result.errors.append(
            "TLSA records do not match the live SMTP STARTTLS certificate for MX host(s): "
            + ", ".join(sorted(set(mismatched_hosts)))
        )


def _normalize_mx_hosts(raw_mx_hosts: object) -> List[str]:
    mx_hosts = raw_mx_hosts if isinstance(raw_mx_hosts, (list, tuple)) else []
    normalized_hosts = (str(host).strip(".").lower() for host in mx_hosts)
    return list(dict.fromkeys(host for host in normalized_hosts if host))


async def _apply_live_tlsa_suggestions(result: DANEResult) -> None:
    result.suggested_records = await _derive_tlsa_suggestions(result.mx_hosts, port=result.port)
    unavailable = [
        f"{suggestion.mx_host}: {suggestion.error}"
        for suggestion in result.suggested_records
        if suggestion.status != "ready" and suggestion.error
    ]
    if unavailable:
        result.warnings.append(
            "Live TLSA suggestion could not be derived for "
            + "; ".join(unavailable[:_MAX_LIVE_TLSA_HOSTS])
        )


async def _collect_tlsa_records(
    result: DANEResult,
    provider: BaseDNSProvider,
) -> Tuple[List[str], List[str]]:
    missing_hosts: List[str] = []
    invalid_hosts: List[str] = []
    for mx_host in result.mx_hosts:
        query_name = f"_{result.port}._tcp.{mx_host}"
        raw_records = await provider.lookup_tlsa(query_name)
        records = raw_records if isinstance(raw_records, (list, tuple)) else []
        if not records:
            missing_hosts.append(mx_host)
            continue
        parsed_records = [
            parse_tlsa_record(record, query_name=query_name, mx_host=mx_host) for record in records
        ]
        result.records.extend(parsed_records)
        if not any(record.valid for record in parsed_records):
            invalid_hosts.append(mx_host)
    return missing_hosts, invalid_hosts


def _append_tlsa_coverage_errors(
    result: DANEResult,
    *,
    missing_hosts: List[str],
    invalid_hosts: List[str],
) -> None:
    if missing_hosts:
        result.errors.append(
            "No TLSA records were found for MX host(s): " + ", ".join(missing_hosts)
        )
    if invalid_hosts:
        result.errors.append(
            "TLSA records need syntax review for MX host(s): " + ", ".join(invalid_hosts)
        )


def _finalize_dane_status(result: DANEResult) -> None:
    valid_hosts = {record.mx_host for record in result.records if record.valid}
    if not result.errors:
        result.status = "pass"
    elif any(error.startswith("TLSA records do not match") for error in result.errors):
        result.status = "fail"
    elif valid_hosts:
        result.status = "partial"


async def check_dane(
    domain: str,
    provider: BaseDNSProvider,
    *,
    port: int = 25,
    derive_suggestions: bool = False,
) -> DANEResult:
    """Resolve MX hosts and lint their SMTP DANE TLSA records."""
    normalized_domain = domain.strip().strip(".").lower()
    result = DANEResult(port=port)
    result.mx_hosts = _normalize_mx_hosts(await provider.lookup_mx(normalized_domain))
    if not result.mx_hosts:
        result.errors.append("No MX hosts were found for DANE/TLSA evaluation.")
        return result

    if derive_suggestions:
        await _apply_live_tlsa_suggestions(result)

    missing_hosts, invalid_hosts = await _collect_tlsa_records(result, provider)
    _append_tlsa_coverage_errors(
        result,
        missing_hosts=missing_hosts,
        invalid_hosts=invalid_hosts,
    )
    if result.records:
        result.warnings.append(
            "DMARQ validates TLSA syntax and MX coverage. When live SMTP access succeeds, "
            "DMARQ compares DANE-EE SPKI hashes with the STARTTLS certificate; DNSSEC chain "
            "validation is still operator-confirmed."
        )
    _compare_live_tlsa_suggestions(result)
    _finalize_dane_status(result)
    return result


async def check_dane_cached(
    db: Session,
    provider: BaseDNSProvider,
    domain: str,
    *,
    port: int = 25,
    derive_suggestions: bool = False,
    ttl_seconds: int = DEFAULT_DNS_CACHE_TTL_SECONDS,
    refresh: bool = False,
) -> Tuple[DANEResult, bool, datetime]:
    """Resolve DANE posture, reusing the shared DNS cache semantics."""
    now = _utcnow_naive()
    normalized_domain = domain.strip().strip(".").lower()
    provider_name = f"{provider.__class__.__name__}:dane"
    cache_key = f"{_CACHE_KEY}:{port}"
    if derive_suggestions:
        cache_key = f"{cache_key}:{_LIVE_TLSA_CACHE_SUFFIX}"
    row = (
        db.query(DNSCache)
        .filter(
            DNSCache.domain == normalized_domain,
            DNSCache.provider == provider_name,
            DNSCache.selectors_key == cache_key,
        )
        .first()
    )
    if row and not refresh and _is_fresh(row, ttl_seconds, now):
        return _result_from_json(row.result_json), True, row.checked_at

    result = await check_dane(
        normalized_domain,
        provider,
        port=port,
        derive_suggestions=derive_suggestions,
    )
    payload = json.dumps(asdict(result), sort_keys=True, separators=(",", ":"))
    if row is None:
        row = DNSCache(
            domain=normalized_domain,
            provider=provider_name,
            selectors_key=cache_key,
            result_json=payload,
            checked_at=now,
        )
        db.add(row)
    else:
        row.result_json = payload
        row.checked_at = now

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        row = (
            db.query(DNSCache)
            .filter(
                DNSCache.domain == normalized_domain,
                DNSCache.provider == provider_name,
                DNSCache.selectors_key == cache_key,
            )
            .first()
        )
        if row is None:
            raise
        row.result_json = payload
        row.checked_at = now
        db.commit()

    db.refresh(row)
    return result, False, row.checked_at
