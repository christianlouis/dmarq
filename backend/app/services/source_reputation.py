"""Passive sender IP reputation scoring from existing DMARC evidence."""

from __future__ import annotations

import hashlib
import ipaddress
import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional, Tuple

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.models.dns_cache import DNSCache
from app.services.dns_cache import DEFAULT_DNS_CACHE_TTL_SECONDS
from app.services.source_reputation_feeds import (
    IPFeedReputation,
    ReputationFeedProvider,
    lookup_sources_reputation_cached,
    providers_from_settings,
)

_CACHE_PROVIDER = "source-reputation-v1"


@dataclass
class ReputationEvidence:
    """One explainable input used for source reputation scoring."""

    label: str
    value: str
    source: str = "local"


@dataclass
class SourceReputation:
    """Reputation posture for one observed sending IP."""

    ip: str
    status: str
    risk_score: int
    summary: str
    listings: List[str] = field(default_factory=list)
    evidence: List[ReputationEvidence] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    first_seen: Optional[int] = None
    last_seen: Optional[int] = None
    checked_at: str = ""


@dataclass
class ReputationPresentation:
    """Frontend-friendly reputation labels and evidence context."""

    status_label: str
    status_detail: str
    feed_status: str
    feed_summary: str
    evidence_summary: str


@dataclass
class DomainReputation:
    """Domain-level reputation summary for observed sending infrastructure."""

    domain: str
    status: str
    checked_at: str
    sources: List[SourceReputation] = field(default_factory=list)
    summary: Dict[str, int] = field(default_factory=dict)


def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _is_fresh(row: DNSCache, ttl_seconds: int, now: datetime) -> bool:
    return row.checked_at >= now - timedelta(seconds=ttl_seconds)


def _evidence_from_json(value: Dict[str, Any]) -> ReputationEvidence:
    return ReputationEvidence(
        label=str(value.get("label") or ""),
        value=str(value.get("value") or ""),
        source=str(value.get("source") or "local"),
    )


def _source_from_json(value: Dict[str, Any]) -> SourceReputation:
    return SourceReputation(
        ip=str(value.get("ip") or "unknown"),
        status=str(value.get("status") or "unknown"),
        risk_score=int(value.get("risk_score") or 0),
        summary=str(value.get("summary") or ""),
        listings=list(value.get("listings") or []),
        evidence=[_evidence_from_json(item) for item in value.get("evidence") or []],
        recommendations=list(value.get("recommendations") or []),
        first_seen=value.get("first_seen"),
        last_seen=value.get("last_seen"),
        checked_at=str(value.get("checked_at") or ""),
    )


def _result_from_json(value: str) -> DomainReputation:
    data = json.loads(value)
    return DomainReputation(
        domain=str(data.get("domain") or ""),
        status=str(data.get("status") or "unknown"),
        checked_at=str(data.get("checked_at") or ""),
        sources=[_source_from_json(item) for item in data.get("sources") or []],
        summary=dict(data.get("summary") or {}),
    )


def _metadata_value(source: Dict[str, Any], *keys: str) -> Optional[str]:
    extensions = source.get("extensions") or {}
    for key in keys:
        value = source.get(key) if key in source else extensions.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def _metadata_listings(source: Dict[str, Any]) -> List[str]:
    value = _metadata_value(source, "reputation:listings", "demo:blacklists", "blacklists")
    if not value:
        return []
    return [item.strip() for item in value.replace(";", ",").split(",") if item.strip()]


def _reported_reputation(source: Dict[str, Any]) -> Optional[str]:
    value = _metadata_value(source, "reputation:status", "demo:reputation", "reputation")
    return value.lower() if value else None


def _source_fingerprint(sources: Iterable[Dict[str, Any]]) -> str:
    rows = []
    for source in sources:
        rows.append(
            {
                "ip": source.get("source_ip") or source.get("ip"),
                "count": source.get("count"),
                "dmarc_fail_count": source.get("dmarc_fail_count"),
                "dmarc_pass_count": source.get("dmarc_pass_count"),
                "spf_result": source.get("spf_result"),
                "dkim_result": source.get("dkim_result"),
                "extensions": source.get("extensions") or {},
            }
        )
    payload = json.dumps(sorted(rows, key=lambda row: str(row.get("ip"))), sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


def _report_fingerprint(reports: Iterable[Dict[str, Any]]) -> str:
    rows = []
    for report in reports:
        rows.append(
            {
                "begin": report.get("begin_date") or report.get("begin_timestamp"),
                "end": report.get("end_date") or report.get("end_timestamp"),
                "records": [
                    {
                        "source_ip": record.get("source_ip"),
                        "count": record.get("count"),
                        "disposition": record.get("disposition"),
                    }
                    for record in report.get("records") or []
                ],
            }
        )
    payload = json.dumps(rows, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


def _context_fingerprint(
    senders_by_ip: Optional[Dict[str, Dict[str, Any]]],
    anomalies_by_ip: Optional[Dict[str, List[Dict[str, Any]]]],
) -> str:
    payload = json.dumps(
        {
            "senders": senders_by_ip or {},
            "anomalies": anomalies_by_ip or {},
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


def _source_seen_windows(reports: Iterable[Dict[str, Any]]) -> Dict[str, Dict[str, Optional[int]]]:
    windows: Dict[str, Dict[str, Optional[int]]] = {}
    for report in reports:
        begin = _timestamp(report.get("begin_date") or report.get("begin_timestamp"))
        end = _timestamp(report.get("end_date") or report.get("end_timestamp")) or begin
        for record in report.get("records") or []:
            ip = str(record.get("source_ip") or "unknown")
            item = windows.setdefault(ip, {"first_seen": None, "last_seen": None})
            if begin is not None:
                item["first_seen"] = (
                    begin if item["first_seen"] is None else min(item["first_seen"], begin)
                )
            if end is not None:
                item["last_seen"] = (
                    end if item["last_seen"] is None else max(item["last_seen"], end)
                )
    return windows


def _timestamp(value: Any) -> Optional[int]:
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str) and value.strip():
        try:
            return int(value)
        except ValueError:
            try:
                parsed = datetime.fromisoformat(value)
            except ValueError:
                return None
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return int(parsed.astimezone(timezone.utc).timestamp())
    return None


def _network_evidence(ip: str, source: Dict[str, Any]) -> Tuple[int, List[ReputationEvidence]]:
    evidence: List[ReputationEvidence] = []
    risk = 0
    has_demo_metadata = bool(_metadata_value(source, "demo:source", "demo:network"))
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return 20, [ReputationEvidence("IP format", "Invalid source IP", "local")]
    if not address.is_global and not has_demo_metadata:
        risk += 18
        evidence.append(
            ReputationEvidence(
                "Network scope",
                "Private, reserved, loopback, or otherwise non-global source address",
                "local",
            )
        )
    return risk, evidence


def _status_from_risk(risk_score: int, listings: List[str], reported: Optional[str]) -> str:
    if listings or reported == "listed":
        return "listed"
    if risk_score >= 70:
        return "critical"
    if risk_score >= 40:
        return "suspicious"
    if reported == "clean" or risk_score <= 10:
        return "clean"
    return "unknown"


def _external_reputation_evidence(
    feed_result: Optional[IPFeedReputation],
) -> Tuple[int, List[str], List[ReputationEvidence]]:
    risk_score = 0
    evidence: List[ReputationEvidence] = []
    listings = _external_listings(feed_result)
    if listings:
        risk_score += 45
        evidence.append(
            ReputationEvidence(
                "External reputation feeds",
                ", ".join(listings),
                "external",
            )
        )
    suspicious_notes = _external_suspicious_notes(feed_result)
    if suspicious_notes:
        risk_score += 20
        evidence.extend(suspicious_notes)
    evidence.extend(_external_feed_notes(feed_result))
    return risk_score, listings, evidence


def _source_reputation(
    source: Dict[str, Any],
    sender: Optional[Dict[str, Any]],
    anomalies: List[Dict[str, Any]],
    seen: Dict[str, Optional[int]],
    feed_result: Optional[IPFeedReputation],
    *,
    checked_at: str,
) -> SourceReputation:
    ip = str(source.get("source_ip") or source.get("ip") or "unknown")
    count = int(source.get("count") or 0)
    failed = int(source.get("dmarc_fail_count") or 0)
    failure_rate = (failed / count) * 100 if count else 0.0
    listings = _metadata_listings(source)
    reported = _reported_reputation(source)

    evidence: List[ReputationEvidence] = [
        ReputationEvidence("Observed messages", str(count), "dmarc"),
        ReputationEvidence("DMARC failure rate", f"{failure_rate:.1f}%", "dmarc"),
    ]
    risk_score = min(35, round(failure_rate * 0.35))
    network_risk, network_evidence = _network_evidence(ip, source)
    risk_score += network_risk
    evidence.extend(network_evidence)

    if listings:
        risk_score += 45
        evidence.append(ReputationEvidence("Blacklist listings", ", ".join(listings), "metadata"))
    elif reported == "listed":
        risk_score += 45
        evidence.append(ReputationEvidence("Reputation status", "listed", "metadata"))
    if reported in {"suspicious", "watch"}:
        risk_score += 20
        evidence.append(ReputationEvidence("Reputation status", reported, "metadata"))
    elif reported == "clean":
        evidence.append(ReputationEvidence("Reputation status", "clean", "metadata"))

    external_risk, external_listings, external_evidence = _external_reputation_evidence(feed_result)
    if external_listings:
        listings.extend(item for item in external_listings if item not in listings)
    risk_score += external_risk
    evidence.extend(external_evidence)

    if sender and sender.get("status") in {"unknown", "suspicious"}:
        risk_score += 18 if sender.get("status") == "unknown" else 25
        evidence.append(ReputationEvidence("Sender identity", sender.get("reason", ""), "local"))

    error_anomalies = [item for item in anomalies if item.get("severity") == "error"]
    warning_anomalies = [item for item in anomalies if item.get("severity") == "warning"]
    if error_anomalies:
        risk_score += 25
        evidence.append(ReputationEvidence("Source anomalies", str(len(error_anomalies)), "local"))
    elif warning_anomalies:
        risk_score += 10
        evidence.append(
            ReputationEvidence("Source anomalies", str(len(warning_anomalies)), "local")
        )

    risk_score = max(0, min(100, risk_score))
    status = _status_from_risk(risk_score, listings, reported)
    recommendations = _recommendations(status, listings, sender, failed)
    return SourceReputation(
        ip=ip,
        status=status,
        risk_score=risk_score,
        summary=_summary_for(status, risk_score, failed),
        listings=listings,
        evidence=evidence,
        recommendations=recommendations,
        first_seen=seen.get("first_seen"),
        last_seen=seen.get("last_seen"),
        checked_at=checked_at,
    )


def _summary_for(status: str, risk_score: int, failed: int) -> str:
    if status == "listed":
        return "Observed source has blacklist or reputation-list evidence."
    if status in {"critical", "suspicious"}:
        return f"Observed source needs review; reputation risk is {risk_score}/100."
    if failed:
        return "Observed source has authentication failures but no listing evidence."
    if status == "clean":
        return "Observed source has no local reputation findings."
    return "No reputation listing evidence is available for this source."


def _external_listings(feed_result: Optional[IPFeedReputation]) -> List[str]:
    if feed_result is None:
        return []
    listings: List[str] = []
    for item in feed_result.evidence:
        if item.status == "listed":
            listings.append(item.listing or item.provider_name or item.provider_id)
    return listings


def _external_feed_notes(feed_result: Optional[IPFeedReputation]) -> List[ReputationEvidence]:
    if feed_result is None:
        return []
    notes: List[ReputationEvidence] = []
    for item in feed_result.evidence:
        if item.status == "clean":
            notes.append(
                ReputationEvidence(
                    f"{item.provider_name} lookup",
                    item.detail or "clean",
                    "external",
                )
            )
        elif item.status in {"error", "not_configured", "skipped"}:
            notes.append(
                ReputationEvidence(
                    f"{item.provider_name} lookup",
                    item.detail or item.status,
                    "external",
                )
            )
    return notes


def _external_suspicious_notes(feed_result: Optional[IPFeedReputation]) -> List[ReputationEvidence]:
    if feed_result is None:
        return []
    notes: List[ReputationEvidence] = []
    for item in feed_result.evidence:
        if item.status == "suspicious":
            notes.append(
                ReputationEvidence(
                    f"{item.provider_name} reputation",
                    item.detail or "Provider returned a non-clean reputation signal.",
                    "external",
                )
            )
    return notes


def _recommendations(
    status: str,
    listings: List[str],
    sender: Optional[Dict[str, Any]],
    failed: int,
) -> List[str]:
    if status == "listed":
        return [
            "Pause policy tightening until the sending owner confirms the listing.",
            "Check the listed IP with the named reputation provider and follow its delisting process.",
            "Confirm the source is still authorized before adding or keeping it in SPF.",
        ]
    if status in {"critical", "suspicious"}:
        return [
            "Confirm who owns this source and whether it should send for the domain.",
            "Review recent alignment failures and source anomalies before trusting the IP.",
        ]
    if failed and sender and sender.get("status") == "known":
        return [f"Fix sender authentication in {sender.get('name')} before enforcement."]
    if failed:
        return ["Fix SPF/DKIM alignment before treating this source as healthy."]
    if listings:
        return ["Review reputation-list evidence before changing DMARC policy."]
    return []


def reputation_presentation(item: SourceReputation) -> ReputationPresentation:
    """Return labels that make reputation evidence understandable in templates."""
    status_label = {
        "listed": "Listed",
        "critical": "Critical",
        "suspicious": "Needs review",
        "clean": "Clean",
        "unknown": "Not enough evidence",
    }.get(item.status, item.status.replace("_", " ").title())
    status_detail = {
        "listed": "External or metadata evidence says this IP is listed.",
        "critical": "High local or external risk signals were observed.",
        "suspicious": "Some evidence needs operator review before trusting this source.",
        "clean": "No local or configured external reputation findings were found.",
        "unknown": "DMARQ has local DMARC evidence, but no decisive reputation signal.",
    }.get(item.status, item.summary)

    external_evidence = [evidence for evidence in item.evidence if evidence.source == "external"]
    external_values = " ".join(evidence.value.lower() for evidence in external_evidence)
    if item.listings:
        feed_status = "listed"
        feed_summary = "Listed by " + ", ".join(item.listings[:3])
        if len(item.listings) > 3:
            feed_summary += f" +{len(item.listings) - 3}"
    elif any("not configured" in evidence.value.lower() for evidence in external_evidence):
        feed_status = "not_configured"
        feed_summary = "External reputation feeds are not configured."
    elif any(
        token in external_values
        for token in ("timed out", "unavailable", "unexpected", "error")
    ):
        feed_status = "error"
        feed_summary = "External reputation lookup returned errors."
    elif external_evidence:
        feed_status = "checked"
        feed_summary = "External reputation feeds checked without listings."
    else:
        feed_status = "local_only"
        feed_summary = "Using local DMARC evidence only; external feeds are not enabled."

    evidence_summary = item.summary
    if item.evidence:
        primary = item.evidence[0]
        evidence_summary = f"{item.summary} Evidence: {primary.label} {primary.value}."

    return ReputationPresentation(
        status_label=status_label,
        status_detail=status_detail,
        feed_status=feed_status,
        feed_summary=feed_summary,
        evidence_summary=evidence_summary,
    )


def build_source_reputation(
    domain: str,
    reports: Iterable[Dict[str, Any]],
    sources: Iterable[Dict[str, Any]],
    *,
    senders_by_ip: Optional[Dict[str, Dict[str, Any]]] = None,
    anomalies_by_ip: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    feed_results_by_ip: Optional[Dict[str, IPFeedReputation]] = None,
) -> DomainReputation:
    """Build passive reputation evidence for observed sources."""
    checked_at = _utcnow_iso()
    sender_map = senders_by_ip or {}
    anomaly_map = anomalies_by_ip or {}
    feed_map = feed_results_by_ip or {}
    seen_windows = _source_seen_windows(reports)
    source_rows = list(sources)
    reputations = [
        _source_reputation(
            source,
            sender_map.get(str(source.get("source_ip") or source.get("ip") or "unknown")),
            anomaly_map.get(str(source.get("source_ip") or source.get("ip") or "unknown"), []),
            seen_windows.get(str(source.get("source_ip") or source.get("ip") or "unknown"), {}),
            feed_map.get(str(source.get("source_ip") or source.get("ip") or "unknown")),
            checked_at=checked_at,
        )
        for source in source_rows
    ]
    reputations.sort(key=lambda item: (-item.risk_score, -len(item.listings), item.ip))
    summary = _domain_summary(reputations)
    return DomainReputation(
        domain=domain,
        status=_domain_status(summary),
        checked_at=checked_at,
        sources=reputations,
        summary=summary,
    )


def _domain_summary(sources: List[SourceReputation]) -> Dict[str, int]:
    return {
        "total_sources": len(sources),
        "listed": sum(1 for source in sources if source.status == "listed"),
        "suspicious": sum(1 for source in sources if source.status in {"critical", "suspicious"}),
        "clean": sum(1 for source in sources if source.status == "clean"),
        "unknown": sum(1 for source in sources if source.status == "unknown"),
        "highest_risk_score": max((source.risk_score for source in sources), default=0),
    }


def _domain_status(summary: Dict[str, int]) -> str:
    if summary.get("listed", 0) > 0:
        return "listed"
    if summary.get("suspicious", 0) > 0:
        return "attention"
    if summary.get("total_sources", 0) == 0:
        return "unknown"
    return "clean"


def source_reputation_by_ip(result: DomainReputation) -> Dict[str, SourceReputation]:
    """Return reputation rows keyed by source IP."""
    return {source.ip: source for source in result.sources}


def source_reputation_cache_key(
    sources: Iterable[Dict[str, Any]],
    reports: Iterable[Dict[str, Any]] = (),
    *,
    senders_by_ip: Optional[Dict[str, Dict[str, Any]]] = None,
    anomalies_by_ip: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    feed_results_by_ip: Optional[Dict[str, IPFeedReputation]] = None,
    feed_providers: Optional[Iterable[ReputationFeedProvider]] = None,
    feed_max_ips: Optional[int] = None,
    days: int = 30,
) -> str:
    """Return a stable cache key for a domain reputation input set."""
    feed_fingerprint = (
        _feed_provider_fingerprint(feed_providers, feed_max_ips=feed_max_ips)
        if feed_providers is not None
        else _feed_fingerprint(feed_results_by_ip)
    )
    payload = (
        f"source-reputation:{int(days)}:"
        f"{_source_fingerprint(sources)}:"
        f"{_report_fingerprint(reports)}:"
        f"{_context_fingerprint(senders_by_ip, anomalies_by_ip)}:"
        f"{feed_fingerprint}"
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _feed_fingerprint(feed_results_by_ip: Optional[Dict[str, IPFeedReputation]]) -> str:
    payload = json.dumps(
        {ip: asdict(result) for ip, result in sorted((feed_results_by_ip or {}).items())},
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


def _feed_provider_fingerprint(
    feed_providers: Iterable[ReputationFeedProvider],
    *,
    feed_max_ips: Optional[int],
) -> str:
    payload = json.dumps(
        {
            "max_ips": feed_max_ips,
            "providers": [
                {
                    "provider_id": provider.config.provider_id,
                    "enabled": provider.config.enabled,
                    "kind": provider.config.kind,
                    "query_zone": provider.config.query_zone,
                    "listing_name": provider.config.listing_name,
                }
                for provider in feed_providers
            ],
        },
        sort_keys=True,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:24]


async def build_source_reputation_cached(
    db: Session,
    domain: str,
    reports: Iterable[Dict[str, Any]],
    sources: Iterable[Dict[str, Any]],
    *,
    senders_by_ip: Optional[Dict[str, Dict[str, Any]]] = None,
    anomalies_by_ip: Optional[Dict[str, List[Dict[str, Any]]]] = None,
    days: int = 30,
    ttl_seconds: int = DEFAULT_DNS_CACHE_TTL_SECONDS,
    refresh: bool = False,
) -> Tuple[DomainReputation, bool, datetime]:
    """Build source reputation with persisted cache semantics."""
    now = _utcnow_naive()
    source_rows = list(sources)
    report_rows = list(reports)
    settings = get_settings()
    feed_providers = providers_from_settings(settings)
    cache_key = source_reputation_cache_key(
        source_rows,
        report_rows,
        senders_by_ip=senders_by_ip,
        anomalies_by_ip=anomalies_by_ip,
        feed_providers=feed_providers,
        feed_max_ips=settings.SOURCE_REPUTATION_FEED_MAX_IPS,
        days=days,
    )
    row = (
        db.query(DNSCache)
        .filter(
            DNSCache.domain == domain,
            DNSCache.provider == _CACHE_PROVIDER,
            DNSCache.selectors_key == cache_key,
        )
        .first()
    )
    if row and not refresh and _is_fresh(row, ttl_seconds, now):
        return _result_from_json(row.result_json), True, row.checked_at

    feed_results_by_ip = await lookup_sources_reputation_cached(
        db,
        [str(source.get("source_ip") or source.get("ip") or "unknown") for source in source_rows],
        feed_providers,
        ttl_seconds=settings.SOURCE_REPUTATION_FEED_CACHE_SECONDS,
        max_ips=settings.SOURCE_REPUTATION_FEED_MAX_IPS,
        refresh=refresh,
    )

    result = build_source_reputation(
        domain,
        report_rows,
        source_rows,
        senders_by_ip=senders_by_ip,
        anomalies_by_ip=anomalies_by_ip,
        feed_results_by_ip=feed_results_by_ip,
    )
    payload = json.dumps(asdict(result), sort_keys=True, separators=(",", ":"))
    if row is None:
        row = DNSCache(
            domain=domain,
            provider=_CACHE_PROVIDER,
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
                DNSCache.domain == domain,
                DNSCache.provider == _CACHE_PROVIDER,
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
