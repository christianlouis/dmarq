"""Parse, compare, persist, and remove imported DNS zone evidence."""

from __future__ import annotations

import asyncio
import hashlib
import json
from datetime import datetime, timedelta
from typing import Any, Dict, List

import dns.asyncresolver
import dns.exception
import dns.name
import dns.resolver
import dns.zone
from sqlalchemy.orm import Session

from app.models.dns_zone_baseline import DNSZoneBaseline

SUPPORTED_TYPES = {"SOA", "NS", "MX", "A", "AAAA", "TXT", "CNAME"}
COMPARISON_TYPES = {"NS", "MX", "TXT", "CNAME"}
MAX_ZONE_BYTES = 1_000_000
MAX_RECORDS = 5_000


def _normalize_value(record_type: str, value: str) -> str:
    value = value.strip()
    if record_type == "TXT":
        return value.removeprefix('"').removesuffix('"').replace('" "', "")
    if record_type in {"NS", "CNAME"}:
        return value.rstrip(".").lower()
    return value


def parse_bind_zone(domain: str, zone_text: str) -> List[Dict[str, Any]]:  # noqa: C901
    """Parse a BIND export with an explicit zone origin and no provider credentials."""
    normalized_domain = domain.strip().strip(".").lower()
    if not normalized_domain:
        raise ValueError("Domain is required for a zone baseline")
    if not zone_text.strip():
        raise ValueError("Zone text is empty")
    if len(zone_text.encode("utf-8")) > MAX_ZONE_BYTES:
        raise ValueError("Zone text exceeds the 1 MB safety limit")
    try:
        zone = dns.zone.from_text(
            zone_text,
            origin=dns.name.from_text(f"{normalized_domain}."),
            relativize=False,
            check_origin=False,
        )
    except (dns.exception.DNSException, ValueError) as exc:
        raise ValueError(f"Zone text is not valid BIND data: {exc}") from exc
    records: List[Dict[str, Any]] = []
    for owner, node in zone.nodes.items():
        name = str(owner).rstrip(".").lower()
        for rdataset in node.rdatasets:
            record_type = dns.rdatatype.to_text(rdataset.rdtype)
            if record_type not in SUPPORTED_TYPES:
                continue
            for rdata in rdataset:
                records.append(
                    {
                        "name": name,
                        "type": record_type,
                        "ttl": rdataset.ttl,
                        "value": _normalize_value(record_type, rdata.to_text()),
                    }
                )
                if len(records) > MAX_RECORDS:
                    raise ValueError("Zone baseline exceeds the 5,000 record safety limit")
    if not records:
        raise ValueError("Zone baseline contains no supported DNS records")
    return sorted(records, key=lambda item: (item["name"], item["type"], item["value"]))


async def _resolve_public(name: str, record_type: str) -> Dict[str, Any]:
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 3.0
    try:
        answer = await resolver.resolve(name, record_type)
        values = [_normalize_value(record_type, item.to_text()) for item in answer]
        return {"status": "observed", "values": sorted(values)}
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return {"status": "absent", "values": []}
    except (dns.exception.DNSException, OSError) as exc:
        return {"status": "unavailable", "values": [], "error": str(exc)}


async def compare_with_public_dns(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Compare imported evidence with public DNS without treating either as authoritative truth."""
    grouped: Dict[tuple[str, str], List[str]] = {}
    for record in records:
        key = (record["name"], record["type"])
        if record["type"] in COMPARISON_TYPES:
            grouped.setdefault(key, []).append(record["value"])
    keys = list(grouped)[:100]
    observations = await asyncio.gather(*(_resolve_public(name, rtype) for name, rtype in keys))
    comparison = []
    for (name, record_type), public in zip(keys, observations):
        imported = sorted(grouped[(name, record_type)])
        public_values = public["values"]
        comparison.append(
            {
                "name": name,
                "type": record_type,
                "imported_values": imported,
                "public_values": public_values,
                "public_status": public["status"],
                "matches": public["status"] == "observed" and imported == public_values,
                "provenance": {
                    "imported": "local zone baseline",
                    "public": "system public DNS resolver",
                },
                **({"error": public["error"]} if public.get("error") else {}),
            }
        )
    return comparison


async def preview_zone_baseline(domain: str, zone_text: str) -> Dict[str, Any]:
    records = parse_bind_zone(domain, zone_text)
    comparison = await compare_with_public_dns(records)
    return {
        "domain": domain.strip().strip(".").lower(),
        "records": records,
        "record_count": len(records),
        "comparison": comparison,
        "mismatch_count": sum(1 for item in comparison if not item["matches"]),
        "provenance": "imported_zone_baseline",
        "affects_health_score": False,
    }


async def save_zone_baseline(
    db: Session,
    *,
    workspace_id: int,
    domain: str,
    zone_text: str,
    ttl_hours: int = 24,
    source: str = "manual_bind_import",
) -> DNSZoneBaseline:
    preview = await preview_zone_baseline(domain, zone_text)
    now = datetime.utcnow()
    baseline = DNSZoneBaseline(
        workspace_id=workspace_id,
        domain=preview["domain"],
        source=source,
        source_hash=hashlib.sha256(zone_text.encode("utf-8")).hexdigest(),
        records_json=json.dumps(preview["records"], sort_keys=True),
        comparison_json=json.dumps(preview["comparison"], sort_keys=True),
        imported_at=now,
        expires_at=now + timedelta(hours=max(1, min(ttl_hours, 168))),
    )
    db.add(baseline)
    db.commit()
    db.refresh(baseline)
    return baseline


def baseline_payload(item: DNSZoneBaseline) -> Dict[str, Any]:
    return {
        "id": item.id,
        "domain": item.domain,
        "source": item.source,
        "record_count": len(json.loads(item.records_json)),
        "comparison": json.loads(item.comparison_json or "[]"),
        "imported_at": item.imported_at.isoformat(),
        "expires_at": item.expires_at.isoformat(),
        "expired": item.expires_at <= datetime.utcnow(),
        "removed": item.removed_at is not None,
        "provenance": "imported_zone_baseline",
        "affects_health_score": False,
    }
