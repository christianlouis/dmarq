"""Cloudflare DNS discovery, analysis, and change tracking."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.credential_encryption import decrypt_secret
from app.models.dns_cache import DNSRecordChange, DNSRecordSnapshot
from app.models.domain import Domain
from app.models.setting import Setting
from app.services.dns_resolver import (
    CloudflareDNSProvider,
    extract_dmarc_policy,
    parse_dmarc_record_tags,
)
from app.services.workspaces import assign_default_workspace_to_unscoped_rows

PROVIDER_NAME = "cloudflare"


@dataclass
class CloudflareCredentials:
    """Resolved Cloudflare credentials from persisted settings or environment."""

    api_token: Optional[str] = None
    zone_id: Optional[str] = None

    @property
    def configured(self) -> bool:
        return bool(self.api_token)


def _utcnow_naive() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _plain_setting_value(db: Session, key: str) -> Optional[str]:
    row = db.query(Setting).filter(Setting.key == key).first()
    if row is None or not row.value:
        return None
    if key == "cloudflare.api_token":
        return decrypt_secret(row.value)
    return row.value


def get_cloudflare_credentials(db: Session) -> CloudflareCredentials:
    """Resolve Cloudflare credentials from app settings, falling back to env vars."""
    settings = get_settings()
    return CloudflareCredentials(
        api_token=_plain_setting_value(db, "cloudflare.api_token") or settings.CLOUDFLARE_API_TOKEN,
        zone_id=_plain_setting_value(db, "cloudflare.zone_id") or settings.CLOUDFLARE_ZONE_ID,
    )


def build_cloudflare_provider(db: Session) -> CloudflareDNSProvider:
    """Return a Cloudflare provider configured from settings and environment."""
    credentials = get_cloudflare_credentials(db)
    if not credentials.configured:
        raise LookupError("Cloudflare API token is not configured")
    return CloudflareDNSProvider(
        api_token=credentials.api_token,
        zone_id=credentials.zone_id,
    )


async def discover_cloudflare_zones(
    db: Session,
    *,
    workspace_id: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Return zones visible to the configured Cloudflare token with import state."""
    provider = build_cloudflare_provider(db)
    known_query = db.query(Domain.name)
    if workspace_id is not None:
        known_query = known_query.filter(Domain.workspace_id == workspace_id)
    known_domains = {name for (name,) in known_query.all()}
    zones = await provider.list_zones()
    return [
        {
            "id": zone.get("id"),
            "name": zone.get("name"),
            "status": zone.get("status"),
            "account_name": (zone.get("account") or {}).get("name"),
            "imported": zone.get("name") in known_domains,
        }
        for zone in zones
        if zone.get("id") and zone.get("name")
    ]


async def import_cloudflare_domains(
    db: Session,
    *,
    requested_domains: Optional[List[str]] = None,
    workspace_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Create Domain rows for Cloudflare zones, returning imported and existing names."""
    if workspace_id is None:
        workspace = assign_default_workspace_to_unscoped_rows(db)
        workspace_id = workspace.id
    zones = await discover_cloudflare_zones(db, workspace_id=workspace_id)
    requested = {domain.strip().lower() for domain in requested_domains or [] if domain.strip()}
    imported: List[str] = []
    existing: List[str] = []
    skipped: List[str] = []

    for zone in zones:
        name = str(zone["name"]).lower()
        if requested and name not in requested:
            skipped.append(name)
            continue
        domain = (
            db.query(Domain)
            .filter(Domain.name == name, Domain.workspace_id == workspace_id)
            .first()
        )
        if domain is None:
            db.add(Domain(name=name, active=True, verified=True, workspace_id=workspace_id))
            imported.append(name)
        else:
            existing.append(name)

    db.commit()
    return {
        "imported": imported,
        "existing": existing,
        "skipped": skipped,
        "total_discovered": len(zones),
    }


async def get_zone_for_domain(db: Session, domain: str) -> Dict[str, Any]:
    """Resolve the Cloudflare zone for a domain name."""
    provider = build_cloudflare_provider(db)
    credentials = get_cloudflare_credentials(db)
    if credentials.zone_id:
        records = await provider.list_dns_records(zone_id=credentials.zone_id)
        try:
            zone = await provider.find_zone_for_domain(domain)
        except LookupError:
            zone = None
        return {
            "id": credentials.zone_id,
            "name": zone.get("name") if zone else domain,
            "records": records,
        }
    zone = await provider.find_zone_for_domain(domain)
    if not zone:
        raise LookupError(f"No Cloudflare zone found for {domain}")
    records = await provider.list_dns_records(zone_id=zone["id"])
    return {"id": zone["id"], "name": zone["name"], "records": records}


def _record_key(record: Dict[str, Any]) -> str:
    record_id = record.get("id")
    if record_id:
        return str(record_id)
    payload = json.dumps(
        {
            "type": record.get("type"),
            "name": record.get("name"),
            "content": record.get("content"),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _record_hash(record: Dict[str, Any]) -> str:
    payload = json.dumps(
        {
            "type": record.get("type"),
            "name": record.get("name"),
            "content": record.get("content"),
            "proxied": record.get("proxied"),
            "ttl": record.get("ttl"),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _change_to_dict(change: DNSRecordChange) -> Dict[str, Any]:
    return {
        "id": change.id,
        "domain": change.domain,
        "provider": change.provider,
        "zone_id": change.zone_id,
        "record_type": change.record_type,
        "record_name": change.record_name,
        "change_type": change.change_type,
        "previous_content": change.previous_content,
        "current_content": change.current_content,
        "observed_at": change.observed_at.isoformat() if change.observed_at else None,
    }


def sync_dns_record_changes(
    db: Session,
    *,
    domain: str,
    zone_id: str,
    records: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Track additions, modifications, and removals for a Cloudflare DNS snapshot."""
    now = _utcnow_naive()
    existing = {
        snapshot.record_key: snapshot
        for snapshot in db.query(DNSRecordSnapshot)
        .filter(
            DNSRecordSnapshot.domain == domain,
            DNSRecordSnapshot.provider == PROVIDER_NAME,
            DNSRecordSnapshot.zone_id == zone_id,
            DNSRecordSnapshot.active == True,  # noqa: E712
        )
        .all()
    }
    seen: set[str] = set()
    changes: List[DNSRecordChange] = []

    for record in records:
        record_type = str(record.get("type") or "").upper()
        record_name = str(record.get("name") or "")
        if not record_type or not record_name:
            continue
        key = _record_key(record)
        seen.add(key)
        content = record.get("content")
        current_hash = _record_hash(record)
        snapshot = existing.get(key)
        if snapshot is None:
            snapshot = DNSRecordSnapshot(
                domain=domain,
                provider=PROVIDER_NAME,
                zone_id=zone_id,
                record_key=key,
                record_id=record.get("id"),
                record_type=record_type,
                record_name=record_name,
                content=content,
                proxied=record.get("proxied"),
                ttl=record.get("ttl"),
                record_hash=current_hash,
                active=True,
                first_seen_at=now,
                last_seen_at=now,
            )
            db.add(snapshot)
            changes.append(
                DNSRecordChange(
                    domain=domain,
                    provider=PROVIDER_NAME,
                    zone_id=zone_id,
                    record_key=key,
                    record_id=record.get("id"),
                    record_type=record_type,
                    record_name=record_name,
                    change_type="added",
                    current_content=content,
                    observed_at=now,
                )
            )
            continue

        if snapshot.record_hash != current_hash:
            changes.append(
                DNSRecordChange(
                    domain=domain,
                    provider=PROVIDER_NAME,
                    zone_id=zone_id,
                    record_key=key,
                    record_id=record.get("id"),
                    record_type=record_type,
                    record_name=record_name,
                    change_type="modified",
                    previous_content=snapshot.content,
                    current_content=content,
                    observed_at=now,
                )
            )
            snapshot.content = content
            snapshot.proxied = record.get("proxied")
            snapshot.ttl = record.get("ttl")
            snapshot.record_hash = current_hash
        snapshot.record_id = record.get("id")
        snapshot.record_type = record_type
        snapshot.record_name = record_name
        snapshot.active = True
        snapshot.last_seen_at = now

    for key, snapshot in existing.items():
        if key in seen:
            continue
        snapshot.active = False
        snapshot.last_seen_at = now
        changes.append(
            DNSRecordChange(
                domain=domain,
                provider=PROVIDER_NAME,
                zone_id=zone_id,
                record_key=key,
                record_id=snapshot.record_id,
                record_type=snapshot.record_type,
                record_name=snapshot.record_name,
                change_type="removed",
                previous_content=snapshot.content,
                observed_at=now,
            )
        )

    for change in changes:
        db.add(change)
    db.commit()
    for change in changes:
        db.refresh(change)
    return [_change_to_dict(change) for change in changes]


def list_dns_record_changes(db: Session, domain: str, *, limit: int = 50) -> List[Dict[str, Any]]:
    """Return recent DNS record change events for a domain."""
    rows = (
        db.query(DNSRecordChange)
        .filter(DNSRecordChange.domain == domain)
        .order_by(DNSRecordChange.observed_at.desc(), DNSRecordChange.id.desc())
        .limit(max(1, min(limit, 200)))
        .all()
    )
    return [_change_to_dict(row) for row in rows]


def _txt_contents(records: List[Dict[str, Any]], name: str) -> List[str]:
    target = name.rstrip(".").lower()
    return [
        str(record.get("content") or "")
        for record in records
        if str(record.get("type") or "").upper() == "TXT"
        and str(record.get("name") or "").rstrip(".").lower() == target
    ]


def _cloudflare_record_to_dict(record: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": record.get("id"),
        "type": record.get("type"),
        "name": record.get("name"),
        "content": record.get("content"),
        "ttl": record.get("ttl"),
        "proxied": record.get("proxied"),
        "modified_on": record.get("modified_on"),
    }


def analyze_dns_records(domain: str, records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Analyze Cloudflare DNS records and return checks plus actionable suggestions."""
    root_txt = _txt_contents(records, domain)
    dmarc_records = _txt_contents(records, f"_dmarc.{domain}")
    spf_records = [record for record in root_txt if record.lower().startswith("v=spf1")]
    dmarc_candidate_records = [record for record in dmarc_records if "v=dmarc1" in record.lower()]
    dmarc_auth_records = [
        record for record in dmarc_candidate_records if parse_dmarc_record_tags(record)
    ]
    dkim_records = [
        record
        for record in records
        if str(record.get("type") or "").upper() == "TXT"
        and "._domainkey." in str(record.get("name") or "").lower()
        and ("v=dkim1" in str(record.get("content") or "").lower())
    ]

    suggestions: List[Dict[str, str]] = []
    if not dmarc_candidate_records:
        suggestions.append(
            {
                "type": "missing_dmarc",
                "severity": "error",
                "message": "Add a TXT record at _dmarc with a v=DMARC1 policy.",
            }
        )
    elif len(dmarc_candidate_records) > 1:
        suggestions.append(
            {
                "type": "duplicate_dmarc",
                "severity": "error",
                "message": "Keep exactly one DMARC TXT record at _dmarc.",
            }
        )
    elif not dmarc_auth_records or extract_dmarc_policy(dmarc_auth_records[0]) is None:
        suggestions.append(
            {
                "type": "malformed_dmarc",
                "severity": "error",
                "message": "Add a p=none, p=quarantine, or p=reject tag to the DMARC record.",
            }
        )

    if not spf_records:
        suggestions.append(
            {
                "type": "missing_spf",
                "severity": "warning",
                "message": "Add an SPF TXT record at the root domain for authorized senders.",
            }
        )
    elif len(spf_records) > 1:
        suggestions.append(
            {
                "type": "duplicate_spf",
                "severity": "error",
                "message": "Merge multiple SPF records into a single v=spf1 TXT record.",
            }
        )

    if not dkim_records:
        suggestions.append(
            {
                "type": "missing_dkim",
                "severity": "warning",
                "message": "No DKIM TXT records were found; configure DKIM for active mail providers.",
            }
        )

    return {
        "records": [_cloudflare_record_to_dict(record) for record in records],
        "checks": {
            "dmarc": bool(dmarc_auth_records),
            "dmarc_record": dmarc_auth_records[0] if dmarc_auth_records else None,
            "dmarc_policy": (
                extract_dmarc_policy(dmarc_auth_records[0]) if dmarc_auth_records else None
            ),
            "spf": len(spf_records) == 1,
            "spf_record": spf_records[0] if spf_records else None,
            "dkim": bool(dkim_records),
            "dkim_records": [
                _cloudflare_record_to_dict(record)
                for record in sorted(dkim_records, key=lambda item: str(item.get("name") or ""))
            ],
        },
        "suggestions": suggestions,
    }
