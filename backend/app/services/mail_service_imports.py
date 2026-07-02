"""Read-only mail service sender-domain discovery and import helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any, Dict, List, Optional

import httpx
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.credential_encryption import decrypt_secret
from app.models.domain import Domain

# Imported for model registration side effects when this service is loaded directly.
from app.models.mail_source_import import MailSourceImport  # noqa: F401
from app.models.setting import Setting
from app.models.workspace import Workspace
from app.services.organizations import require_organization_plan_limit
from app.services.workspaces import assign_default_workspace_to_unscoped_rows

POSTMARK_API_BASE = "https://api.postmarkapp.com"
MAIL_SERVICE_DESCRIPTION_PREFIX = "Mail-service sender domain imported from "


class MailServiceImportError(RuntimeError):
    """Raised when a mail service API request fails."""


@dataclass
class RequiredDNSRecord:
    """DNS record requested by a mail delivery service."""

    record_type: str
    name: str
    value: str
    purpose: str

    def to_dict(self) -> Dict[str, str]:
        return asdict(self)


@dataclass
# pylint: disable=too-many-instance-attributes
class MailServiceDomain:
    """One verified or pending sender domain visible in a mail service."""

    provider: str
    provider_name: str
    external_id: str
    domain: str
    verification_state: str
    imported: bool = False
    importable: bool = True
    required_dns_records: Optional[List[Dict[str, str]]] = None
    source: str = "mail_service_sender"
    next_action: str = "Import this sender domain to monitor DNS posture before reports arrive."

    def to_dict(self) -> Dict[str, Any]:
        payload = asdict(self)
        payload["required_dns_records"] = self.required_dns_records or []
        return payload


PROVIDER_NAMES = {
    "postmark": "Postmark",
}


def supported_mail_service_import_providers() -> List[Dict[str, str]]:
    """Return mail service providers that support sender-domain import."""
    return [{"id": provider_id, "name": name} for provider_id, name in PROVIDER_NAMES.items()]


def _provider_name(provider_id: str) -> str:
    return PROVIDER_NAMES.get(provider_id, provider_id)


def _normalize_provider(provider: str) -> str:
    return (provider or "").strip().lower().replace("_", "-")


def _setting_value(db: Session, key: str) -> Optional[str]:
    row = db.query(Setting).filter(Setting.key == key).first()
    if row is None or not row.value:
        return None
    if key == "postmark.account_token":
        return decrypt_secret(row.value)
    return row.value


def get_postmark_account_token(db: Session) -> Optional[str]:
    """Resolve the Postmark account token from settings or environment."""
    return _setting_value(db, "postmark.account_token") or get_settings().POSTMARK_ACCOUNT_TOKEN


def _domain_from_email(value: Any) -> Optional[str]:
    if not value:
        return None
    text = str(value).strip().lower()
    if "@" not in text:
        return None
    domain = text.rsplit("@", 1)[1].strip()
    return domain or None


def _verification_state(*flags: Optional[bool]) -> str:
    known = [flag for flag in flags if flag is not None]
    if known and all(known):
        return "verified"
    if known and any(known):
        return "partial"
    return "pending"


def _add_record(
    records: List[Dict[str, str]],
    *,
    record_type: str,
    name: Any,
    value: Any,
    purpose: str,
) -> None:
    if not name or not value:
        return
    records.append(
        RequiredDNSRecord(
            record_type=record_type,
            name=str(name),
            value=str(value),
            purpose=purpose,
        ).to_dict()
    )


def _postmark_domain_records(item: Dict[str, Any]) -> List[Dict[str, str]]:
    records: List[Dict[str, str]] = []
    _add_record(
        records,
        record_type="TXT",
        name=item.get("DKIMPendingHost") or item.get("DKIMHost"),
        value=item.get("DKIMPendingTextValue") or item.get("DKIMTextValue"),
        purpose="dkim",
    )
    _add_record(
        records,
        record_type="CNAME",
        name=item.get("ReturnPathDomain"),
        value=item.get("ReturnPathDomainCNAMEValue"),
        purpose="return_path",
    )
    return records


def _postmark_sender_records(item: Dict[str, Any]) -> List[Dict[str, str]]:
    records: List[Dict[str, str]] = []
    _add_record(
        records,
        record_type="TXT",
        name=item.get("DKIMHost"),
        value=item.get("DKIMTextValue"),
        purpose="dkim",
    )
    _add_record(
        records,
        record_type="CNAME",
        name=item.get("ReturnPathDomain"),
        value=item.get("ReturnPathDomainCNAMEValue"),
        purpose="return_path",
    )
    return records


async def _postmark_get(path: str, token: str) -> Dict[str, Any]:
    headers = {
        "Accept": "application/json",
        "X-Postmark-Account-Token": token,
    }
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.get(f"{POSTMARK_API_BASE}{path}", headers=headers)
            response.raise_for_status()
            return response.json()
    except (httpx.RequestError, httpx.HTTPStatusError, ValueError) as exc:
        raise MailServiceImportError(f"Postmark discovery failed: {exc}") from exc


async def _postmark_get_all(
    path: str,
    key: str,
    token: str,
    *,
    count: int = 500,
) -> List[Dict[str, Any]]:
    """Return every item from a paginated Postmark account endpoint."""
    items: List[Dict[str, Any]] = []
    offset = 0
    total_count: Optional[int] = None
    while total_count is None or offset < total_count:
        separator = "&" if "?" in path else "?"
        payload = await _postmark_get(f"{path}{separator}count={count}&offset={offset}", token)
        page_items = payload.get(key) or []
        items.extend(page_items)
        total_count = int(payload.get("TotalCount") or len(items))
        if not page_items:
            break
        offset += len(page_items)
        if offset >= total_count:
            break
    return items


def _first_present_bool(item: Dict[str, Any], *keys: str) -> Optional[bool]:
    for key in keys:
        if key in item:
            value = item.get(key)
            return bool(value) if value is not None else None
    return None


async def discover_postmark_sender_domains(
    db: Session,
    *,
    workspace_id: Optional[int] = None,
) -> List[Dict[str, Any]]:
    """Return Postmark sender domains and sender signatures with import state."""
    token = get_postmark_account_token(db)
    if not token:
        raise LookupError("Postmark account token is not configured")

    known_query = db.query(Domain.name)
    if workspace_id is not None:
        known_query = known_query.filter(Domain.workspace_id == workspace_id)
    known_domains = {name for (name,) in known_query.all()}

    domain_items = await _postmark_get_all("/domains", "Domains", token)
    sender_items = await _postmark_get_all("/senders", "SenderSignatures", token)
    items: Dict[str, Dict[str, Any]] = {}

    for item in domain_items:
        name = str(item.get("Name") or "").strip().lower()
        if not name:
            continue
        state = _verification_state(
            item.get("DKIMVerified"),
            _first_present_bool(item, "ReturnPathDomainVerified", "SPFVerified"),
        )
        items[name] = {
            "provider": "postmark",
            "provider_name": _provider_name("postmark"),
            "external_id": str(item.get("ID") or name),
            "domain": name,
            "verification_state": state,
            "required_dns_records": _postmark_domain_records(item),
            "imported": name in known_domains,
        }

    for item in sender_items:
        name = str(item.get("Domain") or "").strip().lower() or _domain_from_email(
            item.get("EmailAddress")
        )
        if not name:
            continue
        state = "verified" if item.get("Confirmed") else "pending"
        if name in items:
            if items[name]["verification_state"] != "verified" and state == "verified":
                items[name]["verification_state"] = state
            items[name]["required_dns_records"].extend(_postmark_sender_records(item))
            continue
        items[name] = {
            "provider": "postmark",
            "provider_name": _provider_name("postmark"),
            "external_id": str(item.get("ID") or name),
            "domain": name,
            "verification_state": state,
            "required_dns_records": _postmark_sender_records(item),
            "imported": name in known_domains,
        }

    return list(items.values())


async def preview_mail_service_import(
    db: Session,
    *,
    provider: str,
    workspace_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Return importable sender domains for a mail service without creating rows."""
    provider_id = _normalize_provider(provider)
    if provider_id != "postmark":
        raise LookupError(f"Unsupported mail service import: {provider_id}")

    domains = await discover_postmark_sender_domains(db, workspace_id=workspace_id)
    items = [
        MailServiceDomain(
            provider=provider_id,
            provider_name=_provider_name(provider_id),
            external_id=str(item["external_id"]),
            domain=str(item["domain"]).lower(),
            verification_state=str(item.get("verification_state") or "pending"),
            imported=bool(item.get("imported")),
            importable=not bool(item.get("imported")),
            required_dns_records=item.get("required_dns_records") or [],
            next_action=(
                "Already monitored in this workspace."
                if item.get("imported")
                else (
                    "Import this Postmark sender domain to monitor mail health before "
                    "reports arrive."
                )
            ),
        ).to_dict()
        for item in domains
    ]
    return {
        "provider": provider_id,
        "provider_name": _provider_name(provider_id),
        "domains": items,
        "total_discovered": len(items),
        "importable_count": sum(1 for item in items if item["importable"]),
    }


async def mail_service_dns_records_for_domain(
    db: Session,
    domain: str,
    *,
    workspace_id: Optional[int] = None,
) -> List[Dict[str, str]]:
    """Return provider-required DNS records for one sender domain."""
    normalized_domain = domain.strip().strip(".").lower()
    if not normalized_domain:
        return []
    try:
        domains = await discover_postmark_sender_domains(db, workspace_id=workspace_id)
    except (LookupError, MailServiceImportError):
        return []
    records: List[Dict[str, str]] = []
    for item in domains:
        if str(item.get("domain") or "").strip().strip(".").lower() != normalized_domain:
            continue
        for record in item.get("required_dns_records") or []:
            record_type = str(record.get("record_type") or "").strip().upper()
            name = str(record.get("name") or "").strip().strip(".")
            value = str(record.get("value") or "").strip().strip(".")
            if not record_type or not name or not value:
                continue
            records.append(
                {
                    "provider": "postmark",
                    "provider_name": _provider_name("postmark"),
                    "record_type": record_type,
                    "name": name,
                    "value": value,
                    "purpose": str(record.get("purpose") or "sender_verification"),
                }
            )
    return records


def mail_service_context_from_domain(domain: Optional[Domain]) -> List[Dict[str, str]]:
    """Extract displayable mail service context from imported domain descriptions."""
    if domain is None or not domain.description:
        return []
    description = domain.description.strip()
    if not description.startswith(MAIL_SERVICE_DESCRIPTION_PREFIX):
        return []
    remainder = description[len(MAIL_SERVICE_DESCRIPTION_PREFIX) :]
    provider_name = remainder.split("(", 1)[0].strip().rstrip(".")
    state = ""
    if "(" in remainder and ")" in remainder:
        state = remainder.split("(", 1)[1].split(")", 1)[0].strip()
    return [
        {
            "provider": provider_name.lower(),
            "provider_name": provider_name,
            "verification_state": state or "unknown",
            "source": "mail_service_sender",
        }
    ]


def _existing_domain_names(db: Session, domain_names: List[str]) -> set[str]:
    if not domain_names:
        return set()
    return {row[0] for row in db.query(Domain.name).filter(Domain.name.in_(domain_names)).all()}


def _create_imported_domain(
    db: Session,
    *,
    name: str,
    provider_name: str,
    state: str,
    workspace_id: int,
) -> str:
    db.add(
        Domain(
            name=name,
            description=(
                f"{MAIL_SERVICE_DESCRIPTION_PREFIX}{provider_name} "
                f"({state}). DNS records are still linted and repaired in DMARQ."
            ),
            active=True,
            verified=(state == "verified"),
            workspace_id=workspace_id,
        )
    )
    try:
        db.commit()
        return "imported"
    except IntegrityError:
        db.rollback()
        return "existing" if _existing_domain_names(db, [name]) else "skipped"


async def import_mail_service_domains(
    db: Session,
    *,
    provider: str,
    requested_domains: Optional[List[str]] = None,
    workspace_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Import selected mail service sender domains as monitored domains."""
    # pylint: disable=too-many-branches,too-many-locals
    provider_id = _normalize_provider(provider)
    if provider_id != "postmark":
        raise LookupError(f"Unsupported mail service import: {provider_id}")

    if workspace_id is None:
        workspace = assign_default_workspace_to_unscoped_rows(db)
        workspace_id = workspace.id
    else:
        workspace = db.query(Workspace).filter(Workspace.id == workspace_id).first()

    preview = await preview_mail_service_import(
        db,
        provider=provider_id,
        workspace_id=workspace_id,
    )
    requested = {domain.strip().lower() for domain in requested_domains or [] if domain.strip()}
    imported: List[str] = []
    existing: List[str] = []
    skipped: List[str] = []
    candidate_names: List[str] = []
    states: Dict[str, str] = {}

    for item in preview["domains"]:
        name = str(item["domain"]).lower()
        if requested and name not in requested:
            skipped.append(name)
            continue
        candidate_names.append(name)
        states[name] = str(item.get("verification_state") or "pending")

    existing_names = _existing_domain_names(db, candidate_names)
    new_names = [name for name in candidate_names if name not in existing_names]
    if workspace and workspace.organization and new_names:
        require_organization_plan_limit(
            db,
            workspace.organization,
            "monitored_domains",
            increment=len(new_names),
        )

    provider_name = _provider_name(provider_id)
    for name in candidate_names:
        if name in existing_names:
            existing.append(name)
        else:
            result = _create_imported_domain(
                db,
                name=name,
                provider_name=provider_name,
                state=states.get(name, "pending"),
                workspace_id=workspace_id,
            )
            if result == "imported":
                imported.append(name)
            elif result == "existing":
                existing.append(name)
            else:
                skipped.append(name)
    return {
        "provider": provider_id,
        "provider_name": provider_name,
        "imported": imported,
        "existing": existing,
        "skipped": skipped,
        "total_discovered": preview["total_discovered"],
    }
