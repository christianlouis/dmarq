"""Privacy-preserving AI and agent assistance helpers."""

from __future__ import annotations

import hashlib
import json
import re
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional

from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.redaction import SENSITIVE_VALUE, redact_sensitive_text
from app.models.domain import Domain
from app.models.mail_source import MailSource
from app.models.setting import Setting
from app.services.bimi import check_bimi_cached
from app.services.dns_cache import resolve_domain_dns_cached
from app.services.dns_guidance import build_dns_guidance
from app.services.dns_resolver import get_default_provider
from app.services.mta_sts import check_mta_sts_cached
from app.services.report_persistence import hydrate_report_store_from_db
from app.services.report_store import ReportStore

AI_DEFAULTS = {
    "ai.enabled": "false",
    "ai.provider": "template",
    "ai.model": "",
    "ai.remote_base_url": "",
    "ai.redaction_mode": "strict",
    "ai.action_tools_enabled": "false",
    "ai.remediation_cache_seconds": "86400",
    "mcp.enabled": "false",
}

EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b", re.IGNORECASE)
LONG_TOKEN_PATTERN = re.compile(r"\b[A-Za-z0-9._~+/=-]{24,}\b")
REMEDIATION_CACHE_MAX_ENTRIES = 256
_REMEDIATION_CACHE: Dict[str, tuple[float, Dict[str, Any]]] = {}


@dataclass(frozen=True)
class AssistanceConfig:
    """Operator-controlled automation settings."""

    ai_enabled: bool
    provider: str
    model: str
    remote_base_url: str
    redaction_mode: str
    action_tools_enabled: bool
    mcp_enabled: bool
    remediation_cache_seconds: int

    def to_dict(self) -> Dict[str, Any]:
        """Return a UI/API-safe provider configuration."""
        return {
            "ai_enabled": self.ai_enabled,
            "provider": self.provider,
            "model": self.model,
            "remote_base_url_configured": bool(self.remote_base_url),
            "redaction_mode": self.redaction_mode,
            "action_tools_enabled": self.action_tools_enabled,
            "mcp_enabled": self.mcp_enabled,
            "remediation_cache_seconds": self.remediation_cache_seconds,
            "data_handling": {
                "default_provider": "template",
                "secrets_in_prompts": "never",
                "raw_message_content": "never",
                "remote_provider_requires_opt_in": True,
            },
        }


def _setting_value(db: Session, key: str) -> str:
    row = db.query(Setting).filter(Setting.key == key).first()
    if row is None:
        return AI_DEFAULTS.get(key, "")
    return row.value or ""


def _setting_bool(db: Session, key: str) -> bool:
    return _setting_value(db, key).strip().lower() in {"1", "true", "yes", "on"}


def _setting_int(db: Session, key: str, default: int) -> int:
    try:
        return max(0, int(_setting_value(db, key) or default))
    except (TypeError, ValueError):
        return default


def get_assistance_config(db: Session) -> AssistanceConfig:
    """Load AI/MCP settings with safe defaults."""
    provider = (_setting_value(db, "ai.provider") or "template").strip().lower()
    if provider not in {"template", "local", "remote", "litellm"}:
        provider = "template"
    redaction_mode = (_setting_value(db, "ai.redaction_mode") or "strict").strip().lower()
    if redaction_mode not in {"strict", "balanced"}:
        redaction_mode = "strict"
    return AssistanceConfig(
        ai_enabled=_setting_bool(db, "ai.enabled"),
        provider=provider,
        model=_setting_value(db, "ai.model").strip(),
        remote_base_url=_setting_value(db, "ai.remote_base_url").strip(),
        redaction_mode=redaction_mode,
        action_tools_enabled=_setting_bool(db, "ai.action_tools_enabled"),
        mcp_enabled=_setting_bool(db, "mcp.enabled"),
        remediation_cache_seconds=_setting_int(db, "ai.remediation_cache_seconds", 86400),
    )


def redact_safe_value(value: Any, *, mode: str = "strict") -> Any:
    """Redact values before they can be shared with model or agent surfaces."""
    if isinstance(value, dict):
        return {str(key): redact_safe_value(item, mode=mode) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_safe_value(item, mode=mode) for item in value]
    if not isinstance(value, str):
        return value
    redacted = redact_sensitive_text(value)
    redacted = LONG_TOKEN_PATTERN.sub(SENSITIVE_VALUE, redacted)
    if mode == "strict":
        redacted = EMAIL_PATTERN.sub(r"*@\1", redacted)
    return redacted


def _domain_exists(
    db: Session,
    store: ReportStore,
    domain: str,
    *,
    workspace_id: Optional[int] = None,
) -> bool:
    if workspace_id is None and domain in store.get_domains():
        return True
    query = db.query(Domain.id).filter(Domain.name == domain, Domain.active.is_(True))
    if workspace_id is not None:
        query = query.filter(Domain.workspace_id == workspace_id)
    return query.first() is not None


def _evidence(label: str, value: Any, href: str) -> Dict[str, str]:
    return {
        "label": label,
        "value": str(value),
        "href": href,
    }


def _domain_selectors_from_db(
    db: Session,
    domain: str,
    *,
    workspace_id: Optional[int] = None,
) -> List[str]:
    query = db.query(Domain.dkim_selectors).filter(Domain.name == domain)
    if workspace_id is not None:
        query = query.filter(Domain.workspace_id == workspace_id)
    row = query.first()
    if row is None:
        return []
    return [selector.strip() for selector in (row[0] or "").split(",") if selector.strip()]


def _selectors_from_reports(store: ReportStore, domain: str) -> List[str]:
    selectors: List[str] = []
    for report in store.get_domain_reports(domain):
        for record in report.get("records", []):
            for dkim_entry in record.get("dkim") or []:
                if not isinstance(dkim_entry, dict):
                    continue
                selector = str(dkim_entry.get("selector") or "").strip()
                if selector and selector not in selectors:
                    selectors.append(selector)
    return selectors


def _mail_source_context(
    db: Session,
    *,
    workspace_id: Optional[int] = None,
) -> List[Dict[str, Any]]:
    query = db.query(MailSource).filter(MailSource.enabled.is_(True))
    if workspace_id is not None:
        query = query.filter(MailSource.workspace_id == workspace_id)
    rows = query.order_by(MailSource.name).all()
    return [
        {
            "name": source.name,
            "method": source.method,
            "server": source.server or None,
            "folder": source.folder,
            "polling_interval_minutes": source.polling_interval,
            "last_checked": source.last_checked.isoformat() if source.last_checked else None,
        }
        for source in rows[:10]
    ]


def _remediation_cache_key(context: Dict[str, Any]) -> str:
    serialized = json.dumps(context, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _stable_cache_context(context: Dict[str, Any]) -> Dict[str, Any]:
    stable = dict(context)
    stable["generated_at"] = "<generated>"
    return stable


def _cache_get(key: str, ttl_seconds: int) -> Optional[Dict[str, Any]]:
    _cache_prune(ttl_seconds)
    cached = _REMEDIATION_CACHE.get(key)
    if cached is None:
        return None
    created_at, payload = cached
    if ttl_seconds and time.time() - created_at <= ttl_seconds:
        return payload
    _REMEDIATION_CACHE.pop(key, None)
    return None


def _cache_prune(ttl_seconds: int) -> None:
    if ttl_seconds:
        now = time.time()
        expired_keys = [
            key
            for key, (created_at, _payload) in _REMEDIATION_CACHE.items()
            if now - created_at > ttl_seconds
        ]
        for key in expired_keys:
            _REMEDIATION_CACHE.pop(key, None)
    while len(_REMEDIATION_CACHE) > REMEDIATION_CACHE_MAX_ENTRIES:
        oldest_key = min(_REMEDIATION_CACHE, key=lambda item: _REMEDIATION_CACHE[item][0])
        _REMEDIATION_CACHE.pop(oldest_key, None)


def _cache_set(key: str, payload: Dict[str, Any]) -> None:
    if len(_REMEDIATION_CACHE) >= REMEDIATION_CACHE_MAX_ENTRIES:
        oldest_key = min(_REMEDIATION_CACHE, key=lambda item: _REMEDIATION_CACHE[item][0])
        _REMEDIATION_CACHE.pop(oldest_key, None)
    _REMEDIATION_CACHE[key] = (time.time(), payload)


def _template_remediation_plan(context: Dict[str, Any]) -> Dict[str, Any]:
    findings = context["dns_guidance"]["findings"]
    actions = []
    for index, finding in enumerate(findings, start=1):
        actions.append(
            {
                "id": f"remediate-{index}",
                "finding_code": finding["code"],
                "title": finding["title"],
                "priority": finding["severity"],
                "summary": finding["action"],
                "steps": finding.get("remediation_steps")
                or [
                    "Review the linked evidence.",
                    "Apply the smallest DNS or provider configuration change.",
                    "Refresh DMARQ after propagation.",
                ],
                "evidence": finding.get("evidence", []),
                "target_record": finding.get("target_record"),
                "requires_human_change": True,
            }
        )
    return {
        "domain": context["domain"],
        "provider": "template",
        "cached": False,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": (
            "DMARQ built this remediation plan from local DNS, report, and infrastructure "
            "context. No remote model was used."
        ),
        "actions": actions,
        "safe_context": context,
    }


async def _litellm_remediation_plan(
    config: AssistanceConfig,
    context: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    try:
        import litellm  # pylint: disable=import-outside-toplevel  # type: ignore[import]
    except ImportError:
        return None

    model = config.model or "gpt-4o-mini"
    litellm.drop_params = True
    messages = [
        {
            "role": "system",
            "content": (
                "You generate concise, operational remediation plans for DMARC, SPF, "
                "DKIM, MTA-STS, TLS-RPT, and BIMI findings. Never suggest automatic "
                "DNS changes. Return only valid JSON with keys summary and actions. "
                "Each action must include finding_code, title, priority, summary, "
                "steps, evidence, target_record, and requires_human_change."
            ),
        },
        {
            "role": "user",
            "content": json.dumps(context, sort_keys=True),
        },
    ]
    kwargs: Dict[str, Any] = {
        "model": model,
        "messages": messages,
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
        "timeout": 20,
    }
    if config.remote_base_url:
        kwargs["api_base"] = config.remote_base_url
    try:
        response = await litellm.acompletion(**kwargs)
        content = response["choices"][0]["message"]["content"]
        parsed = json.loads(content)
    except Exception:  # pylint: disable=broad-exception-caught
        return None

    actions = parsed.get("actions")
    if not isinstance(actions, list):
        return None
    return {
        "domain": context["domain"],
        "provider": "litellm",
        "model": model,
        "cached": False,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "summary": str(parsed.get("summary") or "AI-generated remediation plan."),
        "actions": actions,
        "safe_context": context,
    }


async def build_remediation_plan(  # pylint: disable=too-many-locals
    db: Session,
    domain: str,
    *,
    finding_code: Optional[str] = None,
    refresh: bool = False,
    workspace_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Build a step-by-step remediation plan, optionally enhanced through LiteLLM."""
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store, workspace_id=workspace_id)
    if not _domain_exists(db, store, domain, workspace_id=workspace_id):
        raise ValueError("Domain not found")

    config = get_assistance_config(db)
    manual_selectors = _domain_selectors_from_db(db, domain, workspace_id=workspace_id)
    report_selectors = _selectors_from_reports(store, domain)
    combined_selectors = list(dict.fromkeys(manual_selectors + report_selectors))
    provider = get_default_provider(db)
    dns_result, _, _ = await resolve_domain_dns_cached(
        db,
        provider,
        domain,
        selectors=combined_selectors,
        refresh=refresh,
    )
    mta_sts_result, _, _ = await check_mta_sts_cached(db, provider, domain, refresh=refresh)
    bimi_result, _, _ = await check_bimi_cached(db, provider, domain, refresh=refresh)
    guidance = await build_dns_guidance(
        domain,
        provider,
        dns_result,
        mta_sts_result,
        bimi_result,
        monitored_selectors=combined_selectors,
        observed_selectors=report_selectors,
    )
    finding_dicts = [asdict(finding) for finding in guidance.findings]
    if finding_code:
        finding_dicts = [finding for finding in finding_dicts if finding["code"] == finding_code]

    context = redact_safe_value(
        {
            "domain": domain,
            "generated_at": datetime.utcnow().isoformat() + "Z",
            "demo_mode": get_settings().DEMO_MODE,
            "dns_provider": provider.__class__.__name__,
            "mail_sources": _mail_source_context(db, workspace_id=workspace_id),
            "dkim_selectors": {
                "manual": manual_selectors,
                "observed_from_reports": report_selectors,
                "checked": dns_result.selectors_checked,
                "resolved": dns_result.dkim_selectors,
            },
            "safe_summary": build_safe_context(db, domain, workspace_id=workspace_id)["summary"],
            "dns_guidance": {
                "status": guidance.status,
                "findings": finding_dicts,
                "target_records": [asdict(record) for record in guidance.target_records],
            },
            "constraints": {
                "read_only_product_default": True,
                "automatic_dns_changes": False,
                "secrets_in_prompts": "never",
                "raw_message_content": "never",
            },
        },
        mode=config.redaction_mode,
    )
    cache_ttl = 30 * 24 * 60 * 60 if get_settings().DEMO_MODE else config.remediation_cache_seconds
    cache_key = _remediation_cache_key(
        {
            "provider": config.provider,
            "model": config.model,
            "base_url_configured": bool(config.remote_base_url),
            "context": _stable_cache_context(context),
        }
    )
    cached = _cache_get(cache_key, cache_ttl)
    if cached:
        return {**cached, "cached": True}

    plan = _template_remediation_plan(context)
    if (
        config.ai_enabled
        and config.provider in {"remote", "local", "litellm"}
        and not get_settings().DEMO_MODE
    ):
        llm_plan = await _litellm_remediation_plan(config, context)
        if llm_plan is not None:
            plan = llm_plan

    _cache_set(cache_key, plan)
    return plan


def build_safe_context(
    db: Session,
    domain: str,
    *,
    workspace_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Build a redacted, evidence-linked context bundle for one domain."""
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store, workspace_id=workspace_id)
    if not _domain_exists(db, store, domain, workspace_id=workspace_id):
        raise ValueError("Domain not found")

    config = get_assistance_config(db)
    summary = store.get_domain_summary(domain)
    total = int(summary.get("total_count", 0) or 0)
    passed = int(summary.get("passed_count", 0) or 0)
    failed = int(summary.get("failed_count", max(0, total - passed)) or 0)
    compliance = float(summary.get("compliance_rate", 0.0) or 0.0)
    reports_processed = int(summary.get("reports_processed", 0) or 0)
    sources = store.get_domain_sources(domain, days=30)[:5]
    reports = store.get_domain_reports(domain, limit=5)

    context = {
        "domain": domain,
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "config": config.to_dict(),
        "summary": {
            "total_messages": total,
            "passed_messages": passed,
            "failed_messages": failed,
            "compliance_rate": compliance,
            "reports_processed": reports_processed,
            "policy": summary.get("policy", "unknown"),
        },
        "top_sources": [
            {
                "source_ip": source.get("source_ip", "unknown"),
                "count": int(source.get("count", 0) or 0),
                "spf": source.get("spf_result", "unknown"),
                "dkim": source.get("dkim_result", "unknown"),
                "dmarc": source.get("dmarc_result", "unknown"),
                "disposition": source.get("disposition", "none"),
            }
            for source in sources
        ],
        "recent_reports": [
            {
                "report_id": report.get("report_id", "unknown"),
                "org_name": report.get("org_name", "Unknown Organization"),
                "total_messages": int(report.get("summary", {}).get("total_count", 0) or 0),
                "pass_rate": report.get("pass_rate", 0.0),
            }
            for report in reports
        ],
        "evidence": [
            _evidence("Domain summary", domain, f"/domain/{domain}"),
            _evidence("Total messages", total, f"/domain/{domain}#compliance-chart"),
            _evidence("Compliance rate", f"{compliance}%", f"/domain/{domain}#compliance-chart"),
            _evidence("Failed messages", failed, f"/domain/{domain}#sending-sources"),
        ],
        "redaction": {
            "mode": config.redaction_mode,
            "applied": True,
            "rules": [
                "secret-like key/value fragments",
                "bearer tokens",
                "long opaque tokens",
                "email local-parts in strict mode",
            ],
        },
    }
    return redact_safe_value(context, mode=config.redaction_mode)


def _headline_for_context(context: Dict[str, Any]) -> str:
    summary = context["summary"]
    total = int(summary["total_messages"])
    failed = int(summary["failed_messages"])
    compliance = float(summary["compliance_rate"])
    if total == 0:
        return "No DMARC aggregate volume has been observed yet."
    if failed == 0 and compliance >= 99:
        return "Observed DMARC traffic is passing cleanly."
    if compliance >= 90:
        return "DMARC posture is mostly healthy, with a small failure set to review."
    return "DMARC posture needs remediation before policy enforcement."


def build_evidence_summary(
    db: Session,
    domain: str,
    *,
    workspace_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Return an evidence-first operator summary and remediation plan."""
    context = build_safe_context(db, domain, workspace_id=workspace_id)
    summary = context["summary"]
    failed = int(summary["failed_messages"])
    total = int(summary["total_messages"])
    compliance = float(summary["compliance_rate"])
    recommendations: List[Dict[str, Any]] = []

    if total == 0:
        recommendations.append(
            {
                "priority": "medium",
                "title": "Confirm report ingestion",
                "detail": "No aggregate reports are available for this domain.",
                "action": "Check mailbox sources and senders for rua delivery.",
                "evidence": [context["evidence"][0]],
            }
        )
    elif failed > 0:
        recommendations.append(
            {
                "priority": "high" if compliance < 90 else "medium",
                "title": "Review failing sending sources",
                "detail": f"{failed} of {total} observed messages failed DMARC alignment.",
                "action": (
                    "Open the sending-source evidence and confirm whether each failing "
                    "source is legitimate."
                ),
                "evidence": [context["evidence"][2], context["evidence"][3]],
            }
        )

    unknown_or_failing_sources = [
        source
        for source in context["top_sources"]
        if source.get("dmarc") in {"fail", "mixed", "unknown", "none"}
    ]
    if unknown_or_failing_sources:
        recommendations.append(
            {
                "priority": "medium",
                "title": "Triage top unauthenticated sources",
                "detail": "At least one high-volume source is not consistently passing DMARC.",
                "action": "Verify ownership before adding SPF mechanisms or enabling DKIM signing.",
                "evidence": [
                    _evidence(
                        "Top source",
                        f"{source['source_ip']} ({source['count']} messages)",
                        f"/domain/{context['domain']}#sending-sources",
                    )
                    for source in unknown_or_failing_sources[:3]
                ],
            }
        )

    return {
        "enabled": get_assistance_config(db).ai_enabled,
        "provider": context["config"],
        "summary": {
            "domain": context["domain"],
            "headline": _headline_for_context(context),
            "total_messages": total,
            "failed_messages": failed,
            "compliance_rate": compliance,
        },
        "recommendations": recommendations,
        "safe_context": context,
    }


def _proposal_id(payload: Dict[str, Any]) -> str:
    serialized = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]


def build_action_proposals(
    db: Session,
    domain: str,
    *,
    workspace_id: Optional[int] = None,
) -> Dict[str, Any]:
    """Generate reviewable, reproducible action proposals without mutating state."""
    summary = build_evidence_summary(db, domain, workspace_id=workspace_id)
    proposals = []
    for index, recommendation in enumerate(summary["recommendations"], start=1):
        payload = {
            "domain": domain,
            "index": index,
            "title": recommendation["title"],
            "action": recommendation["action"],
            "evidence": recommendation.get("evidence", []),
        }
        proposal_id = _proposal_id(payload)
        proposals.append(
            {
                "proposal_id": proposal_id,
                "domain": domain,
                "status": "proposed",
                "title": recommendation["title"],
                "rationale": recommendation["detail"],
                "proposed_action": recommendation["action"],
                "requires_human_confirmation": True,
                "confirmation_text": proposal_id,
                "mutates_state": False,
                "evidence": recommendation.get("evidence", []),
            }
        )
    return {
        "domain": domain,
        "action_tools_enabled": get_assistance_config(db).action_tools_enabled,
        "proposals": proposals,
    }
