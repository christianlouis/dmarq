"""Privacy-preserving AI and agent assistance helpers."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List

from sqlalchemy.orm import Session

from app.core.redaction import SENSITIVE_VALUE, redact_sensitive_text
from app.models.domain import Domain
from app.models.setting import Setting
from app.services.report_persistence import hydrate_report_store_from_db
from app.services.report_store import ReportStore

AI_DEFAULTS = {
    "ai.enabled": "false",
    "ai.provider": "template",
    "ai.model": "",
    "ai.remote_base_url": "",
    "ai.redaction_mode": "strict",
    "ai.action_tools_enabled": "false",
    "mcp.enabled": "false",
}

EMAIL_PATTERN = re.compile(r"\b[A-Z0-9._%+-]+@([A-Z0-9.-]+\.[A-Z]{2,})\b", re.IGNORECASE)
LONG_TOKEN_PATTERN = re.compile(r"\b[A-Za-z0-9._~+/=-]{24,}\b")


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


def get_assistance_config(db: Session) -> AssistanceConfig:
    """Load AI/MCP settings with safe defaults."""
    provider = (_setting_value(db, "ai.provider") or "template").strip().lower()
    if provider not in {"template", "local", "remote"}:
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


def _domain_exists(db: Session, store: ReportStore, domain: str) -> bool:
    if domain in store.get_domains():
        return True
    return (
        db.query(Domain.id).filter(Domain.name == domain, Domain.active.is_(True)).first()
        is not None
    )


def _evidence(label: str, value: Any, href: str) -> Dict[str, str]:
    return {
        "label": label,
        "value": str(value),
        "href": href,
    }


def build_safe_context(db: Session, domain: str) -> Dict[str, Any]:
    """Build a redacted, evidence-linked context bundle for one domain."""
    store = ReportStore.get_instance()
    hydrate_report_store_from_db(db, store)
    if not _domain_exists(db, store, domain):
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


def build_evidence_summary(db: Session, domain: str) -> Dict[str, Any]:
    """Return an evidence-first operator summary and remediation plan."""
    context = build_safe_context(db, domain)
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


def build_action_proposals(db: Session, domain: str) -> Dict[str, Any]:
    """Generate reviewable, reproducible action proposals without mutating state."""
    summary = build_evidence_summary(db, domain)
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
