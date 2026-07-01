"""Build prioritized, human-reviewed remediation queues for domains."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Set

DNS_AUTOMATION_OPERATIONS = {"create", "update"}
DNS_AUTOMATION_RECORD_TYPES = {"TXT", "CNAME"}
SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}
DNS_SEVERITY = {"error": "critical", "warning": "medium", "info": "low"}
HEALTH_DNS_EQUIVALENTS = {
    "missing_dmarc": {"dmarc_missing"},
    "missing_spf": {"spf_missing"},
    "missing_dkim": {"dkim_selector_missing", "dkim_selector_broken"},
    "dmarc_lint": {
        "dmarc_external_rua_unauthorized",
        "dmarc_external_ruf_unauthorized",
        "dmarc_policy_value_invalid",
        "dmarc_alignment_value_invalid",
        "dmarc_failure_option_invalid",
        "dmarc_policy_or_reporting_missing",
        "dmarc_lint_warning",
    },
}


def _evidence_from_pairs(evidence: Iterable[Dict[str, Any]]) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    for item in evidence:
        label = str(item.get("label") or item.get("name") or "evidence")
        value = str(item.get("value") or item.get("detail") or "")
        if value:
            rows.append({"label": label, "value": value})
    return rows


def _evidence_from_values(values: Iterable[Any], *, label: str) -> List[Dict[str, str]]:
    return [{"label": label, "value": str(value)} for value in values if str(value)]


def _automation_eligible(plan: Dict[str, Any], available_write_providers: List[str]) -> bool:
    proposed_value = str(plan.get("proposed_value") or "")
    return (
        bool(available_write_providers)
        and plan.get("operation") in DNS_AUTOMATION_OPERATIONS
        and plan.get("record_type") in DNS_AUTOMATION_RECORD_TYPES
        and bool(proposed_value)
        and "<" not in proposed_value
        and not plan.get("provider_value_required")
    )


def _queue_status(items: List[Dict[str, Any]]) -> str:
    if any(item["state"] == "approval_ready" for item in items):
        return "needs_approval"
    if any(item["state"] == "manual_action" for item in items):
        return "needs_manual_action"
    if any(item["state"] == "investigate" for item in items):
        return "needs_investigation"
    return "healthy"


def _summary(items: List[Dict[str, Any]]) -> Dict[str, int]:
    return {
        "total": len(items),
        "approval_ready": sum(1 for item in items if item["state"] == "approval_ready"),
        "manual_action": sum(1 for item in items if item["state"] == "manual_action"),
        "investigate": sum(1 for item in items if item["state"] == "investigate"),
        "informational": sum(1 for item in items if item["state"] == "informational"),
        "notify_approval_required": sum(
            1 for item in items if item.get("notification", {}).get("state") == "approval_required"
        ),
        "notify_action_required": sum(
            1 for item in items if item.get("notification", {}).get("state") == "action_required"
        ),
        "notify_investigation_required": sum(
            1
            for item in items
            if item.get("notification", {}).get("state") == "investigation_required"
        ),
        "notify_summary_only": sum(
            1 for item in items if item.get("notification", {}).get("state") == "summary_only"
        ),
    }


def _notification_profile(domain: str, item: Dict[str, Any]) -> Dict[str, Any]:
    """Return read-only notification routing metadata for a remediation item."""
    state = str(item.get("state") or "")
    severity = str(item.get("severity") or "info")
    source = str(item.get("source") or "remediation")
    item_id = str(item.get("id") or "unknown")
    dedupe_key = f"dmarq:remediation:{domain}:{item_id}"

    if state == "approval_ready":
        return {
            "state": "approval_required",
            "event": "dmarq.remediation.approval_required",
            "channel": "email_security",
            "dedupe_key": dedupe_key,
            "reason": "Notify an operator that a safe DNS repair is ready for preview.",
            "next_transition": "verified_after_apply",
        }
    if state == "manual_action" and SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK["high"]:
        return {
            "state": "action_required",
            "event": "dmarq.remediation.manual_action_required",
            "channel": "email_security",
            "dedupe_key": dedupe_key,
            "reason": "Escalate high-impact manual remediation work.",
            "next_transition": "resolved_by_operator",
        }
    if state == "investigate":
        return {
            "state": "investigation_required",
            "event": "dmarq.remediation.investigation_required",
            "channel": "email_security",
            "dedupe_key": dedupe_key,
            "reason": "Ask an operator to confirm whether the sender or finding is legitimate.",
            "next_transition": "manual_action_or_resolved",
        }
    return {
        "state": "summary_only",
        "event": "dmarq.remediation.summary",
        "channel": "daily_summary" if source == "dns_lint" else "email_security",
        "dedupe_key": dedupe_key,
        "reason": "Include this lower-risk remediation item in summary reporting.",
        "next_transition": "resolved_or_escalated",
    }


def _remediation_notification_payload(domain: str, item: Dict[str, Any]) -> Dict[str, Any]:
    """Return the sanitized event payload that would be sent for a queue item."""
    notification = item.get("notification") or {}
    automation = item.get("automation") or {}
    return {
        "schema_version": "dmarq.remediation.notification.v1",
        "domain": domain,
        "item_id": str(item.get("id") or ""),
        "source": str(item.get("source") or "remediation"),
        "state": str(item.get("state") or ""),
        "severity": str(item.get("severity") or "info"),
        "confidence": str(item.get("confidence") or "medium"),
        "title": str(item.get("title") or ""),
        "detail": str(item.get("detail") or ""),
        "notification_state": str(notification.get("state") or "summary_only"),
        "event_type": str(notification.get("event") or "dmarq.remediation.summary"),
        "channel": str(notification.get("channel") or "email_security"),
        "dedupe_key": str(notification.get("dedupe_key") or ""),
        "reason": str(notification.get("reason") or ""),
        "next_transition": str(notification.get("next_transition") or ""),
        "automation": {
            "eligible": bool(automation.get("eligible")),
            "requires_approval": bool(automation.get("requires_approval", True)),
            "provider": automation.get("provider"),
            "plan_id": automation.get("plan_id"),
            "apply_endpoint": automation.get("apply_endpoint"),
        },
        "evidence": [
            {"label": str(row.get("label") or "evidence"), "value": str(row.get("value") or "")}
            for row in item.get("evidence", [])[:5]
            if str(row.get("value") or "")
        ],
    }


def _attach_notification_profiles(domain: str, items: List[Dict[str, Any]]) -> None:
    for item in items:
        item["notification"] = _notification_profile(domain, item)
        item["notification"]["payload_preview"] = _remediation_notification_payload(domain, item)


def _dns_item(
    *,
    domain: str,
    plan: Dict[str, Any],
    finding: Optional[Dict[str, Any]],
    available_write_providers: List[str],
    recommended_provider: Optional[str],
) -> Dict[str, Any]:
    automation_ready = bool(recommended_provider) and _automation_eligible(
        plan,
        available_write_providers,
    )
    severity = DNS_SEVERITY.get(str(plan.get("severity") or "info"), "low")
    steps = list(plan.get("manual_steps") or [])
    evidence = _evidence_from_values(plan.get("current_values") or [], label="current_value")
    if finding:
        evidence.extend(_evidence_from_values(finding.get("evidence") or [], label="finding"))
    prerequisites = [
        "Review the exact DNS diff in DMARQ.",
        "Confirm the record belongs to this sending domain.",
    ]
    if automation_ready:
        prerequisites.append("Preview the provider mutation before approving the write.")
    else:
        prerequisites.append("Use the manual DNS-provider steps; provider write is not ready.")
    if recommended_provider:
        prerequisites.append(f"Use the detected provider path for {recommended_provider}.")

    return {
        "id": f"dns:{plan.get('plan_id') or plan.get('finding_code')}",
        "source": "dns_lint",
        "state": "approval_ready" if automation_ready else "manual_action",
        "severity": severity,
        "confidence": "high" if finding else "medium",
        "title": finding.get("title") if finding else f"Review {plan.get('finding_code')}",
        "detail": finding.get("detail") if finding else str(plan.get("rationale") or ""),
        "next_steps": steps or [str(plan.get("rationale") or "Review the DNS finding.")],
        "evidence": evidence,
        "blast_radius": f"DNS record {plan.get('name')} ({plan.get('record_type')})",
        "prerequisites": prerequisites,
        "expected_health_score_impact": str(plan.get("expected_health_impact") or ""),
        "automation": {
            "eligible": automation_ready,
            "requires_approval": True,
            "provider": recommended_provider,
            "plan_id": plan.get("plan_id"),
            "apply_endpoint": (
                f"/api/v1/domains/{domain}/dns/change-plan/apply" if automation_ready else None
            ),
            "reason": (
                "Safe provider-backed DNS preview is available."
                if automation_ready
                else "Manual review is required before provider automation is safe."
            ),
        },
    }


def _health_item(domain: str, action: Dict[str, Any]) -> Dict[str, Any]:
    state = "investigate" if action.get("type") == "low_compliance" else "manual_action"
    return {
        "id": f"health:{action.get('type')}",
        "source": "health_score",
        "state": state,
        "severity": str(action.get("severity") or "medium"),
        "confidence": "medium",
        "title": str(action.get("title") or "Review domain health"),
        "detail": str(action.get("detail") or ""),
        "next_steps": [str(action.get("next_step") or "Review the domain evidence.")],
        "evidence": _evidence_from_pairs(action.get("evidence") or []),
        "blast_radius": f"Observed DMARC traffic for {domain}",
        "prerequisites": [
            "Confirm the sender or DNS owner before making changes.",
            "Use report evidence to avoid trusting unknown senders by mistake.",
        ],
        "expected_health_score_impact": str(action.get("score_impact") or 0),
        "automation": {
            "eligible": False,
            "requires_approval": True,
            "provider": None,
            "plan_id": None,
            "apply_endpoint": None,
            "reason": "This item needs investigation before a provider change is safe.",
        },
    }


def build_remediation_queue(
    *,
    domain: str,
    health: Dict[str, Any],
    dns_guidance: Dict[str, Any],
    available_write_providers: Optional[List[str]] = None,
    recommended_provider: Optional[str] = None,
) -> Dict[str, Any]:
    """Group health and DNS findings into a prioritized remediation queue."""
    providers = list(available_write_providers or [])
    findings = {str(finding.get("code")): finding for finding in dns_guidance.get("findings") or []}
    plans = list(dns_guidance.get("change_plans") or [])
    planned_findings: Set[str] = {str(plan.get("finding_code")) for plan in plans}
    items = [
        _dns_item(
            domain=domain,
            plan=plan,
            finding=findings.get(str(plan.get("finding_code"))),
            available_write_providers=providers,
            recommended_provider=recommended_provider,
        )
        for plan in plans
    ]

    for action in health.get("actions") or []:
        action_type = str(action.get("type") or "")
        if HEALTH_DNS_EQUIVALENTS.get(action_type, set()) & planned_findings:
            continue
        items.append(_health_item(domain, action))

    _attach_notification_profiles(domain, items)
    items.sort(
        key=lambda item: (
            item["state"] != "approval_ready",
            -SEVERITY_RANK.get(item["severity"], 0),
            item["id"],
        )
    )
    return {
        "domain": domain,
        "status": _queue_status(items),
        "summary": _summary(items),
        "items": items,
    }
