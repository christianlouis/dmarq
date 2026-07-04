"""Build prioritized, human-reviewed remediation queues for domains."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Set

from app.services.webhook_events import (
    EVENT_REMEDIATION_APPROVAL_REQUIRED,
    EVENT_REMEDIATION_INVESTIGATION_REQUIRED,
    EVENT_REMEDIATION_MANUAL_ACTION_REQUIRED,
    EVENT_REMEDIATION_SUMMARY,
)

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
            "event": EVENT_REMEDIATION_APPROVAL_REQUIRED,
            "channel": "email_security",
            "dedupe_key": dedupe_key,
            "reason": "Notify an operator that a safe DNS repair is ready for preview.",
            "next_transition": "verified_after_apply",
        }
    if state == "manual_action" and SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK["high"]:
        return {
            "state": "action_required",
            "event": EVENT_REMEDIATION_MANUAL_ACTION_REQUIRED,
            "channel": "email_security",
            "dedupe_key": dedupe_key,
            "reason": "Escalate high-impact manual remediation work.",
            "next_transition": "resolved_by_operator",
        }
    if state == "investigate":
        return {
            "state": "investigation_required",
            "event": EVENT_REMEDIATION_INVESTIGATION_REQUIRED,
            "channel": "email_security",
            "dedupe_key": dedupe_key,
            "reason": "Ask an operator to confirm whether the sender or finding is legitimate.",
            "next_transition": "manual_action_or_resolved",
        }
    return {
        "state": "summary_only",
        "event": EVENT_REMEDIATION_SUMMARY,
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
        "event_type": str(notification.get("event") or EVENT_REMEDIATION_SUMMARY),
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
            for row in item.get("evidence", [])
            if str(row.get("value") or "")
        ][:5],
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

    next_steps = steps or [str(plan.get("rationale") or "Review the DNS finding.")]
    item = {
        "id": f"dns:{plan.get('plan_id') or plan.get('finding_code')}",
        "source": "dns_lint",
        "state": "approval_ready" if automation_ready else "manual_action",
        "severity": severity,
        "confidence": "high" if finding else "medium",
        "title": finding.get("title") if finding else f"Review {plan.get('finding_code')}",
        "detail": finding.get("detail") if finding else str(plan.get("rationale") or ""),
        "next_steps": next_steps,
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
    item["action_plan"] = _action_plan_for_item(item)
    return item


def _health_playbook(domain: str, action: Dict[str, Any]) -> Dict[str, Any]:
    """Return deterministic operator steps for common health-score findings."""
    action_type = str(action.get("type") or "")
    default_step = str(action.get("next_step") or "Review the domain evidence.")

    playbooks: Dict[str, Dict[str, Any]] = {
        "low_compliance": {
            "steps": [
                "Open the sending-source table and sort by failed messages and last sent date.",
                (
                    "For each active failing source, verify the IP, PTR hostname, ASN, and provider "
                    + "owner before changing DNS."
                ),
                (
                    "If SPF passes but DKIM fails, repair DKIM signing or the DKIM selector for "
                    + "that sender."
                ),
                (
                    "If DKIM passes but SPF fails, verify the envelope-from or return-path domain "
                    + "before adding SPF includes or IPs."
                ),
                (
                    "Do not authorize receiver, mailbox, or forwarding IPs just because a preserved "
                    + "DKIM signature passed."
                ),
                (
                    "Refresh reports after the next receiver report window and confirm the source "
                    + "now passes DMARC."
                ),
            ],
            "prerequisites": [
                "Use recent report rows first; old senders may no longer need remediation.",
                "Confirm whether each source is an authorized sender, a forwarder, or abuse.",
            ],
            "completion_criteria": (
                "The active failing sources are owned and passing DMARC, or are intentionally "
                + "blocked by policy."
            ),
        },
        "source_reputation_listed": {
            "steps": [
                "Open the affected sending sources and identify which IPs are listed.",
                "Confirm whether each listed IP is still used by this domain and who owns it.",
                "Pause DMARC policy tightening until the owner confirms the reputation finding.",
                (
                    "Follow the named blacklist or provider delisting process with evidence from "
                    + "the current mail server or provider account."
                ),
                (
                    "After delisting, send a small authenticated test and wait for fresh DMARC "
                    + "reports before marking the issue resolved."
                ),
            ],
            "prerequisites": [
                "Use listing evidence from the configured reputation feed, not only local volume.",
                "Do not delist or authorize sources that are not part of the mail estate.",
            ],
            "completion_criteria": (
                "The listed source is either removed from sending, delisted by the provider, "
                + "or documented as intentionally blocked."
            ),
        },
        "source_reputation_review": {
            "steps": [
                (
                    "Open the source details and review PTR, ASN, country, provider, and latest "
                    + "send date."
                ),
                (
                    "Confirm whether the source belongs to a configured mail provider or owned "
                    + "infrastructure."
                ),
                "If the source is legitimate, repair SPF/DKIM alignment before trusting it.",
                (
                    "If the source is unknown or stale, keep it blocked and monitor whether it "
                    + "reappears in fresh reports."
                ),
            ],
            "prerequisites": [
                "Use current source intelligence and report timestamps before making a change.",
                "Require a human owner for every source that will be authorized.",
            ],
            "completion_criteria": (
                "The suspicious source is assigned to an owner and fixed, or treated as "
                + "unauthorized traffic."
            ),
        },
        "policy_none": {
            "steps": [
                "Confirm that all recent legitimate senders pass DMARC consistently.",
                "Move the domain from p=none to p=quarantine with an appropriate pct value.",
                "Monitor fresh reports for unexpected legitimate failures.",
                "Move to p=reject only after failures are understood and accepted.",
            ],
            "prerequisites": [
                "Do not tighten policy while active legitimate senders are failing.",
                "Make sure rua reporting remains configured before and after policy changes.",
            ],
            "completion_criteria": "The domain enforces quarantine or reject without new failures.",
        },
    }

    if action_type in playbooks:
        return playbooks[action_type]
    if action_type == "missing_dkim":
        return {
            "steps": [
                "Identify the sender or provider for each missing selector from report evidence.",
                "Fetch the exact DKIM TXT or CNAME value from that provider or mail server.",
                "Publish the selector in authoritative DNS and refresh DMARQ DNS evidence.",
                "Confirm fresh reports show DKIM pass for that sender before tightening DMARC.",
            ],
            "prerequisites": [
                "Provider-specific DKIM targets must come from the mail provider or MTA.",
                "Do not publish placeholder DKIM values.",
            ],
            "completion_criteria": "Observed legitimate senders have healthy DKIM selectors.",
        }
    return {
        "steps": [default_step],
        "prerequisites": [
            "Confirm the sender or DNS owner before making changes.",
            "Use report evidence to avoid trusting unknown senders by mistake.",
        ],
        "completion_criteria": (
            "The underlying domain health action no longer appears in the remediation queue."
        ),
    }


def _health_item(domain: str, action: Dict[str, Any]) -> Dict[str, Any]:
    state = "investigate" if action.get("type") == "low_compliance" else "manual_action"
    playbook = _health_playbook(domain, action)
    item = {
        "id": f"health:{action.get('type')}",
        "source": "health_score",
        "state": state,
        "severity": str(action.get("severity") or "medium"),
        "confidence": "medium",
        "title": str(action.get("title") or "Review domain health"),
        "detail": str(action.get("detail") or ""),
        "next_steps": playbook["steps"],
        "evidence": _evidence_from_pairs(action.get("evidence") or []),
        "blast_radius": f"Observed DMARC traffic for {domain}",
        "prerequisites": playbook["prerequisites"],
        "completion_criteria": playbook["completion_criteria"],
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
    item["action_plan"] = _action_plan_for_item(item)
    return item


def _action_plan_for_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """Return a compact operator action plan for one remediation queue item."""
    automation = item.get("automation") or {}
    source = str(item.get("source") or "remediation")
    state = str(item.get("state") or "")
    steps = [str(step) for step in item.get("next_steps") or [] if str(step).strip()]
    prerequisites = [str(step) for step in item.get("prerequisites") or [] if str(step).strip()]

    if automation.get("eligible"):
        owner = "Domain DNS operator"
        completion = "Provider preview is approved, applied, and verified by DMARQ."
        steps = [
            "Open the DNS change plan and preview the provider mutation.",
            "Confirm the zone, record name, old value, new value, and TTL.",
            "Approve the change, then refresh DNS posture after propagation.",
        ]
    elif state == "investigate":
        owner = "Mail operations owner"
        completion = str(
            item.get("completion_criteria")
            or "Sender legitimacy is confirmed and the item is resolved or converted into a DNS repair."
        )
        steps = steps or [
            "Review the report evidence and sending-source history.",
            "Confirm whether the sender is legitimate for this domain.",
            "Authorize the sender with SPF/DKIM only after ownership is clear.",
        ]
    elif source == "dns_lint":
        owner = "Domain DNS operator"
        completion = "The DNS lint finding is no longer present after refresh."
        steps = steps or [
            "Open the DNS guidance section.",
            "Apply the listed record change in the authoritative DNS provider.",
            "Refresh DMARQ DNS checks after propagation.",
        ]
    else:
        owner = "Mail operations owner"
        completion = str(
            item.get("completion_criteria")
            or "The underlying domain health action no longer appears in the remediation queue."
        )
        steps = steps or ["Review the evidence and complete the recommended operator action."]

    automation_path = (
        "provider_preview"
        if automation.get("eligible")
        else ("investigate" if state == "investigate" else "manual")
    )

    return {
        "owner": owner,
        "diagnosis": str(item.get("detail") or item.get("title") or "Review this finding."),
        "prerequisites": prerequisites[:5],
        "steps": steps[:6],
        "completion_criteria": completion,
        "automation_path": automation_path,
        "guidance_paths": _guidance_paths_for_item(
            item,
            owner=owner,
            automation_path=automation_path,
        ),
    }


def _guidance_paths_for_item(
    item: Dict[str, Any],
    *,
    owner: str,
    automation_path: str,
) -> List[Dict[str, str]]:
    """Return operator guidance paths for one remediation item."""
    automation = item.get("automation") or {}
    provider = str(automation.get("provider") or "detected provider")
    source = str(item.get("source") or "remediation")
    state = str(item.get("state") or "")

    if automation_path == "provider_preview":
        return [
            {
                "key": "provider",
                "label": f"{provider} guided repair",
                "summary": "Use the connected DNS provider preview and approve the exact record mutation.",
                "owner": owner,
            },
            {
                "key": "manual",
                "label": "Manual DNS fallback",
                "summary": "Copy the proposed record into the authoritative DNS provider if provider automation is not desired.",
                "owner": "Domain DNS operator",
            },
        ]
    if source == "dns_lint":
        return [
            {
                "key": "provider",
                "label": "DNS provider console",
                "summary": "Open the authoritative DNS zone and apply the record value from the remediation plan.",
                "owner": "Domain DNS operator",
            },
            {
                "key": "self_hosted",
                "label": "Self-hosted DNS",
                "summary": "Update the zone file or DNS management system, reload the service, then refresh DMARQ evidence.",
                "owner": "DNS platform operator",
            },
        ]
    if state == "investigate":
        return [
            {
                "key": "provider",
                "label": "Mail provider investigation",
                "summary": "Check sender signatures, bounce domains, and provider authentication status before changing DNS.",
                "owner": "Mail operations owner",
            },
            {
                "key": "self_hosted",
                "label": "Self-hosted mail investigation",
                "summary": "Review MTA logs, DKIM signing configuration, SPF envelope sender alignment, and recent sending hosts.",
                "owner": "Mail server operator",
            },
        ]
    return [
        {
            "key": "provider",
            "label": "Provider-guided remediation",
            "summary": "Use the provider dashboard to confirm required DNS or sender settings before applying changes.",
            "owner": owner,
        },
        {
            "key": "self_hosted",
            "label": "Self-hosted remediation",
            "summary": "Apply the equivalent mail or DNS configuration directly in the local infrastructure.",
            "owner": owner,
        },
    ]


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
