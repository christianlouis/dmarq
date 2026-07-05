"""Build prioritized, human-reviewed remediation queues for domains."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Set

from app.services.remediation_evidence import evidence_refresh_for_remediation_item
from app.services.remediation_readiness import (
    OPERATOR_REVIEW_READINESS_LEVELS,
    repair_readiness_for_stage,
)
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
STATE_PRIORITY = {
    "approval_ready": 40,
    "manual_action": 30,
    "investigate": 20,
    "informational": 10,
}
TRACKS = (
    "provider_preview",
    "manual_dns",
    "sender_investigation",
    "reputation_review",
    "self_hosted_or_provider",
    "blocked_by_prerequisite",
    "manual_only",
)
INCIDENT_TYPES = {
    "low_compliance": "legitimate_sender_failing_alignment",
    "missing_dmarc": "dmarc_policy_missing_or_weak",
    "policy_none": "dmarc_policy_missing_or_weak",
    "missing_spf": "spf_include_or_record_problem",
    "missing_dkim": "missing_or_broken_dkim",
    "source_reputation_listed": "sending_ip_reputation_risk",
    "source_reputation_review": "sending_ip_reputation_risk",
    "review_forwarding": "forwarding_or_receiver_alignment_review",
}
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
    summary = {
        "total": len(items),
        "approval_ready": sum(1 for item in items if item["state"] == "approval_ready"),
        "manual_action": sum(1 for item in items if item["state"] == "manual_action"),
        "investigate": sum(1 for item in items if item["state"] == "investigate"),
        "informational": sum(1 for item in items if item["state"] == "informational"),
        "provider_fix_available": sum(
            1 for item in items if item.get("automation", {}).get("eligible")
        ),
        "self_hosted_guidance": sum(
            1
            for item in items
            if any(
                path.get("key") == "self_hosted"
                for path in item.get("action_plan", {}).get("guidance_paths", [])
            )
        ),
        "manual_only": sum(1 for item in items if item.get("remediation_track") == "manual_only"),
        "blocked_by_prerequisite": sum(
            1 for item in items if item.get("remediation_track") == "blocked_by_prerequisite"
        ),
        "repair_preview_ready": sum(
            1
            for item in items
            if (item.get("repair_progression") or {}).get("stage") == "preview_ready"
        ),
        "repair_approval_pending": sum(
            1
            for item in items
            if (item.get("repair_progression") or {}).get("stage") == "approval_pending"
        ),
        "repair_blocked": sum(
            1 for item in items if (item.get("repair_progression") or {}).get("stage") == "blocked"
        ),
        "repair_needs_evidence": sum(
            1
            for item in items
            if (item.get("repair_progression") or {}).get("verification_required")
        ),
        "repair_ready_for_preview": sum(
            1
            for item in items
            if (item.get("repair_progression") or {}).get("readiness_level") == "ready_for_preview"
        ),
        "repair_waiting_on_operator": sum(
            1
            for item in items
            if (item.get("repair_progression") or {}).get("readiness_level")
            in OPERATOR_REVIEW_READINESS_LEVELS
        ),
        "repair_readiness_blocked": sum(
            1
            for item in items
            if (item.get("repair_progression") or {}).get("readiness_level") == "blocked"
        ),
        "repair_readiness_score": max(
            [
                int((item.get("repair_progression") or {}).get("readiness_score") or 0)
                for item in items
            ]
            or [0]
        ),
        "provider_preview_available": sum(
            1
            for item in items
            if (item.get("provider_repair_plan") or {}).get("safe_preview_available")
        ),
        "provider_apply_after_approval": sum(
            1
            for item in items
            if (item.get("provider_repair_plan") or {}).get("can_apply_after_approval")
        ),
        "provider_apply_blocked": sum(
            1
            for item in items
            if (item.get("provider_repair_plan") or {}).get("kind") == "dns_provider_repair"
            and (item.get("provider_repair_plan") or {}).get("apply_blocked")
        ),
        "provider_value_missing": sum(
            1
            for item in items
            if "provider_specific_value" in (item.get("provider_repair_plan") or {}).get(
                "blocked_reasons", []
            )
        ),
        "provider_manual_fallback": sum(
            1
            for item in items
            if (item.get("provider_repair_plan") or {}).get("kind") == "dns_provider_repair"
            and (item.get("provider_repair_plan") or {}).get("manual_fallback")
        ),
        "provider_pre_apply_checks": sum(
            1
            for item in items
            if (item.get("provider_repair_plan") or {}).get("pre_apply_checks")
        ),
        "provider_post_apply_checks": sum(
            1
            for item in items
            if (item.get("provider_repair_plan") or {}).get("post_apply_checks")
        ),
        "requires_fresh_evidence": sum(
            1 for item in items if (item.get("action_plan") or {}).get("requires_fresh_evidence")
        ),
        "rollback_guidance": sum(
            1 for item in items if (item.get("action_plan") or {}).get("rollback_plan")
        ),
        "closure_gate_required": sum(
            1 for item in items if (item.get("verification_plan") or {}).get("closure_gate")
        ),
        "stale_evidence_warning": sum(
            1
            for item in items
            if (item.get("verification_plan") or {}).get("stale_evidence_warning")
        ),
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
        "evidence_refresh_required": sum(
            1 for item in items if (item.get("evidence_refresh") or {}).get("required")
        ),
        "evidence_refresh_dns": sum(
            1 for item in items if (item.get("evidence_refresh") or {}).get("refresh_key") == "dns"
        ),
        "evidence_refresh_reports": sum(
            1
            for item in items
            if (item.get("evidence_refresh") or {}).get("refresh_key")
            in {"reports", "reports_and_sources"}
        ),
        "evidence_refresh_reputation": sum(
            1
            for item in items
            if (item.get("evidence_refresh") or {}).get("refresh_key") == "source_reputation"
        ),
        "evidence_refresh_prerequisite": sum(
            1
            for item in items
            if (item.get("evidence_refresh") or {}).get("refresh_key") == "provider_value"
        ),
    }
    for track in TRACKS:
        summary[f"track_{track}"] = sum(
            1 for item in items if item.get("remediation_track") == track
        )
    return summary


def _incident_type_for_item(item: Dict[str, Any]) -> str:
    """Classify remediation work into stable product incident families."""
    source = str(item.get("source") or "")
    item_id = str(item.get("id") or "")
    if source == "dns_lint" or item_id.startswith("dns:"):
        if "dkim" in item_id:
            return "missing_or_broken_dkim"
        if "spf" in item_id:
            return "spf_include_or_record_problem"
        if "dmarc" in item_id:
            return "dmarc_policy_missing_or_weak"
        return "mail_provider_requires_dns_records"
    action_type = item_id.removeprefix("health:")
    return INCIDENT_TYPES.get(action_type, "domain_health_action")


def _loop_state_for_item(item: Dict[str, Any]) -> str:
    """Return the autonomous-loop state without implying unsupervised changes."""
    if item.get("automation", {}).get("eligible"):
        return "proposal_ready_for_approval"
    state = str(item.get("state") or "")
    if state == "investigate":
        return "evidence_review_required"
    if state == "manual_action":
        return "operator_action_required"
    return "observed"


def _remediation_track(item: Dict[str, Any]) -> str:
    """Summarize the safest next lane for this item."""
    if item.get("automation", {}).get("eligible"):
        return "provider_preview"
    if item.get("state") == "investigate":
        return "sender_investigation"
    if str(item.get("incident_type") or "") == "sending_ip_reputation_risk":
        return "reputation_review"
    if str(item.get("source") or "") == "dns_lint":
        if any(
            "provider-specific" in str(prerequisite).lower()
            for prerequisite in item.get("prerequisites", [])
        ):
            return "blocked_by_prerequisite"
        return "manual_dns"
    if any(
        path.get("key") == "self_hosted"
        for path in item.get("action_plan", {}).get("guidance_paths", [])
    ):
        return "self_hosted_or_provider"
    return "manual_only"


def _priority_score(item: Dict[str, Any]) -> int:
    """Return deterministic ordering and dashboard priority score."""
    severity = SEVERITY_RANK.get(str(item.get("severity") or "info"), 0) * 100
    state = STATE_PRIORITY.get(str(item.get("state") or ""), 0)
    automation = 15 if item.get("automation", {}).get("eligible") else 0
    try:
        impact = abs(int(float(str(item.get("expected_health_score_impact") or "0"))))
    except ValueError:
        impact = 0
    return severity + state + automation + min(impact, 50)


def _priority_band(item: Dict[str, Any], *, score: Optional[int] = None) -> str:
    if score is None:
        score = int(item.get("priority_score") or _priority_score(item))
    if score >= 400:
        return "urgent"
    if score >= 300:
        return "high"
    if score >= 200:
        return "normal"
    return "watch"


def _operator_decision_options(item: Dict[str, Any]) -> List[str]:
    """Return allowed human-in-the-loop actions for UI and integrations."""
    options = ["previewed", "acknowledged", "snoozed", "resolved", "rejected"]
    if item.get("automation", {}).get("eligible"):
        return ["preview_change", "approve_after_preview", *options]
    if item.get("state") == "investigate":
        return ["mark_legitimate", "mark_unknown", "convert_to_manual_action", *options]
    return options


def _operator_decision_summary(item: Dict[str, Any]) -> str:
    remediation_track = str(item.get("remediation_track") or _remediation_track(item))
    if item.get("automation", {}).get("eligible"):
        return "Preview the exact DNS diff, then explicitly approve or reject the proposed repair."
    if item.get("state") == "investigate":
        return "Classify the sender before authorizing DNS, suppressing alerts, or marking the item fixed."
    if remediation_track == "blocked_by_prerequisite":
        return (
            "Collect the missing provider-specific value before this can become a repair proposal."
        )
    return "Acknowledge the work, complete it manually, then mark it resolved only after fresh evidence confirms it."


def _repair_progression_with_readiness(
    progression: Dict[str, Any],
    *,
    verification_status: str,
) -> Dict[str, Any]:
    """Add operator-facing repair readiness without implying mutation."""
    stage = str(progression.get("stage") or "operator_review")
    reasons: List[str] = []
    blocked_by: List[str] = []
    readiness = repair_readiness_for_stage(stage)

    if stage == "preview_ready":
        reasons.extend(
            [
                "A connected DNS provider can produce an exact change preview.",
                "A human approval gate is still required before apply.",
            ]
        )
    elif stage == "blocked":
        blocked_by.append("provider_specific_value")
        reasons.append("The provider-specific target value is missing.")
    elif stage == "classification_required":
        blocked_by.append("sender_classification")
        reasons.append("The sender must be classified before DNS or policy changes are safe.")
    elif stage == "reputation_review":
        blocked_by.append("fresh_reputation_evidence")
        reasons.append("Fresh reputation or blacklist evidence is required before closure.")
    elif stage == "manual_repair":
        reasons.append("The item has operator guidance but no connected safe write path.")
    else:
        reasons.append("The item needs fresh evidence and operator context before closure.")

    if progression.get("verification_required"):
        blocked_by.append("fresh_evidence_before_closure")
        reasons.append("Fresh evidence is required before DMARQ can call this fixed.")

    if verification_status and verification_status != "verified":
        blocked_by.append(verification_status)

    return {
        **progression,
        **readiness,
        "readiness_reasons": reasons[:5],
        "blocked_by": list(dict.fromkeys(blocked_by))[:5],
        "next_safe_action": str(
            progression.get("next_step")
            or progression.get("summary")
            or "Review the remediation evidence before taking action."
        ),
    }


def _repair_progression_for_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """Return the safe repair lane and gates without performing any mutation."""
    automation = item.get("automation") or {}
    track = str(item.get("remediation_track") or _remediation_track(item))
    verification = item.get("verification_plan") or {}
    state = str(item.get("state") or "")

    if automation.get("eligible"):
        verification_status = str(verification.get("status") or "pending_operator_approval")
        return _repair_progression_with_readiness(
            {
                "stage": "preview_ready",
                "label": "Preview ready",
                "summary": "A connected DNS provider can prepare the exact mutation for review.",
                "next_gate": "Human approval before apply",
                "next_step": "Open the provider preview, compare old and new DNS values, then approve or reject.",
                "can_preview": True,
                "can_apply_after_approval": True,
                "manual_fallback": True,
                "verification_required": True,
                "verification_status": verification_status,
            },
            verification_status=verification_status,
        )
    if track == "blocked_by_prerequisite":
        verification_status = str(verification.get("status") or "pending_dns_refresh")
        return _repair_progression_with_readiness(
            {
                "stage": "blocked",
                "label": "Blocked by prerequisite",
                "summary": "DMARQ needs a provider-specific value before this can become a safe repair.",
                "next_gate": "Provider value required",
                "next_step": "Fetch the exact DKIM, SPF, DMARC, or CNAME target from the mail provider first.",
                "can_preview": False,
                "can_apply_after_approval": False,
                "manual_fallback": True,
                "verification_required": True,
                "verification_status": verification_status,
            },
            verification_status=verification_status,
        )
    if state == "investigate":
        verification_status = str(verification.get("status") or "pending_sender_review")
        return _repair_progression_with_readiness(
            {
                "stage": "classification_required",
                "label": "Classify sender",
                "summary": "A human must decide whether the source is legitimate, forwarding, abuse, or stale.",
                "next_gate": "Sender classification",
                "next_step": "Review source intelligence and recent report evidence before changing SPF or DKIM.",
                "can_preview": False,
                "can_apply_after_approval": False,
                "manual_fallback": False,
                "verification_required": True,
                "verification_status": verification_status,
            },
            verification_status=verification_status,
        )
    if track == "manual_dns":
        verification_status = str(verification.get("status") or "pending_dns_refresh")
        return _repair_progression_with_readiness(
            {
                "stage": "manual_repair",
                "label": "Manual DNS repair",
                "summary": "The finding has DNS guidance but no connected safe write path yet.",
                "next_gate": "Operator applies DNS manually",
                "next_step": "Apply the suggested record in authoritative DNS, then refresh DMARQ evidence.",
                "can_preview": False,
                "can_apply_after_approval": False,
                "manual_fallback": True,
                "verification_required": True,
                "verification_status": verification_status,
            },
            verification_status=verification_status,
        )
    if track == "reputation_review":
        verification_status = str(verification.get("status") or "pending_report_evidence")
        return _repair_progression_with_readiness(
            {
                "stage": "reputation_review",
                "label": "Review reputation",
                "summary": "The source needs reputation or blacklist evidence before operator closure.",
                "next_gate": "Fresh reputation evidence",
                "next_step": "Check current reputation feeds and decide whether to delist, stop, or accept the sender.",
                "can_preview": False,
                "can_apply_after_approval": False,
                "manual_fallback": False,
                "verification_required": True,
                "verification_status": verification_status,
            },
            verification_status=verification_status,
        )
    verification_status = str(verification.get("status") or "pending_report_evidence")
    return _repair_progression_with_readiness(
        {
            "stage": "operator_review",
            "label": "Operator review",
            "summary": "The remediation remains manual until current evidence proves it is fixed.",
            "next_gate": "Fresh evidence before closure",
            "next_step": "Complete the operator action and import fresh reports or DNS checks before marking fixed.",
            "can_preview": False,
            "can_apply_after_approval": False,
            "manual_fallback": True,
            "verification_required": True,
            "verification_status": verification_status,
        },
        verification_status=verification_status,
    )


def _provider_repair_plan_for_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """Return explicit read-only provider progression for DNS repair items."""
    automation = item.get("automation") or {}
    repair = item.get("repair_progression") or {}
    refresh = item.get("evidence_refresh") or {}
    provider = str(automation.get("provider") or "")
    plan_id = automation.get("plan_id")
    source = str(item.get("source") or "")
    stage = str(repair.get("stage") or "operator_review")
    blocked_reasons = list(repair.get("blocked_by") or [])
    verification = item.get("verification_plan") or {}
    blast_radius = str(item.get("blast_radius") or "")
    pre_apply_checks = [
        "Confirm the authoritative zone and record owner.",
        "Compare the current DNS value, proposed value, record type, and TTL.",
        "Confirm a human operator explicitly approved this repair.",
    ]
    post_apply_checks = [
        verification.get("closure_gate")
        or "Refresh DNS evidence after propagation and rebuild the remediation queue.",
        verification.get("next_check") or "Keep the item open until fresh evidence is available.",
    ]
    post_apply_checks = [str(check) for check in post_apply_checks if str(check)]

    if source != "dns_lint":
        return {
            "kind": "not_provider_repair",
            "provider": provider,
            "provider_label": provider or "No DNS provider repair",
            "plan_id": plan_id,
            "stage": "not_applicable",
            "safe_preview_available": False,
            "can_apply_after_approval": False,
            "apply_requires_approval": False,
            "apply_blocked": False,
            "blocked_reasons": [],
            "manual_fallback": bool(repair.get("manual_fallback")),
            "preview_endpoint": "",
            "apply_endpoint": "",
            "operation": "",
            "record_name": "",
            "record_type": "",
            "capability": "manual_review",
            "approval_gate": "No provider DNS apply gate for this item.",
            "pre_apply_checks": [],
            "post_apply_checks": post_apply_checks[:3],
            "blast_radius": blast_radius,
            "operator_warning": "Do not change DNS from this item without a matching DNS finding.",
            "next_step": repair.get("next_safe_action")
            or "Review sender, report, reputation, or policy evidence before DNS changes.",
            "completion_gate": verification.get("closure_gate") or "",
        }

    if not provider:
        blocked_reasons.append("no_connected_provider")
    if not automation.get("eligible"):
        blocked_reasons.append("provider_preview_not_available")
    if refresh.get("safe_to_run") is False or refresh.get("refresh_key") == "provider_value":
        blocked_reasons.append("provider_specific_value")

    safe_preview = bool(automation.get("eligible") and provider)
    can_apply = bool(safe_preview and repair.get("can_apply_after_approval"))
    blocked_reasons = list(dict.fromkeys(str(reason) for reason in blocked_reasons if reason))
    if can_apply:
        blocked_reasons = [
            reason
            for reason in blocked_reasons
            if reason
            not in {
                "fresh_evidence_before_closure",
                "pending_operator_approval",
            }
        ]
    apply_blocked = bool(not can_apply or blocked_reasons)

    return {
        "kind": "dns_provider_repair",
        "provider": provider,
        "provider_label": provider or "Manual DNS provider",
        "plan_id": plan_id,
        "stage": stage,
        "safe_preview_available": safe_preview,
        "can_apply_after_approval": can_apply,
        "apply_requires_approval": True,
        "apply_blocked": apply_blocked,
        "blocked_reasons": blocked_reasons[:6],
        "manual_fallback": bool(repair.get("manual_fallback", True)),
        "preview_endpoint": str(automation.get("apply_endpoint") or "") if safe_preview else "",
        "apply_endpoint": str(automation.get("apply_endpoint") or "") if can_apply else "",
        "operation": str(automation.get("operation") or ""),
        "record_name": str(automation.get("record_name") or ""),
        "record_type": str(automation.get("record_type") or ""),
        "capability": "provider_preview" if safe_preview else "manual_dns",
        "approval_gate": (
            "Provider apply is available only after explicit operator approval."
            if can_apply
            else "Provider apply is blocked; use manual fallback or resolve blockers first."
        ),
        "pre_apply_checks": pre_apply_checks[:5],
        "post_apply_checks": post_apply_checks[:5],
        "blast_radius": blast_radius,
        "operator_warning": (
            "Preview does not mean fixed; close only after fresh DNS evidence confirms the change."
        ),
        "next_step": str(
            repair.get("next_safe_action")
            or repair.get("next_step")
            or "Review the DNS record change and collect fresh evidence before closure."
        ),
        "completion_gate": verification.get("closure_gate") or "",
    }


def _evidence_refresh_for_item(domain: str, item: Dict[str, Any]) -> Dict[str, Any]:
    """Return the safe read-only refresh path before a remediation item is closed."""
    return evidence_refresh_for_remediation_item(domain, item)


def _apply_loop_metadata(domain: str, items: List[Dict[str, Any]]) -> None:
    for item in items:
        item["incident_type"] = _incident_type_for_item(item)
        item["loop_state"] = _loop_state_for_item(item)
        item["remediation_track"] = _remediation_track(item)
        priority_score = _priority_score(item)
        item["priority_score"] = priority_score
        item["priority_band"] = _priority_band(item, score=priority_score)
        item["operator_decisions"] = _operator_decision_options(item)
        item["repair_progression"] = _repair_progression_for_item(item)
        item["evidence_refresh"] = _evidence_refresh_for_item(domain, item)
        item["provider_repair_plan"] = _provider_repair_plan_for_item(item)


def _loop_summary(domain: str, items: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Return dashboard-ready remediation loop state for this domain."""
    summary = _summary(items)
    next_item = items[0] if items else None
    if not items:
        status = "clear"
        next_action = "No current remediation work; keep importing reports and monitoring DNS."
    elif summary["approval_ready"]:
        status = "approval_required"
        next_action = "Preview and approve the highest-priority provider-backed repair."
    elif summary["investigate"]:
        status = "investigation_required"
        next_action = (
            "Classify the highest-priority sender or reputation finding before changing DNS."
        )
    else:
        status = "manual_action_required"
        next_action = (
            "Complete the highest-priority manual provider or self-hosted remediation step."
        )
    return {
        "domain": domain,
        "status": status,
        "next_action": next_action,
        "what_dmarq_can_fix": summary["provider_fix_available"],
        "what_needs_approval": summary["approval_ready"],
        "what_needs_manual_action": summary["manual_action"],
        "what_needs_investigation": summary["investigate"],
        "manual_only": summary["manual_only"],
        "blocked_by_prerequisite": summary["blocked_by_prerequisite"],
        "track_provider_preview": summary["track_provider_preview"],
        "track_manual_dns": summary["track_manual_dns"],
        "track_sender_investigation": summary["track_sender_investigation"],
        "track_reputation_review": summary["track_reputation_review"],
        "track_self_hosted_or_provider": summary["track_self_hosted_or_provider"],
        "repair_preview_ready": summary["repair_preview_ready"],
        "repair_approval_pending": summary["repair_approval_pending"],
        "repair_blocked": summary["repair_blocked"],
        "repair_needs_evidence": summary["repair_needs_evidence"],
        "repair_ready_for_preview": summary["repair_ready_for_preview"],
        "repair_waiting_on_operator": summary["repair_waiting_on_operator"],
        "repair_readiness_blocked": summary["repair_readiness_blocked"],
        "repair_readiness_score": summary["repair_readiness_score"],
        "provider_preview_available": summary["provider_preview_available"],
        "provider_apply_after_approval": summary["provider_apply_after_approval"],
        "provider_apply_blocked": summary["provider_apply_blocked"],
        "provider_value_missing": summary["provider_value_missing"],
        "provider_manual_fallback": summary["provider_manual_fallback"],
        "provider_pre_apply_checks": summary["provider_pre_apply_checks"],
        "provider_post_apply_checks": summary["provider_post_apply_checks"],
        "requires_fresh_evidence": summary["requires_fresh_evidence"],
        "rollback_guidance": summary["rollback_guidance"],
        "closure_gate_required": summary["closure_gate_required"],
        "stale_evidence_warning": summary["stale_evidence_warning"],
        "evidence_refresh_required": summary["evidence_refresh_required"],
        "evidence_refresh_dns": summary["evidence_refresh_dns"],
        "evidence_refresh_reports": summary["evidence_refresh_reports"],
        "evidence_refresh_reputation": summary["evidence_refresh_reputation"],
        "evidence_refresh_prerequisite": summary["evidence_refresh_prerequisite"],
        "top_item_id": next_item.get("id") if next_item else None,
        "top_incident_type": next_item.get("incident_type") if next_item else None,
        "top_loop_state": next_item.get("loop_state") if next_item else None,
        "top_remediation_track": next_item.get("remediation_track") if next_item else None,
        "top_priority_band": next_item.get("priority_band") if next_item else None,
        "top_priority_score": next_item.get("priority_score") if next_item else 0,
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
    action_plan = item.get("action_plan") or {}
    verification_plan = item.get("verification_plan") or {}
    repair_progression = item.get("repair_progression") or {}
    evidence_refresh = item.get("evidence_refresh") or {}
    provider_repair_plan = item.get("provider_repair_plan") or {}
    return {
        "schema_version": "dmarq.remediation.notification.v1",
        "domain": domain,
        "item_id": str(item.get("id") or ""),
        "source": str(item.get("source") or "remediation"),
        "state": str(item.get("state") or ""),
        "severity": str(item.get("severity") or "info"),
        "confidence": str(item.get("confidence") or "medium"),
        "incident_type": str(item.get("incident_type") or ""),
        "loop_state": str(item.get("loop_state") or ""),
        "remediation_track": str(item.get("remediation_track") or ""),
        "priority_score": int(item.get("priority_score") or 0),
        "priority_band": str(item.get("priority_band") or "watch"),
        "operator_decisions": [
            str(decision) for decision in item.get("operator_decisions", []) if str(decision)
        ][:8],
        "repair_progression": {
            "stage": str(repair_progression.get("stage") or ""),
            "label": str(repair_progression.get("label") or ""),
            "summary": str(repair_progression.get("summary") or ""),
            "next_gate": str(repair_progression.get("next_gate") or ""),
            "next_step": str(repair_progression.get("next_step") or ""),
            "readiness_level": str(repair_progression.get("readiness_level") or ""),
            "readiness_label": str(repair_progression.get("readiness_label") or ""),
            "readiness_score": int(repair_progression.get("readiness_score") or 0),
            "readiness_reasons": [
                str(reason) for reason in repair_progression.get("readiness_reasons", [])
            ][:5],
            "blocked_by": [str(reason) for reason in repair_progression.get("blocked_by", [])][:5],
            "next_safe_action": str(repair_progression.get("next_safe_action") or ""),
            "can_preview": bool(repair_progression.get("can_preview")),
            "can_apply_after_approval": bool(repair_progression.get("can_apply_after_approval")),
            "manual_fallback": bool(repair_progression.get("manual_fallback")),
            "verification_required": bool(repair_progression.get("verification_required")),
            "verification_status": str(repair_progression.get("verification_status") or ""),
        },
        "provider_repair_plan": {
            "kind": str(provider_repair_plan.get("kind") or ""),
            "provider": str(provider_repair_plan.get("provider") or ""),
            "provider_label": str(provider_repair_plan.get("provider_label") or ""),
            "plan_id": provider_repair_plan.get("plan_id"),
            "stage": str(provider_repair_plan.get("stage") or ""),
            "safe_preview_available": bool(provider_repair_plan.get("safe_preview_available")),
            "can_apply_after_approval": bool(
                provider_repair_plan.get("can_apply_after_approval")
            ),
            "apply_requires_approval": bool(
                provider_repair_plan.get("apply_requires_approval", True)
            ),
            "apply_blocked": bool(provider_repair_plan.get("apply_blocked", True)),
            "blocked_reasons": [
                str(reason) for reason in provider_repair_plan.get("blocked_reasons", [])
            ][:6],
            "manual_fallback": bool(provider_repair_plan.get("manual_fallback")),
            "preview_endpoint": str(provider_repair_plan.get("preview_endpoint") or ""),
            "apply_endpoint": str(provider_repair_plan.get("apply_endpoint") or ""),
            "operation": str(provider_repair_plan.get("operation") or ""),
            "record_name": str(provider_repair_plan.get("record_name") or ""),
            "record_type": str(provider_repair_plan.get("record_type") or ""),
            "capability": str(provider_repair_plan.get("capability") or ""),
            "approval_gate": str(provider_repair_plan.get("approval_gate") or ""),
            "pre_apply_checks": [
                str(check) for check in provider_repair_plan.get("pre_apply_checks", [])
            ][:5],
            "post_apply_checks": [
                str(check) for check in provider_repair_plan.get("post_apply_checks", [])
            ][:5],
            "blast_radius": str(provider_repair_plan.get("blast_radius") or ""),
            "operator_warning": str(provider_repair_plan.get("operator_warning") or ""),
            "next_step": str(provider_repair_plan.get("next_step") or ""),
            "completion_gate": str(provider_repair_plan.get("completion_gate") or ""),
        },
        "evidence_refresh": {
            "required": bool(evidence_refresh.get("required")),
            "source": str(evidence_refresh.get("source") or ""),
            "refresh_key": str(evidence_refresh.get("refresh_key") or ""),
            "label": str(evidence_refresh.get("label") or ""),
            "safe_to_run": bool(evidence_refresh.get("safe_to_run")),
            "recommended_action": str(evidence_refresh.get("recommended_action") or ""),
            "completion_signal": str(evidence_refresh.get("completion_signal") or ""),
            "stale_warning": str(evidence_refresh.get("stale_warning") or ""),
            "next_check": str(evidence_refresh.get("next_check") or ""),
            "ui_anchor": str(evidence_refresh.get("ui_anchor") or ""),
            "endpoint_hint": str(evidence_refresh.get("endpoint_hint") or ""),
        },
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
            "operation": automation.get("operation"),
            "record_name": automation.get("record_name"),
            "record_type": automation.get("record_type"),
        },
        "action_plan": {
            "owner": str(action_plan.get("owner") or ""),
            "automation_path": str(action_plan.get("automation_path") or ""),
            "risk_level": str(action_plan.get("risk_level") or ""),
            "safe_to_automate": bool(action_plan.get("safe_to_automate")),
            "operator_decision_summary": str(action_plan.get("operator_decision_summary") or ""),
            "completion_criteria": str(action_plan.get("completion_criteria") or ""),
            "decision_checkpoints": [
                str(checkpoint)
                for checkpoint in action_plan.get("decision_checkpoints", [])
                if str(checkpoint).strip()
            ][:5],
            "rollback_plan": str(action_plan.get("rollback_plan") or ""),
            "requires_fresh_evidence": bool(action_plan.get("requires_fresh_evidence", True)),
            "steps": [str(step) for step in action_plan.get("steps", []) if str(step).strip()][:5],
            "guidance_paths": [
                {
                    "key": str(path.get("key") or ""),
                    "label": str(path.get("label") or ""),
                    "owner": str(path.get("owner") or ""),
                }
                for path in action_plan.get("guidance_paths", [])
                if str(path.get("key") or "")
            ][:3],
        },
        "verification": {
            "label": str(verification_plan.get("label") or ""),
            "status": str(verification_plan.get("status") or ""),
            "method": str(verification_plan.get("verification_method") or ""),
            "freshness_requirement": str(verification_plan.get("freshness_requirement") or ""),
            "failure_mode": str(verification_plan.get("failure_mode") or ""),
            "closure_gate": str(verification_plan.get("closure_gate") or ""),
            "stale_evidence_warning": str(verification_plan.get("stale_evidence_warning") or ""),
            "summary": str(verification_plan.get("summary") or ""),
            "next_check": str(verification_plan.get("next_check") or ""),
            "evidence_needed": [
                str(evidence)
                for evidence in verification_plan.get("evidence_needed", [])
                if str(evidence).strip()
            ][:5],
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
    if plan.get("provider_value_required"):
        prerequisites.append(
            "Provider-specific record value is required before DMARQ can preview a write."
        )
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
            "operation": plan.get("operation"),
            "record_name": plan.get("name"),
            "record_type": plan.get("record_type"),
            "reason": (
                "Safe provider-backed DNS preview is available."
                if automation_ready
                else "Manual review is required before provider automation is safe."
            ),
        },
    }
    item["action_plan"] = _action_plan_for_item(item)
    item["verification_plan"] = _verification_plan_for_item(item)
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
    item["verification_plan"] = _verification_plan_for_item(item)
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
        risk_level = "medium"
        safe_to_automate = True
        decision_checkpoints = [
            "Confirm the authoritative zone and record owner before approving the preview.",
            "Compare old and proposed DNS values, including TTL and record type.",
            "Wait for fresh DNS evidence before treating the item as fixed.",
        ]
        rollback_plan = (
            "If verification fails, restore the previous DNS value from the provider preview "
            "or keep the manual remediation item open."
        )
        steps = [
            "Open the DNS change plan and preview the provider mutation.",
            "Confirm the zone, record name, old value, new value, and TTL.",
            "Approve the change, then refresh DNS posture after propagation.",
        ]
    elif state == "investigate":
        owner = "Mail operations owner"
        risk_level = "high"
        safe_to_automate = False
        completion = str(
            item.get("completion_criteria")
            or "Sender legitimacy is confirmed and the item is resolved or converted into a DNS repair."
        )
        decision_checkpoints = [
            "Confirm whether the sender is still active in recent DMARC reports.",
            "Classify the source as legitimate, forwarding, abuse, or stale traffic.",
            "Avoid SPF or DKIM changes until the sender owner is known.",
        ]
        rollback_plan = (
            "If the classification is wrong, reopen the item and wait for fresh report "
            "evidence before changing DNS or policy."
        )
        steps = steps or [
            "Review the report evidence and sending-source history.",
            "Confirm whether the sender is legitimate for this domain.",
            "Authorize the sender with SPF/DKIM only after ownership is clear.",
        ]
    elif source == "dns_lint":
        owner = "Domain DNS operator"
        risk_level = "medium"
        safe_to_automate = False
        completion = "The DNS lint finding is no longer present after refresh."
        decision_checkpoints = [
            "Confirm the record is edited at the authoritative DNS provider.",
            "Check whether the proposed value replaces or appends to existing records.",
            "Refresh trusted resolver evidence after the DNS TTL has elapsed.",
        ]
        rollback_plan = (
            "If the lint finding remains or mail flow worsens, restore the previous DNS "
            "record value and keep the item open."
        )
        steps = steps or [
            "Open the DNS guidance section.",
            "Apply the listed record change in the authoritative DNS provider.",
            "Refresh DMARQ DNS checks after propagation.",
        ]
    else:
        owner = "Mail operations owner"
        risk_level = "medium" if item.get("severity") in {"critical", "high"} else "low"
        safe_to_automate = False
        completion = str(
            item.get("completion_criteria")
            or "The underlying domain health action no longer appears in the remediation queue."
        )
        decision_checkpoints = [
            "Confirm the finding still appears in current domain health evidence.",
            "Complete the operator action outside DMARQ if needed.",
            "Refresh DMARC report or DNS evidence before marking the item resolved.",
        ]
        rollback_plan = (
            "If fresh evidence still shows the finding, leave the item open and update the "
            "operator note instead of closing it."
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
        "risk_level": risk_level,
        "safe_to_automate": safe_to_automate,
        "operator_decision_summary": _operator_decision_summary(item),
        "decision_checkpoints": decision_checkpoints[:5],
        "rollback_plan": rollback_plan,
        "requires_fresh_evidence": True,
        "guidance_paths": _guidance_paths_for_item(
            item,
            owner=owner,
            automation_path=automation_path,
        ),
    }


def _verification_plan_for_item(item: Dict[str, Any]) -> Dict[str, Any]:
    """Return read-only evidence DMARQ should check before considering an item fixed."""
    automation = item.get("automation") or {}
    source = str(item.get("source") or "remediation")
    state = str(item.get("state") or "")

    if automation.get("eligible"):
        provider = str(automation.get("provider") or "connected DNS provider")
        return {
            "label": "Verify after approved provider repair",
            "status": "pending_operator_approval",
            "verification_method": "provider_write_then_dns_refresh",
            "freshness_requirement": "Fresh DNS evidence after provider propagation.",
            "failure_mode": "Keep the item open if the expected record is not visible.",
            "closure_gate": "Close only after approved provider apply and fresh DNS evidence agree.",
            "stale_evidence_warning": (
                "Do not mark this fixed from the preview alone; DNS propagation evidence is required."
            ),
            "summary": (
                f"DMARQ should only mark this fixed after the approved {provider} write is "
                "visible in fresh DNS evidence."
            ),
            "evidence_needed": [
                "The provider preview was approved and applied by a human operator.",
                "A fresh DNS lookup returns the expected record value from authoritative evidence.",
                "The remediation item disappears from the current queue after DNS refresh.",
            ],
            "next_check": "Refresh DNS posture after provider propagation, then rebuild the queue.",
        }

    if source == "dns_lint":
        return {
            "label": "Verify DNS evidence after manual repair",
            "status": "pending_dns_refresh",
            "verification_method": "manual_dns_refresh",
            "freshness_requirement": "Fresh resolver evidence after DNS TTL and propagation.",
            "failure_mode": "Keep the manual action open if the lint finding remains.",
            "closure_gate": "Close only after a fresh DNS refresh no longer reports this lint finding.",
            "stale_evidence_warning": (
                "Cached or pre-change DNS evidence can make a repaired record look broken."
            ),
            "summary": (
                "Manual DNS changes are complete only when DMARQ can read the corrected record "
                "from trusted resolver evidence."
            ),
            "evidence_needed": [
                "Authoritative DNS returns the expected TXT or CNAME record.",
                "The original DNS lint finding is no longer present after refresh.",
                "No new DNS lint finding was introduced by the change.",
            ],
            "next_check": "Run a DNS refresh after propagation and review the updated lint result.",
        }

    if state == "investigate":
        return {
            "label": "Verify sender evidence before repair",
            "status": "pending_sender_review",
            "verification_method": "fresh_dmarc_report_window",
            "freshness_requirement": "A new receiver report covering the active sender.",
            "failure_mode": "Keep investigating if the sender remains unknown, failing, or stale.",
            "closure_gate": (
                "Close only after the sender is classified and a newer DMARC report confirms "
                "the expected treatment."
            ),
            "stale_evidence_warning": (
                "Old report rows can describe senders that no longer send mail for this domain."
            ),
            "summary": (
                "Investigation items are not fixed until the sender is classified and fresh "
                "DMARC reports prove the chosen treatment."
            ),
            "evidence_needed": [
                "The sender is classified as legitimate, forwarding, abuse, or stale traffic.",
                "Recent report rows show the source now passes DMARC or is intentionally blocked.",
                "Source intelligence and last-sent timestamps still match the operator decision.",
            ],
            "next_check": "Wait for the next receiver report window, then confirm active sources.",
        }

    return {
        "label": "Verify domain health after operator action",
        "status": "pending_report_evidence",
        "verification_method": "fresh_health_rebuild",
        "freshness_requirement": "Fresh DMARC reports or DNS checks after the operator action.",
        "failure_mode": "Keep the item open if the same health action is still present.",
        "closure_gate": "Close only after fresh health evidence removes the same finding.",
        "stale_evidence_warning": (
            "Do not close from an operator note alone; import or refresh evidence first."
        ),
        "summary": (
            "Health items should stay open until fresh DMARC or DNS evidence confirms the "
            "underlying finding is gone."
        ),
        "evidence_needed": [
            "Fresh DMARC reports or DNS checks cover the affected source or record.",
            "The same health action no longer appears in the remediation queue.",
            "Any remaining failures are documented as expected or intentionally blocked.",
        ],
        "next_check": "Refresh domain health after new evidence is imported.",
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

    _apply_loop_metadata(domain, items)
    _attach_notification_profiles(domain, items)
    items.sort(
        key=lambda item: (
            item["state"] != "approval_ready",
            -SEVERITY_RANK.get(item["severity"], 0),
            -int(item.get("priority_score") or 0),
            item["id"],
        )
    )
    return {
        "domain": domain,
        "status": _queue_status(items),
        "summary": _summary(items),
        "loop": _loop_summary(domain, items),
        "items": items,
    }
