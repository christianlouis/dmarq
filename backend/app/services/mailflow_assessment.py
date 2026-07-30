"""Report-backed mailflow identity and DKIM alignment guidance.

The service only interprets ingestion-time source projections. It never
performs DNS, provider, reputation, or delivery lookups on a UI read.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable

from app.services.mail_signals import build_dmarc_source_signals


def _count(value: object) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _values(source: Dict[str, Any], key: str) -> list[str]:
    return sorted({str(value).strip() for value in source.get(key) or [] if str(value).strip()})


def _protective_disposition(source: Dict[str, Any]) -> bool:
    failed = _count(source.get("dmarc_fail_count"))
    dispositions = source.get("disposition_counts") or {}
    protected = _count(dispositions.get("reject")) + _count(dispositions.get("quarantine"))
    return failed > 0 and protected >= failed


def _alignment_status(pass_count: int, fail_count: int) -> str:
    if pass_count and fail_count:
        return "mixed"
    if pass_count:
        return "pass"
    if fail_count:
        return "not_observed"
    return "unknown"


def _flow(
    source: Dict[str, Any],
    sender: Dict[str, Any],
    *,
    workspace_id: int | None,
    domain: str,
) -> Dict[str, Any]:
    messages = _count(source.get("count"))
    spf_pass = _count(source.get("spf_pass_count"))
    spf_fail = _count(source.get("spf_fail_count"))
    dkim_pass = _count(source.get("dkim_pass_count"))
    dkim_fail = _count(source.get("dkim_fail_count"))
    dmarc_fail = _count(source.get("dmarc_fail_count"))
    protected = _protective_disposition(source)
    fully_spf_aligned_without_dkim = (
        messages > 0 and spf_pass == messages and dkim_pass == 0 and dkim_fail == messages
    )

    if fully_spf_aligned_without_dkim:
        status = "aligned_dkim_not_observed"
        label = "Aligned DKIM not observed"
        intended_mail_impact = "likely_affected" if dmarc_fail else "fragile"
        detail = (
            f"Receivers evaluated {dkim_fail} message(s) without aligned DKIM. "
            "DMARQ cannot tell from aggregate reports alone whether signing is disabled, "
            "a key is missing, or a signature uses the wrong domain."
        )
        next_step = "Confirm DKIM signing for this domain in the sending service"
    elif dkim_pass > 0 and dkim_fail > 0:
        status = "intermittent_dkim_alignment"
        label = "Separate mixed DKIM identities"
        intended_mail_impact = "unknown"
        detail = (
            f"Aligned DKIM passed for {dkim_pass} message(s) and failed for {dkim_fail}. "
            "This source-IP projection combines observed domains and selectors, so it cannot "
            "identify which value belongs to the failures."
        )
        next_step = "Separate the failing identity before changing DKIM"
    elif dkim_pass > 0:
        status = "healthy"
        label = "Aligned DKIM observed"
        intended_mail_impact = "likely_not_affected"
        detail = f"Receivers reported aligned DKIM for {dkim_pass} message(s)."
        next_step = "Keep report intake running"
    elif protected:
        status = "likely_unauthorized"
        label = "Likely unauthorized use"
        intended_mail_impact = "likely_not_affected"
        detail = (
            f"A source without aligned SPF or DKIM failed DMARC for {dmarc_fail} message(s), "
            "and receivers reported quarantine or reject. A provider match alone does not prove "
            "that this tenant is authorized for the domain."
        )
        next_step = "No immediate action; keep monitoring"
    elif sender.get("status") == "known" and dmarc_fail:
        status = "investigate_alignment"
        label = "Review alignment for this known sender"
        intended_mail_impact = "unknown"
        detail = (
            f"This known sending service failed DMARC for {dmarc_fail} message(s), "
            "but the aggregate report does not identify the provider-side cause."
        )
        next_step = "Review SPF and DKIM alignment for this sending service"
    elif dmarc_fail:
        status = "investigate_source"
        label = "Confirm whether this source is yours"
        intended_mail_impact = "unknown"
        detail = (
            f"This source failed DMARC for {dmarc_fail} message(s), but DMARQ cannot yet "
            "link it to an approved sending service."
        )
        next_step = "Classify the source before changing DNS"
    else:
        status = "insufficient_evidence"
        label = "More report evidence needed"
        intended_mail_impact = "unknown"
        detail = (
            "The selected window does not contain enough authentication evidence for this path."
        )
        next_step = "Keep report intake running"

    evidence_level = (
        "inferred"
        if status in {"likely_unauthorized", "investigate_alignment", "investigate_source"}
        else "observed"
    )
    signals = build_dmarc_source_signals(
        source,
        workspace_id=workspace_id,
        domain=domain,
        evidence_refs=source.get("evidence_refs") or (),
    )
    return {
        "source_ip": str(source.get("source_ip") or "unknown"),
        "sender_name": str(sender.get("name") or "Unknown sender"),
        "sender_status": str(sender.get("status") or "unknown"),
        "status": status,
        "label": label,
        "detail": detail,
        "message_count": messages,
        "header_from_domains": _values(source, "header_from_domains"),
        "envelope_from_domains": _values(source, "envelope_from_domains"),
        "spf_domains": _values(source, "spf_domains"),
        "dkim_domains": _values(source, "dkim_domains"),
        "dkim_selectors": _values(source, "dkim_selectors"),
        "spf_alignment": _alignment_status(spf_pass, spf_fail),
        "dkim_alignment": _alignment_status(dkim_pass, dkim_fail),
        "dmarc_status": str(source.get("dmarc_result") or "unknown"),
        "receiver_disposition": str(source.get("disposition") or "none"),
        "intended_mail_impact": intended_mail_impact,
        "evidence_level": evidence_level,
        "claim_level": evidence_level,
        "delivery_certainty": (
            "inferred_only" if evidence_level == "inferred" else "authentication_only"
        ),
        "signals": signals,
        "provider_evidence_status": "not_connected",
        "next_step": next_step,
        "verification_condition": (
            "A fresh aggregate report shows an aligned DKIM pass for this sending path."
        ),
    }


def build_domain_mailflow_assessment(
    domain: str,
    sources: Iterable[Dict[str, Any]],
    sender_by_ip: Dict[str, Dict[str, Any]],
    *,
    workspace_id: int | None = None,
) -> Dict[str, Any]:
    """Build one domain summary plus per-source mailflow identity facts."""
    flows = [
        _flow(
            source,
            sender_by_ip.get(str(source.get("source_ip") or "unknown"), {}),
            workspace_id=workspace_id,
            domain=domain,
        )
        for source in sources
        if _count(source.get("count")) > 0
    ]
    priority = {
        "aligned_dkim_not_observed": 0,
        "intermittent_dkim_alignment": 1,
        "investigate_alignment": 2,
        "investigate_source": 3,
        "likely_unauthorized": 4,
        "healthy": 5,
        "insufficient_evidence": 6,
    }
    flows.sort(key=lambda item: (priority.get(item["status"], 99), -item["message_count"]))
    counts = {key: sum(flow["status"] == key for flow in flows) for key in priority}

    actionable = [flow for flow in flows if flow["status"] == "aligned_dkim_not_observed"]
    investigate = [
        flow
        for flow in flows
        if flow["status"]
        in {"intermittent_dkim_alignment", "investigate_alignment", "investigate_source"}
    ]
    if actionable:
        primary = actionable[0]
        status = "action_required"
        title = "Repair DKIM signing for an active mailflow"
        summary = (
            f"DMARQ observed {len(actionable)} active path(s) for {domain} without reliable "
            "aligned DKIM. Mail may still pass through SPF, but forwarding can break that path."
        )
        next_step = primary["next_step"]
        confidence = "High" if primary["sender_status"] == "known" else "Medium"
    elif investigate:
        primary = investigate[0]
        status = "investigation_required"
        title = "Separate the failing mailflow identity"
        summary = (
            f"DMARQ observed {len(investigate)} path(s) for {domain} whose failing identity "
            "cannot be isolated from the source-IP projection."
        )
        next_step = primary["next_step"]
        confidence = "Medium"
    elif flows and counts["healthy"]:
        primary = next(flow for flow in flows if flow["status"] == "healthy")
        status = "healthy"
        title = "Aligned DKIM is working"
        summary = f"DMARQ observed aligned DKIM on active mailflow paths for {domain}."
        next_step = "Keep report intake running"
        confidence = "High"
    elif flows and counts["likely_unauthorized"]:
        primary = next(flow for flow in flows if flow["status"] == "likely_unauthorized")
        status = "no_action_likely_unauthorized_use"
        title = "Unrecognized failing mail is being protected"
        summary = (
            "Receivers reported protective handling for unrecognized sources. "
            "No DKIM repair should be made for those sources without an owner."
        )
        next_step = "No immediate action; keep monitoring"
        confidence = "Medium"
    else:
        primary = None
        status = "insufficient_evidence"
        title = "Waiting for mailflow evidence"
        summary = f"No active report-backed mailflow is available for {domain} in this window."
        next_step = "Keep report intake running"
        confidence = "Not enough evidence"

    inferences = []
    unknowns = []
    if actionable:
        inferences.append(
            "A missing aligned DKIM pass can indicate disabled signing, a missing key, or the wrong signing domain."
        )
        unknowns.append(
            "The exact provider-side root cause remains unknown without provider evidence."
        )
    if counts["likely_unauthorized"]:
        inferences.append(
            "Protective handling of an unaligned source suggests unauthorized use, but does not prove ownership."
        )
        unknowns.append(
            "Whether the protected source belongs to an approved sender remains unknown."
        )
    if counts["investigate_alignment"]:
        inferences.append(
            "Provider recognition identifies a known service, but does not explain its DMARC failure."
        )
        unknowns.append("The failing SPF or DKIM identity remains unknown from aggregate evidence.")
    if counts["investigate_source"]:
        inferences.append("The failing source may be legitimate, but ownership is not established.")
        unknowns.append(
            "Whether the source belongs to an approved sending service remains unknown."
        )

    return {
        "domain": domain,
        "status": status,
        "title": title,
        "summary": summary,
        "next_step": next_step,
        "cta_label": "Review DKIM repair" if actionable else "Review mailflow evidence",
        "cta_href": "#mailflow-diagnosis",
        "confidence": confidence,
        "evidence_scope": (
            "Aggregate DMARC reports prove receiver authentication observations, not final delivery. "
            "A provider connection is optional and only strengthens the root-cause evidence."
        ),
        "known_facts": [
            f"{len(flows)} active source path(s) were observed in the selected window.",
            f"{len(actionable)} path(s) need DKIM alignment repair.",
        ],
        "inferences": inferences,
        "unknowns": unknowns,
        "repair_steps": (
            [
                "Open the sending service's domain settings and confirm DKIM signing is enabled.",
                f"Generate or rotate a domain-specific key for {domain} if no usable key exists.",
                "Publish the exact selector._domainkey TXT or CNAME value supplied by the sender.",
                "Verify the public record, then send or forward one controlled message.",
                "Keep the repair open until a fresh DMARC report shows aligned DKIM passing.",
            ]
            if actionable
            else []
        ),
        "verification_condition": (
            "A fresh aggregate report shows aligned DKIM passing on the affected path."
        ),
        "primary_source_ip": primary["source_ip"] if primary else None,
        "counts": counts,
        "flows": flows,
    }
