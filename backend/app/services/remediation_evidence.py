"""Shared remediation evidence refresh helpers."""

from typing import Any, Dict


def _fallback_remediation_track(item: Dict[str, Any]) -> str:
    """Infer a conservative remediation track when callers have not set one."""
    if (item.get("automation") or {}).get("eligible"):
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
    return "manual_only"


def evidence_refresh_for_remediation_item(domain: str, item: Dict[str, Any]) -> Dict[str, Any]:
    """Return the safe read-only refresh path before a remediation item is closed."""
    track = str(item.get("remediation_track") or _fallback_remediation_track(item))
    source = str(item.get("source") or "remediation")
    state = str(item.get("state") or "")
    verification = item.get("verification_plan") or {}
    stale_warning = str(verification.get("stale_evidence_warning") or "")
    next_check = str(verification.get("next_check") or "")

    if track == "blocked_by_prerequisite":
        return {
            "required": True,
            "source": "mail_provider",
            "refresh_key": "provider_value",
            "label": "Provider value required",
            "safe_to_run": False,
            "recommended_action": (
                "Collect the exact DKIM, SPF, DMARC, or CNAME target from the mail provider, "
                "then refresh DNS evidence."
            ),
            "completion_signal": "The prerequisite is present and the item can move to manual DNS or provider preview.",
            "stale_warning": stale_warning,
            "next_check": next_check,
            "ui_anchor": "#dns-guidance",
            "endpoint_hint": "",
        }

    if source == "dns_lint" or track in {"provider_preview", "manual_dns"}:
        return {
            "required": True,
            "source": "dns",
            "refresh_key": "dns",
            "label": "Refresh DNS evidence",
            "safe_to_run": True,
            "recommended_action": (
                "Refresh DNS records, DNS lint, posture, and the remediation queue after the DNS TTL."
            ),
            "completion_signal": "The original DNS finding is absent from the refreshed queue.",
            "stale_warning": stale_warning,
            "next_check": next_check,
            "ui_anchor": "#dns-records",
            "endpoint_hint": f"/api/v1/domains/{domain}/dns?refresh=true",
        }

    if (
        track == "reputation_review"
        or str(item.get("incident_type") or "") == "sending_ip_reputation_risk"
    ):
        return {
            "required": True,
            "source": "source_reputation",
            "refresh_key": "source_reputation",
            "label": "Refresh source reputation",
            "safe_to_run": True,
            "recommended_action": (
                "Refresh sending-source rows and reputation feeds, then rebuild the remediation queue."
            ),
            "completion_signal": "Current reputation evidence is clean, accepted, or documented as intentionally blocked.",
            "stale_warning": stale_warning,
            "next_check": next_check,
            "ui_anchor": "#sending-sources",
            "endpoint_hint": f"/api/v1/domains/{domain}/sources?refresh=true",
        }

    if state == "investigate":
        return {
            "required": True,
            "source": "dmarc_reports_and_sources",
            "refresh_key": "reports_and_sources",
            "label": "Refresh report and source evidence",
            "safe_to_run": True,
            "recommended_action": (
                "Reload reports and sending-source intelligence after the next receiver report window."
            ),
            "completion_signal": "Fresh report rows show the source is passing, blocked, or no longer active.",
            "stale_warning": stale_warning,
            "next_check": next_check,
            "ui_anchor": "#sending-sources",
            "endpoint_hint": f"/api/v1/domains/{domain}/sources?refresh=true",
        }

    return {
        "required": True,
        "source": "dmarc_reports",
        "refresh_key": "reports",
        "label": "Refresh report evidence",
        "safe_to_run": True,
        "recommended_action": (
            "Reload reports and rebuild domain health after the operator action has had time to appear."
        ),
        "completion_signal": "The same health action no longer appears in the refreshed remediation queue.",
        "stale_warning": stale_warning,
        "next_check": next_check,
        "ui_anchor": "#reports",
        "endpoint_hint": f"/api/v1/domains/{domain}/reports",
    }
