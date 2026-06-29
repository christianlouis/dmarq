"""Named sender identification and remediation hints for DMARC sources."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Sequence


@dataclass(frozen=True)
class SenderProfile:
    """Static sender profile matched against report and DNS evidence."""

    id: str
    name: str
    provider: str
    category: str
    hostname_tokens: Sequence[str]
    domain_tokens: Sequence[str]
    selector_tokens: Sequence[str]
    extension_tokens: Sequence[str]
    remediation_hint: str
    docs_url: Optional[str] = None


SENDER_PROFILES: Sequence[SenderProfile] = (
    SenderProfile(
        id="google-workspace",
        name="Google Workspace",
        provider="Google",
        category="mailbox_provider",
        hostname_tokens=("google.com", "googlemail.com", "googleusercontent.com"),
        domain_tokens=("_spf.google.com", "google.com"),
        selector_tokens=("google",),
        extension_tokens=("workspace-mail",),
        remediation_hint=(
            "Check Google Workspace DKIM signing and make sure the domain SPF record "
            "authorizes Google's sending include before tightening DMARC policy."
        ),
        docs_url="https://support.google.com/a/answer/174124",
    ),
    SenderProfile(
        id="microsoft-365",
        name="Microsoft 365",
        provider="Microsoft",
        category="mailbox_provider",
        hostname_tokens=("outlook.com", "protection.outlook.com", "microsoft.com"),
        domain_tokens=("spf.protection.outlook.com", "outlook.com", "microsoft.com"),
        selector_tokens=("selector1", "selector2"),
        extension_tokens=("microsoft-365",),
        remediation_hint=(
            "Verify Microsoft 365 DKIM is enabled for the domain and that SPF includes "
            "spf.protection.outlook.com only once."
        ),
        docs_url="https://learn.microsoft.com/en-us/defender-office-365/email-authentication-dkim-configure",
    ),
    SenderProfile(
        id="amazon-ses",
        name="Amazon SES",
        provider="Amazon Web Services",
        category="transactional_email",
        hostname_tokens=("amazonses.com", "amazonaws.com"),
        domain_tokens=("amazonses.com",),
        selector_tokens=("amazonses", "ses"),
        extension_tokens=("amazon-ses",),
        remediation_hint=(
            "Verify the SES identity, publish all DKIM CNAME records, and authorize the "
            "SES MAIL FROM domain in SPF if you use custom bounce handling."
        ),
        docs_url="https://docs.aws.amazon.com/ses/latest/dg/send-email-authentication-dkim.html",
    ),
    SenderProfile(
        id="sendgrid",
        name="SendGrid",
        provider="Twilio SendGrid",
        category="transactional_email",
        hostname_tokens=("sendgrid.net",),
        domain_tokens=("sendgrid.net",),
        selector_tokens=("s1", "s2", "sendgrid"),
        extension_tokens=("sendgrid",),
        remediation_hint=(
            "Complete SendGrid domain authentication, publish the DKIM CNAMEs, and keep "
            "SPF aligned with the authenticated return-path domain."
        ),
        docs_url="https://docs.sendgrid.com/ui/account-and-settings/how-to-set-up-domain-authentication",
    ),
    SenderProfile(
        id="mailchimp",
        name="Mailchimp",
        provider="Intuit Mailchimp",
        category="marketing_email",
        hostname_tokens=("mcsv.net", "mandrillapp.com", "mailchimp.com"),
        domain_tokens=("mandrillapp.com", "mailchimp.com"),
        selector_tokens=("mailchimp", "mandrill", "news"),
        extension_tokens=("newsletter", "marketing"),
        remediation_hint=(
            "Authenticate the sending domain in Mailchimp and confirm both DKIM selectors "
            "plus the Mailchimp SPF include are published before enforcement."
        ),
        docs_url="https://mailchimp.com/help/set-up-email-domain-authentication/",
    ),
    SenderProfile(
        id="zendesk",
        name="Zendesk",
        provider="Zendesk",
        category="support_email",
        hostname_tokens=("zendesk.com",),
        domain_tokens=("zendesk.com",),
        selector_tokens=("zendesk",),
        extension_tokens=("ticketing",),
        remediation_hint=(
            "Enable Zendesk email authentication for the support address and publish the "
            "provided DKIM CNAMEs for aligned helpdesk mail."
        ),
        docs_url="https://support.zendesk.com/hc/en-us/articles/4408843623194",
    ),
    SenderProfile(
        id="stripe",
        name="Stripe",
        provider="Stripe",
        category="transactional_email",
        hostname_tokens=("stripe.com",),
        domain_tokens=("stripe.com",),
        selector_tokens=("stripe",),
        extension_tokens=("billing",),
        remediation_hint=(
            "Use Stripe's domain authentication records for receipt and billing mail, then "
            "confirm DKIM alignment before moving the domain to reject."
        ),
        docs_url="https://docs.stripe.com/email-domain-authentication",
    ),
    SenderProfile(
        id="salesforce",
        name="Salesforce",
        provider="Salesforce",
        category="crm_email",
        hostname_tokens=("salesforce.com", "exacttarget.com"),
        domain_tokens=("salesforce.com", "exacttarget.com"),
        selector_tokens=("salesforce", "exacttarget"),
        extension_tokens=("salesforce",),
        remediation_hint=(
            "Complete Salesforce DKIM key activation and sender authentication for the "
            "org before treating CRM mail as enforcement-ready."
        ),
        docs_url="https://help.salesforce.com/s/articleView?id=sf.emailadmin_dkim_key.htm",
    ),
)


def _normalized_values(values: Iterable[Any]) -> List[str]:
    normalized = []
    for value in values:
        if value is None:
            continue
        text = str(value).strip().lower()
        if text:
            normalized.append(text)
    return normalized


def _contains_any(haystack: Iterable[str], needles: Sequence[str]) -> List[str]:
    matches = []
    for value in haystack:
        for needle in needles:
            if needle and needle.lower() in value:
                matches.append(value)
                break
    return matches


def _profile_score(
    profile: SenderProfile,
    hostname: Optional[str],
    source: Dict[str, Any],
) -> tuple[int, List[str]]:
    host_values = _normalized_values([hostname])
    domain_values = _normalized_values(
        list(source.get("spf_domains") or [])
        + list(source.get("dkim_domains") or [])
        + list(source.get("envelope_from_domains") or [])
    )
    selector_values = _normalized_values(source.get("dkim_selectors") or [])
    extension_values = _normalized_values((source.get("extensions") or {}).values())

    evidence: List[str] = []
    score = 0

    host_matches = _contains_any(host_values, profile.hostname_tokens)
    if host_matches:
        score += 45
        evidence.append(f"PTR hostname matched {host_matches[0]}")

    domain_matches = _contains_any(domain_values, profile.domain_tokens)
    if domain_matches:
        score += 30
        evidence.append(f"Authentication domain matched {domain_matches[0]}")

    selector_matches = _contains_any(selector_values, profile.selector_tokens)
    if selector_matches:
        score += 20
        evidence.append(f"DKIM selector matched {selector_matches[0]}")

    extension_matches = _contains_any(extension_values, profile.extension_tokens)
    if extension_matches:
        score += 25
        evidence.append(f"Report metadata matched {extension_matches[0]}")

    return min(score, 100), evidence


def _owned_infrastructure(
    domain: Optional[str], hostname: Optional[str]
) -> Optional[Dict[str, Any]]:
    if not domain or not hostname:
        return None
    normalized_domain = domain.lower().strip(".")
    normalized_hostname = hostname.lower().strip(".")
    if not normalized_hostname.endswith(normalized_domain):
        return None
    return {
        "id": "owned-infrastructure",
        "name": "Owned infrastructure",
        "provider": normalized_domain,
        "category": "owned_infrastructure",
        "status": "known",
        "confidence": 70,
        "reason": "PTR hostname is under the monitored domain.",
        "evidence": [f"PTR hostname matched {hostname}"],
        "remediation_hint": (
            "Confirm this host is part of your authorized mail estate, then keep SPF and "
            "DKIM aligned before tightening DMARC."
        ),
        "docs_url": None,
    }


def identify_sender(
    ip: str,
    source: Dict[str, Any],
    *,
    hostname: Optional[str] = None,
    domain: Optional[str] = None,
) -> Dict[str, Any]:
    """Return a named sender identity for a source row.

    The function is deterministic and conservative: high-confidence known
    senders are named, ambiguous matches are flagged, and unknown failing
    sources stay visibly distinct from legitimate but misconfigured services.
    """
    profile_matches = []
    for profile in SENDER_PROFILES:
        score, evidence = _profile_score(profile, hostname, source)
        if score >= 30:
            profile_matches.append((score, profile, evidence))

    profile_matches.sort(key=lambda item: item[0], reverse=True)
    if profile_matches:
        best_score, best_profile, best_evidence = profile_matches[0]
        if len(profile_matches) > 1 and profile_matches[1][0] == best_score:
            tied_names = sorted({best_profile.name, profile_matches[1][1].name})
            return {
                "id": "ambiguous-sender",
                "name": "Ambiguous sender",
                "provider": None,
                "category": "unknown",
                "status": "ambiguous",
                "confidence": max(40, min(best_score, 60)),
                "reason": "Multiple sender profiles matched with the same confidence.",
                "evidence": [f"Matched: {', '.join(tied_names)}"],
                "remediation_hint": (
                    "Confirm the service owner before making DNS changes; do not authorize "
                    "an ambiguous source based on IP alone."
                ),
                "docs_url": None,
            }
        return {
            "id": best_profile.id,
            "name": best_profile.name,
            "provider": best_profile.provider,
            "category": best_profile.category,
            "status": "known",
            "confidence": max(55, best_score),
            "reason": "Sender matched known provider evidence.",
            "evidence": best_evidence,
            "remediation_hint": best_profile.remediation_hint,
            "docs_url": best_profile.docs_url,
        }

    suspicious_hostname = bool(
        hostname and any(token in hostname.lower() for token in ("unknown", "forwarder"))
    )
    owned = None if suspicious_hostname else _owned_infrastructure(domain, hostname)
    if owned:
        return owned

    dmarc_failed = (
        int(source.get("dmarc_fail_count", 0) or 0) > 0 or source.get("dmarc_result") == "fail"
    )
    if dmarc_failed and not hostname:
        status = "suspicious"
        reason = "DMARC failures came from a source without reverse DNS."
    elif dmarc_failed:
        status = "unknown"
        reason = "DMARC failures came from an unrecognized sender."
    else:
        status = "unknown"
        reason = "No known provider profile matched this source."

    evidence = [f"Source IP {ip}"]
    if hostname:
        evidence.append(f"PTR hostname {hostname}")

    return {
        "id": "unknown-sender",
        "name": "Unknown sender",
        "provider": None,
        "category": "unknown",
        "status": status,
        "confidence": 0,
        "reason": reason,
        "evidence": evidence,
        "remediation_hint": (
            "Identify the business owner for this source before authorizing it. If nobody "
            "owns it, keep it blocked by DMARC enforcement."
        ),
        "docs_url": None,
    }
