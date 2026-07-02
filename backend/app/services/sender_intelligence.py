"""Named sender identification, source geography, and anomaly hints."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from datetime import datetime, timezone
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
        id="postmark",
        name="Postmark",
        provider="ActiveCampaign Postmark",
        category="transactional_email",
        hostname_tokens=("mtasv.net", "postmarkapp.com"),
        domain_tokens=("mtasv.net", "pm.mtasv.net", "postmarkapp.com"),
        selector_tokens=("pm", "postmark"),
        extension_tokens=("postmark",),
        remediation_hint=(
            "Verify the sender signature or domain in Postmark, publish the DKIM record, "
            "and use the custom Return-Path CNAME to pm.mtasv.net for aligned bounces."
        ),
        docs_url="https://postmarkapp.com/support/article/910-how-do-i-add-a-custom-return-path",
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
        id="mailgun",
        name="Mailgun",
        provider="Sinch Mailgun",
        category="transactional_email",
        hostname_tokens=("mailgun.org", "mailgun.net"),
        domain_tokens=("mailgun.org", "mailgun.net"),
        selector_tokens=("mailgun", "smtpapi"),
        extension_tokens=("mailgun",),
        remediation_hint=(
            "Verify the sending domain in Mailgun, publish the DKIM records, and confirm "
            "the Mailgun SPF/MX tracking records are aligned before enforcement."
        ),
        docs_url="https://help.mailgun.com/hc/en-us/articles/32884702360603-Domain-Verification-Setup-Guide",
    ),
    SenderProfile(
        id="sparkpost",
        name="SparkPost",
        provider="Bird SparkPost",
        category="transactional_email",
        hostname_tokens=("sparkpostmail.com", "sparkpost.com"),
        domain_tokens=("sparkpostmail.com", "sparkpost.com"),
        selector_tokens=("sparkpost", "scph"),
        extension_tokens=("sparkpost",),
        remediation_hint=(
            "Verify the SparkPost sending domain, publish DKIM, and configure a bounce "
            "domain so SPF and bounce handling are easy to audit."
        ),
        docs_url="https://developers.sparkpost.com/api/sending-domains/",
    ),
    SenderProfile(
        id="mailjet",
        name="Mailjet",
        provider="Sinch Mailjet",
        category="transactional_email",
        hostname_tokens=("mailjet.com", "mailjet.net"),
        domain_tokens=("spf.mailjet.com", "mailjet.com", "mailjet.net"),
        selector_tokens=("mailjet",),
        extension_tokens=("mailjet",),
        remediation_hint=(
            "Authenticate the domain in Mailjet and consolidate SPF into one record that "
            "includes spf.mailjet.com, then verify DKIM alignment."
        ),
        docs_url="https://documentation.mailjet.com/hc/en-us/articles/360049641733-Authenticating-Domains-with-SPF-and-DKIM-A-Complete-Guide",
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
        id="brevo",
        name="Brevo",
        provider="Brevo",
        category="marketing_email",
        hostname_tokens=("sendinblue.com", "brevo.com", "sender-sib.com", "mailin.fr"),
        domain_tokens=("sendinblue.com", "brevo.com", "sender-sib.com", "mailin.fr"),
        selector_tokens=("brevo", "sib", "sendinblue"),
        extension_tokens=("brevo", "sendinblue"),
        remediation_hint=(
            "Authenticate the sending domain in Brevo and rely on aligned DKIM for DMARC; "
            "review envelope-from alignment before expecting SPF to pass DMARC."
        ),
        docs_url="https://help.brevo.com/hc/en-us/articles/12163873383186-Authenticate-your-domain-with-Brevo-Brevo-code-DKIM-DMARC",
    ),
    SenderProfile(
        id="klaviyo",
        name="Klaviyo",
        provider="Klaviyo",
        category="marketing_email",
        hostname_tokens=("klaviyo.com", "klaviyomail.com"),
        domain_tokens=("klaviyo.com", "klaviyomail.com"),
        selector_tokens=("klaviyo", "km1", "km2", "kt1", "kt2", "ks1", "ks2", "kl1", "kl2"),
        extension_tokens=("klaviyo",),
        remediation_hint=(
            "Use Klaviyo's branded sending-domain setup and verify the generated CNAME or "
            "NS records before treating campaign mail as fully authenticated."
        ),
        docs_url="https://help.klaviyo.com/hc/en-us/articles/115000357752",
    ),
    SenderProfile(
        id="hubspot",
        name="HubSpot",
        provider="HubSpot",
        category="marketing_email",
        hostname_tokens=("hubspotemail.net", "hubspot.com"),
        domain_tokens=("hubspotemail.net", "hubspot.com"),
        selector_tokens=("hubspot", "hs"),
        extension_tokens=("hubspot",),
        remediation_hint=(
            "Connect the email sending domain in HubSpot and verify the generated DKIM, "
            "SPF, and DMARC records before using stronger DMARC policy."
        ),
        docs_url="https://knowledge.hubspot.com/marketing-email/manage-email-authentication-in-hubspot",
    ),
    SenderProfile(
        id="constant-contact",
        name="Constant Contact",
        provider="Constant Contact",
        category="marketing_email",
        hostname_tokens=("ccsend.com", "constantcontact.com"),
        domain_tokens=("auth.ccsend.com", "ccsend.com", "constantcontact.com"),
        selector_tokens=("constantcontact", "ctct", "ccsend"),
        extension_tokens=("constant-contact", "constantcontact"),
        remediation_hint=(
            "Self-authenticate the domain in Constant Contact with the generated DKIM "
            "records, then check DMARC reports for the authenticated domain signature."
        ),
        docs_url="https://knowledgebase.constantcontact.com/email-digital-marketing/tutorials/KnowledgeBase/5932-Self-authenticate-your-emails-using-your-own-domain",
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
        id="zoho-mail",
        name="Zoho Mail",
        provider="Zoho",
        category="mailbox_provider",
        hostname_tokens=("zoho.com", "zohomail.com", "zoho.eu", "zoho.in"),
        domain_tokens=("zoho.com", "zohomail.com", "zoho.eu", "zoho.in", "one.zoho.com"),
        selector_tokens=("zoho",),
        extension_tokens=("zoho",),
        remediation_hint=(
            "Verify the domain in Zoho, publish SPF and DKIM from the Zoho admin console, "
            "and confirm the selected regional Zoho include is present only once."
        ),
        docs_url="https://www.zoho.com/mail/help/adminconsole/spf-configuration.html",
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


DEMO_IP_INTELLIGENCE: Dict[str, Dict[str, Any]] = {
    "203.0.113.": {
        "country": "United States",
        "country_code": "US",
        "region": "North America",
        "asn": "AS64510",
        "network": "DMARQ Cloud Mail",
    },
    "198.51.100.": {
        "country": "Germany",
        "country_code": "DE",
        "region": "Europe",
        "asn": "AS64520",
        "network": "DMARQ SaaS Edge",
    },
    "192.0.2.": {
        "country": "Netherlands",
        "country_code": "NL",
        "region": "Europe",
        "asn": "AS64530",
        "network": "Legacy Mail Forwarders",
    },
}


GEO_EXTENSION_KEYS = {
    "country": ("geo:country", "demo:country", "country"),
    "country_code": ("geo:country_code", "demo:country_code", "country_code"),
    "region": ("geo:region", "demo:region", "region"),
    "asn": ("geo:asn", "demo:asn", "asn"),
    "network": ("geo:network", "demo:network", "network", "demo:provider"),
}


def _normalized_values(values: Iterable[Any]) -> List[str]:
    normalized = []
    for value in values:
        if value is None:
            continue
        text = str(value).strip().lower()
        if text:
            normalized.append(text)
    return normalized


def _first_metadata_value(source: Dict[str, Any], field: str) -> Optional[str]:
    extensions = source.get("extensions") or {}
    keys = GEO_EXTENSION_KEYS[field]
    for key in keys:
        value = source.get(key) if key in source else extensions.get(key)
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def source_geo_for(ip: str, source: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Return coarse source geography from existing metadata or demo-safe fallbacks."""
    source = source or {}
    geo = {field: _first_metadata_value(source, field) for field in GEO_EXTENSION_KEYS}

    if not geo["region"]:
        for prefix, metadata in DEMO_IP_INTELLIGENCE.items():
            if str(ip).startswith(prefix):
                geo.update({key: geo.get(key) or value for key, value in metadata.items()})
                break

    if not geo["region"]:
        try:
            address = ipaddress.ip_address(ip)
            if address.is_private or address.is_loopback or address.is_reserved:
                geo.update(
                    {
                        "country": geo["country"] or "Private or reserved network",
                        "country_code": geo["country_code"] or "ZZ",
                        "region": "Private or reserved",
                        "asn": geo["asn"],
                        "network": geo["network"] or "Private or reserved address space",
                    }
                )
        except ValueError:
            # Invalid source identifiers have no network metadata to infer.
            pass

    return {
        "country": geo["country"] or "Unknown",
        "country_code": geo["country_code"] or "ZZ",
        "region": geo["region"] or "Unknown",
        "asn": geo["asn"],
        "network": geo["network"],
        "source": (
            "metadata"
            if any(_first_metadata_value(source, field) for field in GEO_EXTENSION_KEYS)
            else "inferred"
        ),
    }


def _report_timestamp(report: Dict[str, Any]) -> int:
    for key in ("begin_timestamp", "begin_date"):
        value = report.get(key)
        if isinstance(value, (int, float)):
            return int(value)
        if isinstance(value, str):
            try:
                return int(value)
            except ValueError:
                try:
                    parsed = datetime.fromisoformat(value)
                    if parsed.tzinfo is None:
                        parsed = parsed.replace(tzinfo=timezone.utc)
                    else:
                        parsed = parsed.astimezone(timezone.utc)
                    return int(parsed.timestamp())
                except ValueError:
                    continue
    return 0


def _report_records(reports: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for report in reports:
        timestamp = _report_timestamp(report)
        for record in report.get("records") or []:
            row = dict(record)
            row["_timestamp"] = timestamp
            row["_domain"] = report.get("domain")
            rows.append(row)
    return rows


def _add_rollup(target: Dict[str, Dict[str, Any]], record: Dict[str, Any]) -> None:
    ip = str(record.get("source_ip") or "unknown")
    count = int(record.get("count") or 0)
    spf_pass = record.get("spf_result") == "pass"
    dkim_pass = record.get("dkim_result") == "pass"
    dmarc_pass = spf_pass or dkim_pass
    item = target.setdefault(
        ip,
        {
            "ip": ip,
            "count": 0,
            "failed": 0,
            "regions": set(),
            "geo": source_geo_for(ip, record),
        },
    )
    item["count"] += count
    item["failed"] += 0 if dmarc_pass else count
    item["regions"].add(item["geo"]["region"])


def _summarize_regions(sources: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    regions: Dict[str, Dict[str, Any]] = {}
    for source in sources:
        ip = str(source.get("source_ip") or source.get("ip") or "unknown")
        geo = source_geo_for(ip, source)
        key = geo["region"]
        item = regions.setdefault(
            key,
            {
                "region": key,
                "country_codes": set(),
                "message_count": 0,
                "source_count": 0,
                "failed_count": 0,
                "networks": set(),
            },
        )
        item["message_count"] += int(source.get("count") or 0)
        item["source_count"] += 1
        item["failed_count"] += int(source.get("dmarc_fail_count") or 0)
        if geo["country_code"]:
            item["country_codes"].add(geo["country_code"])
        if geo.get("network"):
            item["networks"].add(geo["network"])

    rows = []
    for item in regions.values():
        total = int(item["message_count"] or 0)
        failed = int(item["failed_count"] or 0)
        rows.append(
            {
                "region": item["region"],
                "country_codes": sorted(item["country_codes"]),
                "message_count": total,
                "source_count": item["source_count"],
                "failed_count": failed,
                "failure_rate": round((failed / total) * 100, 1) if total else 0.0,
                "networks": sorted(item["networks"]),
            }
        )
    return sorted(rows, key=lambda row: row["message_count"], reverse=True)


def _source_anomalies(
    domain: str,
    baseline: Dict[str, Dict[str, Any]],
    recent: Dict[str, Dict[str, Any]],
    baseline_regions: set[str],
    *,
    period_days: int,
    recent_days: int,
) -> tuple[List[Dict[str, Any]], Dict[str, List[Dict[str, Any]]]]:
    anomalies: List[Dict[str, Any]] = []
    anomalies_by_ip: Dict[str, List[Dict[str, Any]]] = {}

    def add_anomaly(row: Dict[str, Any]) -> None:
        anomalies.append(row)
        ip = row.get("source_ip")
        if ip:
            anomalies_by_ip.setdefault(str(ip), []).append(row)

    for ip, current in sorted(recent.items(), key=lambda item: item[1]["count"], reverse=True):
        previous = baseline.get(ip)
        geo = current["geo"]
        failed = int(current["failed"] or 0)
        count = int(current["count"] or 0)
        if previous is None:
            add_anomaly(
                {
                    "type": "new_sender",
                    "severity": "error" if failed else "warning",
                    "title": "New sending source",
                    "domain": domain,
                    "source_ip": ip,
                    "region": geo["region"],
                    "message_count": count,
                    "failed_count": failed,
                    "detail": f"{ip} is new in the latest source window for {domain}.",
                    "action": "Confirm ownership before authorizing this source in DNS.",
                }
            )
        if (
            geo["region"] not in {"Unknown", "Private or reserved"}
            and geo["region"] not in baseline_regions
        ):
            add_anomaly(
                {
                    "type": "new_region",
                    "severity": "warning",
                    "title": "New sending region",
                    "domain": domain,
                    "source_ip": ip,
                    "region": geo["region"],
                    "message_count": count,
                    "failed_count": failed,
                    "detail": f"{geo['region']} appears for {domain} in recent reports.",
                    "action": "Check whether the provider intentionally added this region.",
                }
            )
        if previous and previous["count"] > 0:
            baseline_rate = previous["count"] / max(1, period_days - recent_days)
            current_rate = count / max(1, recent_days)
            expected_baseline_count = baseline_rate * recent_days
            if current_rate >= baseline_rate * 2.5 and count - expected_baseline_count >= 50:
                add_anomaly(
                    {
                        "type": "volume_spike",
                        "severity": "warning",
                        "title": "Source volume spike",
                        "domain": domain,
                        "source_ip": ip,
                        "region": geo["region"],
                        "message_count": count,
                        "failed_count": failed,
                        "detail": f"{ip} is sending materially more mail than its baseline.",
                        "action": "Verify campaign or service-owner activity for this source.",
                    }
                )
        baseline_failure_rate = (
            (previous["failed"] / previous["count"]) * 100
            if previous and previous["count"]
            else 0.0
        )
        current_failure_rate = (failed / count) * 100 if count else 0.0
        alignment_regressed = current_failure_rate - baseline_failure_rate >= 15
        sustained_alignment_failure = current_failure_rate >= 25 and failed >= 20
        if failed and (alignment_regressed or sustained_alignment_failure):
            add_anomaly(
                {
                    "type": "alignment_failure",
                    "severity": "error" if current_failure_rate >= 50 else "warning",
                    "title": "Alignment failure increased",
                    "domain": domain,
                    "source_ip": ip,
                    "region": geo["region"],
                    "message_count": count,
                    "failed_count": failed,
                    "detail": (
                        f"DMARC failures from {ip} are at {round(current_failure_rate, 1)}% "
                        "in the recent window."
                    ),
                    "action": "Check DKIM selector health and SPF alignment before tightening policy.",
                }
            )

    anomalies.sort(
        key=lambda row: (
            0 if row["severity"] == "error" else 1,
            -int(row.get("message_count") or 0),
            row["type"],
        )
    )
    return anomalies, anomalies_by_ip


def build_source_intelligence(
    domain: str,
    reports: Iterable[Dict[str, Any]],
    sources: Iterable[Dict[str, Any]],
    *,
    period_days: int = 30,
) -> Dict[str, Any]:
    """Build region summaries and anomaly hints for one domain."""
    source_rows = list(sources)
    report_rows = _report_records(reports)
    if not report_rows and not source_rows:
        return {
            "domain": domain,
            "period_days": max(1, int(period_days or 30)),
            "regions": [],
            "anomalies": [],
            "anomalies_by_ip": {},
            "summary": {
                "regions": 0,
                "sources": 0,
                "messages": 0,
                "anomalies": 0,
                "critical": 0,
                "warnings": 0,
            },
        }

    latest_ts = max((row.get("_timestamp") or 0 for row in report_rows), default=0)
    period_days = max(1, int(period_days or 30))
    recent_days = min(7, max(1, period_days // 2))
    recent_start = latest_ts - recent_days * 86400 if latest_ts else 0
    period_start = latest_ts - period_days * 86400 if latest_ts else 0

    baseline: Dict[str, Dict[str, Any]] = {}
    recent: Dict[str, Dict[str, Any]] = {}
    for row in report_rows:
        if period_start and int(row.get("_timestamp") or 0) < period_start:
            continue
        if latest_ts and int(row.get("_timestamp") or 0) >= recent_start:
            _add_rollup(recent, row)
        else:
            _add_rollup(baseline, row)

    regions = _summarize_regions(source_rows)
    baseline_regions = {
        region
        for item in baseline.values()
        for region in item.get("regions", set())
        if region and region != "Unknown"
    }
    anomalies, anomalies_by_ip = _source_anomalies(
        domain,
        baseline,
        recent,
        baseline_regions,
        period_days=period_days,
        recent_days=recent_days,
    )
    return {
        "domain": domain,
        "period_days": period_days,
        "recent_days": recent_days,
        "regions": regions,
        "anomalies": anomalies[:10],
        "anomalies_by_ip": {ip: rows[:5] for ip, rows in anomalies_by_ip.items()},
        "summary": {
            "regions": len(regions),
            "sources": len(source_rows),
            "messages": sum(int(source.get("count") or 0) for source in source_rows),
            "anomalies": len(anomalies),
            "critical": sum(1 for row in anomalies if row["severity"] == "error"),
            "warnings": sum(1 for row in anomalies if row["severity"] == "warning"),
        },
    }


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
