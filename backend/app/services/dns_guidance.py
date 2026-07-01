"""Typed DNS lint and configuration guidance for monitored domains."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Dict, List, Optional

from app.services.bimi import BIMIResult
from app.services.dane import DANEResult
from app.services.dns_provider_detection import DNSProviderDetection
from app.services.dns_resolver import BaseDNSProvider, DomainDNSResult, extract_dmarc_policy
from app.services.mta_sts import MTAStsResult


@dataclass
class DNSGuidanceRecord:
    """Suggested DNS record shape for an operator to publish or review."""

    code: str
    record_type: str
    name: str
    value: str
    purpose: str
    priority: str = "recommended"


@dataclass
class DNSLintFinding:
    """Stable machine-readable lint finding."""

    code: str
    severity: str
    title: str
    detail: str
    action: str
    record_type: str
    record_name: str
    target_record: Optional[DNSGuidanceRecord] = None
    evidence: List[str] = field(default_factory=list)
    remediation_steps: List[str] = field(default_factory=list)


@dataclass
class DNSChangePlan:
    """Read-only DNS change plan derived from a lint finding."""

    plan_id: str
    finding_code: str
    severity: str
    operation: str
    record_type: str
    name: str
    proposed_value: Optional[str]
    current_values: List[str]
    rationale: str
    risk: str
    rollback: str
    expected_health_impact: str
    manual_steps: List[str]
    requires_approval: bool = True
    applies_automatically: bool = False
    provider_write_available: bool = False
    provider_value_required: bool = False


@dataclass
class DNSGuidanceResult:
    """Complete DNS lint and setup guidance payload for one domain."""

    domain: str
    status: str
    findings: List[DNSLintFinding]
    target_records: List[DNSGuidanceRecord]
    dns_provider: Optional[DNSProviderDetection] = None
    change_plans: List[DNSChangePlan] = field(default_factory=list)


def _today_id() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d")


def _target_records(domain: str, result: DomainDNSResult) -> List[DNSGuidanceRecord]:
    dmarc_value = result.dmarc_record or (
        f"v=DMARC1; p=none; rua=mailto:dmarc@{domain}; adkim=r; aspf=r"
    )
    spf_value = result.spf_record or "v=spf1 -all"
    dkim_selector = (result.dkim_selectors or result.selectors_checked or ["selector1"])[0]
    return [
        DNSGuidanceRecord(
            code="target_dmarc",
            record_type="TXT",
            name=f"_dmarc.{domain}",
            value=dmarc_value,
            purpose="DMARC policy discovery and aggregate report delivery.",
        ),
        DNSGuidanceRecord(
            code="target_spf",
            record_type="TXT",
            name=domain,
            value=spf_value,
            purpose=(
                "SPF sender authorization. Use -all for domains with no authorized "
                "senders, or replace with include/ip mechanisms for real senders."
            ),
        ),
        DNSGuidanceRecord(
            code="target_dkim",
            record_type="TXT",
            name=f"{dkim_selector}._domainkey.{domain}",
            value="v=DKIM1; k=rsa; p=<provider-public-key>",
            purpose="DKIM selector public key published by the sending provider.",
        ),
        DNSGuidanceRecord(
            code="target_mta_sts",
            record_type="TXT",
            name=f"_mta-sts.{domain}",
            value=f"v=STSv1; id={_today_id()}",
            purpose=(
                "MTA-STS policy discovery. Host the matching HTTPS policy at "
                f"https://mta-sts.{domain}/.well-known/mta-sts.txt."
            ),
        ),
        DNSGuidanceRecord(
            code="target_tls_rpt",
            record_type="TXT",
            name=f"_smtp._tls.{domain}",
            value=f"v=TLSRPTv1; rua=mailto:tlsrpt@{domain}",
            purpose="SMTP TLS Reporting aggregate delivery.",
        ),
        DNSGuidanceRecord(
            code="target_bimi",
            record_type="TXT",
            name=f"default._bimi.{domain}",
            value=f"v=BIMI1; l=https://{domain}/.well-known/bimi.svg; a=",
            purpose="BIMI logo discovery after DMARC enforcement is ready.",
            priority="optional",
        ),
    ]


def _target_by_code(records: List[DNSGuidanceRecord], code: str) -> DNSGuidanceRecord:
    return next(record for record in records if record.code == code)


def _dane_target_record(domain: str, result: DANEResult) -> DNSGuidanceRecord:
    mx_host = result.mx_hosts[0] if result.mx_hosts else f"<mx-host>.{domain}"
    return DNSGuidanceRecord(
        code="target_dane",
        record_type="TLSA",
        name=f"_{result.port}._tcp.{mx_host}",
        value="3 1 1 <sha256-of-current-mx-certificate-spki>",
        purpose=(
            "DANE SMTP TLSA certificate pinning for one MX host. Publish one matching TLSA "
            "record for every MX host, and only after DNSSEC is correctly signed and the TLSA "
            "value matches the live MX certificate."
        ),
        priority="optional",
    )


def _finding(
    code: str,
    severity: str,
    title: str,
    detail: str,
    action: str,
    record_type: str,
    record_name: str,
    *,
    target_record: Optional[DNSGuidanceRecord] = None,
    evidence: Optional[List[str]] = None,
    remediation_steps: Optional[List[str]] = None,
) -> DNSLintFinding:
    return DNSLintFinding(
        code=code,
        severity=severity,
        title=title,
        detail=detail,
        action=action,
        record_type=record_type,
        record_name=record_name,
        target_record=target_record,
        evidence=list(evidence or []),
        remediation_steps=list(remediation_steps or _default_remediation_steps(code)),
    )


def _default_remediation_steps(code: str) -> List[str]:
    """Return deterministic operator steps for a lint finding."""
    steps = {
        "dmarc_missing": [
            "Open the DNS zone for the affected domain.",
            "Create one TXT record at _dmarc with a monitoring policy and rua mailbox.",
            "Wait for DNS propagation, then refresh DMARQ DNS lint.",
        ],
        "spf_missing": [
            "List every platform currently allowed to send mail for this domain.",
            "Publish exactly one root TXT record beginning with v=spf1.",
            "Use ~all during rollout or -all after all senders are verified.",
        ],
        "spf_multiple_records": [
            "Copy all current SPF mechanisms into one planned SPF record.",
            "Remove duplicate or obsolete mechanisms while preserving active senders.",
            "Publish one root SPF TXT record and remove the extra SPF TXT values.",
        ],
        "spf_all_too_permissive": [
            "Confirm which senders are legitimate from DMARQ sending-source evidence.",
            "Replace +all with ~all while validating, or -all after coverage is complete.",
            "Refresh DNS lint and watch failure trends for at least one report cycle.",
        ],
        "spf_dns_lookup_limit_exceeded": [
            "Count every include, a, mx, ptr, exists, and redirect mechanism.",
            "Remove unused includes and flatten stable sender ranges with the provider.",
            "Keep the final SPF path below 10 DNS lookups before enforcement.",
        ],
        "spf_dns_lookup_limit_risk": [
            "Identify which SPF includes are still actively used.",
            "Remove duplicate or retired sender includes before adding new senders.",
            "Document the remaining lookup budget for future sender onboarding.",
        ],
        "spf_duplicate_include": [
            "Find the repeated include values in the SPF TXT record.",
            "Keep one copy of each include and remove the duplicates.",
            "Refresh DNS lint to confirm the SPF lookup budget improved.",
        ],
        "spf_void_lookup": [
            "Open each referenced include, exists, or redirect target.",
            "Remove targets that no longer publish TXT records.",
            "Ask the sender provider for the current SPF include when the sender is still active.",
        ],
        "dkim_selector_missing": [
            "Identify the sending provider that owns the selector from report evidence.",
            "Open that provider's domain authentication settings and copy the DKIM TXT or CNAME.",
            "Publish the selector record, then refresh DNS lint and confirm it resolves.",
        ],
        "dkim_selector_cname_broken": [
            "Open the DNS CNAME record shown in evidence.",
            "Compare its target with the current value in the sending provider admin page.",
            "Replace stale targets or complete provider-side domain authentication.",
        ],
        "dkim_selector_key_too_short": [
            "Check whether the sending provider supports 2048-bit DKIM keys.",
            "Generate a replacement selector instead of editing the existing key in place.",
            "Publish and validate the new selector before retiring the old selector.",
        ],
        "dkim_selector_stale": [
            "Confirm whether the selector belongs to a retired sender or old key rotation.",
            "Keep it only if a valid provider still uses it for aligned mail.",
            "Remove retired selector records after checking one or more report cycles.",
        ],
        "mta_sts_missing": [
            "Publish _mta-sts TXT with a stable id value.",
            "Host a valid HTTPS policy at the well-known mta-sts hostname.",
            "Start in testing mode and rotate the TXT id whenever the policy changes.",
        ],
        "tls_rpt_missing": [
            "Choose the TLS report mailbox or HTTPS collector endpoint.",
            "Publish one TXT record at _smtp._tls with v=TLSRPTv1 and rua.",
            "Confirm DMARQ imports TLS reports after receivers start sending them.",
        ],
        "tls_rpt_multiple_records": [
            "Merge all TLS-RPT rua destinations into one TXT record.",
            "Remove duplicate _smtp._tls TXT records.",
            "Refresh DNS lint to confirm only one TLS-RPT record remains.",
        ],
        "tls_rpt_rua_missing": [
            "Choose where SMTP TLS reports should be delivered.",
            "Add rua=mailto:... or rua=https://... to the TLS-RPT TXT value.",
            "Refresh DMARQ after DNS propagation.",
        ],
        "bimi_missing": [
            "Complete DMARC enforcement first.",
            "Publish a default._bimi TXT record with an HTTPS SVG logo URL.",
            "Add a certificate URL if the mailbox providers you care about require it.",
        ],
        "dane_missing": [
            "Confirm that the domain's DNS zone is signed and validating with DNSSEC.",
            "For each MX host, derive the intended TLSA value from the live SMTP certificate.",
            "Publish TLSA records under _25._tcp.<mx-host> and refresh DMARQ DNS lint.",
        ],
        "dane_review": [
            "Review every TLSA record shown in evidence for the affected MX hosts.",
            "Compare the TLSA selector and hash with the current SMTP TLS certificate.",
            "Rotate TLSA values in the same change window as certificate changes.",
        ],
        "mail_service_record_missing": [
            "Open the sender-domain authentication page in the mail service.",
            "Copy the required DNS record into the authoritative DNS provider.",
            "Refresh DMARQ DNS lint and then re-check verification in the mail service.",
        ],
        "mail_service_record_conflict": [
            "Compare the existing DNS value with the value required by the mail service.",
            "Confirm no other active sender depends on the current value.",
            "Update the record or split senders onto provider-supported hostnames.",
        ],
    }
    return steps.get(
        code,
        [
            "Open the linked DNS or report evidence in DMARQ.",
            "Make the smallest provider-side change that addresses the finding.",
            "Refresh DNS lint and monitor the next aggregate report cycle.",
        ],
    )


def _classify_dmarc_warning(message: str) -> str:
    lowered = message.lower()
    if "external rua destination" in lowered:
        return "dmarc_external_rua_unauthorized"
    if "external ruf destination" in lowered:
        return "dmarc_external_ruf_unauthorized"
    if "unsupported policy value" in lowered:
        return "dmarc_policy_value_invalid"
    if "adkim" in lowered or "aspf" in lowered:
        return "dmarc_alignment_value_invalid"
    if "fo tag" in lowered:
        return "dmarc_failure_option_invalid"
    if "neither a valid p tag nor a rua" in lowered:
        return "dmarc_policy_or_reporting_missing"
    return "dmarc_lint_warning"


def _dmarc_findings(
    domain: str, result: DomainDNSResult, targets: List[DNSGuidanceRecord]
) -> List[DNSLintFinding]:
    findings: List[DNSLintFinding] = []
    target = _target_by_code(targets, "target_dmarc")
    if not result.dmarc:
        findings.append(
            _finding(
                "dmarc_missing",
                "error",
                "DMARC record is missing",
                "No valid DMARC policy record was discovered for this domain.",
                "Publish a DMARC TXT record in monitoring mode before tightening policy.",
                "TXT",
                target.name,
                target_record=target,
            )
        )
    for warning in result.dmarc_warnings:
        findings.append(
            _finding(
                _classify_dmarc_warning(warning),
                "warning",
                "DMARC record needs review",
                warning,
                "Repair the DMARC tag or supporting authorization record, then refresh lint.",
                "TXT",
                target.name,
                target_record=target,
                evidence=[result.dmarc_record or ""],
            )
        )
    for suggestion in result.dmarc_suggestions:
        findings.append(
            _finding(
                "dmarc_suggestion",
                "info",
                "DMARC setup can be improved",
                suggestion,
                "Review the suggested DMARC target record.",
                "TXT",
                target.name,
                target_record=target,
                evidence=[result.dmarc_record or ""],
            )
        )
    if extract_dmarc_policy(result.dmarc_record) == "none":
        findings.append(
            _finding(
                "dmarc_monitoring_policy",
                "info",
                "DMARC is in monitoring mode",
                "The current policy is p=none.",
                "Use report evidence before planning quarantine or reject.",
                "TXT",
                target.name,
                target_record=target,
                evidence=[result.dmarc_record or ""],
            )
        )
    return findings


def _spf_terms(record: Optional[str]) -> List[str]:
    if not record:
        return []
    return [part.strip() for part in record.split() if part.strip()]


def _spf_dns_lookup_terms(terms: List[str]) -> List[str]:
    return [
        term
        for term in terms
        if term.startswith(("include:", "a", "mx", "ptr", "exists:", "redirect="))
    ]


def _spf_include_domain(term: str) -> Optional[str]:
    if term.startswith("include:"):
        return term.split(":", 1)[1].strip().strip(".").lower() or None
    return None


def _spf_lookup_domain(term: str) -> Optional[str]:
    if term.startswith(("include:", "exists:")):
        return term.split(":", 1)[1].strip().strip(".").lower() or None
    if term.startswith("redirect="):
        return term.split("=", 1)[1].strip().strip(".").lower() or None
    return None


def _spf_all_policy_findings(
    terms: List[str], target: DNSGuidanceRecord, record: Optional[str]
) -> List[DNSLintFinding]:
    findings: List[DNSLintFinding] = []
    all_terms = [term for term in terms if term.endswith("all")]
    if not all_terms:
        findings.append(
            _finding(
                "spf_all_missing",
                "warning",
                "SPF all mechanism is missing",
                "The SPF record does not end with an explicit all policy.",
                "Choose -all after authorizing all senders, or ~all while still validating.",
                "TXT",
                target.name,
                target_record=target,
                evidence=[record or ""],
            )
        )
    elif all_terms[-1].startswith("+") or all_terms[-1] == "all":
        findings.append(
            _finding(
                "spf_all_too_permissive",
                "error",
                "SPF all mechanism is too permissive",
                f"The SPF record uses {all_terms[-1]}, which authorizes every sender.",
                "Replace +all with ~all during rollout or -all once sender coverage is complete.",
                "TXT",
                target.name,
                target_record=target,
                evidence=[record or ""],
            )
        )
    elif all_terms[-1].startswith("?"):
        findings.append(
            _finding(
                "spf_all_neutral",
                "warning",
                "SPF all mechanism is neutral",
                "The SPF record ends with ?all, which provides weak sender guidance.",
                "Use ~all while validating or -all after all senders are authorized.",
                "TXT",
                target.name,
                target_record=target,
                evidence=[record or ""],
            )
        )
    return findings


def _spf_lookup_budget_findings(
    dns_lookup_terms: List[str], target: DNSGuidanceRecord
) -> List[DNSLintFinding]:
    findings: List[DNSLintFinding] = []
    if len(dns_lookup_terms) > 10:
        findings.append(
            _finding(
                "spf_dns_lookup_limit_exceeded",
                "error",
                "SPF DNS lookup budget is exceeded",
                (
                    "The SPF record uses "
                    f"{len(dns_lookup_terms)} DNS-lookup mechanisms; SPF evaluation "
                    "fails after 10."
                ),
                "Flatten or remove unused mechanisms before publishing the final SPF record.",
                "TXT",
                target.name,
                target_record=target,
                evidence=dns_lookup_terms,
            )
        )
    if len(dns_lookup_terms) >= 8:
        findings.append(
            _finding(
                "spf_dns_lookup_limit_risk",
                "warning",
                "SPF DNS lookup budget is exhausted or nearly exhausted",
                (
                    "The SPF record uses "
                    f"{len(dns_lookup_terms)} of 10 available DNS-lookup mechanisms."
                ),
                "Remove unused includes or flatten stable sender ranges before adding new senders.",
                "TXT",
                target.name,
                target_record=target,
                evidence=dns_lookup_terms,
            )
        )
    return findings


def _spf_duplicate_include_findings(
    terms: List[str], target: DNSGuidanceRecord
) -> List[DNSLintFinding]:
    include_domains = [
        include_domain for term in terms if (include_domain := _spf_include_domain(term))
    ]
    duplicate_includes = sorted(
        include_domain for include_domain, count in Counter(include_domains).items() if count > 1
    )
    if not duplicate_includes:
        return []
    return [
        _finding(
            "spf_duplicate_include",
            "warning",
            "SPF record repeats include mechanisms",
            "The same SPF include appears more than once and wastes lookup budget.",
            "Remove duplicate include mechanisms before adding more senders.",
            "TXT",
            target.name,
            target_record=target,
            evidence=duplicate_includes,
        )
    ]


async def _spf_void_lookup_findings(
    provider: BaseDNSProvider,
    dns_lookup_terms: List[str],
    target: DNSGuidanceRecord,
) -> List[DNSLintFinding]:
    void_lookup_terms: List[str] = []
    for term in dns_lookup_terms:
        lookup_domain = _spf_lookup_domain(term)
        if not lookup_domain:
            continue
        try:
            await provider.lookup_txt(lookup_domain)
        except LookupError:
            void_lookup_terms.append(term)
    if not void_lookup_terms:
        return []
    return [
        _finding(
            "spf_void_lookup",
            "warning",
            "SPF record references empty lookup targets",
            "One or more SPF include, exists, or redirect targets did not return TXT records.",
            "Remove stale SPF references or repair the referenced sender-domain SPF records.",
            "TXT",
            target.name,
            target_record=target,
            evidence=void_lookup_terms,
        )
    ]


async def _spf_findings(
    domain: str,
    provider: BaseDNSProvider,
    result: DomainDNSResult,
    targets: List[DNSGuidanceRecord],
) -> List[DNSLintFinding]:
    findings: List[DNSLintFinding] = []
    target = _target_by_code(targets, "target_spf")
    if not result.spf:
        return [
            _finding(
                "spf_missing",
                "warning",
                "SPF record is missing",
                "No SPF TXT record was found at the domain root.",
                "Publish one SPF TXT record that matches the domain's authorized senders.",
                "TXT",
                target.name,
                target_record=target,
            )
        ]

    try:
        root_records = await provider.lookup_txt(domain)
    except LookupError:
        root_records = []
    spf_records = [record for record in root_records if record.lower().startswith("v=spf1")]
    if len(spf_records) > 1:
        findings.append(
            _finding(
                "spf_multiple_records",
                "error",
                "Multiple SPF records found",
                "SPF requires exactly one SPF TXT record at the domain root.",
                "Merge the mechanisms into a single v=spf1 record.",
                "TXT",
                target.name,
                target_record=target,
                evidence=spf_records,
            )
        )

    terms = _spf_terms(result.spf_record)
    findings.extend(_spf_all_policy_findings(terms, target, result.spf_record))
    dns_lookup_terms = _spf_dns_lookup_terms(terms)
    findings.extend(_spf_lookup_budget_findings(dns_lookup_terms, target))
    findings.extend(_spf_duplicate_include_findings(terms, target))
    findings.extend(await _spf_void_lookup_findings(provider, dns_lookup_terms, target))
    return findings


def _dkim_record_tags(record: str) -> Dict[str, str]:
    return {
        part.split("=", 1)[0].strip().lower(): part.split("=", 1)[1].strip()
        for part in record.split(";")
        if "=" in part
    }


def _dkim_public_key_value(record: str) -> str:
    tags = _dkim_record_tags(record)
    return "".join((tags.get("p") or "").split())


def _dkim_record_is_too_short(record: str) -> bool:
    tags = _dkim_record_tags(record)
    key_type = (tags.get("k") or "rsa").lower()
    public_key = _dkim_public_key_value(record)
    return key_type == "rsa" and bool(public_key) and len(public_key) < 216


async def _dkim_selector_record(
    provider: BaseDNSProvider, selector: str, domain: str
) -> Optional[str]:
    try:
        records = await provider.lookup_txt(f"{selector}._domainkey.{domain}")
    except LookupError:
        return None
    for record in records:
        lowered = record.lower()
        if "v=dkim1" in lowered or "p=" in lowered:
            return record
    return None


def _dkim_record_findings(
    selector: str,
    record_name: str,
    record: str,
    target: DNSGuidanceRecord,
    *,
    has_report_evidence: bool,
    observed_selector_set: set[str],
) -> List[DNSLintFinding]:
    findings: List[DNSLintFinding] = []
    if _dkim_record_is_too_short(record):
        findings.append(
            _finding(
                "dkim_selector_key_too_short",
                "warning",
                "DKIM selector key is short",
                (
                    f"Selector {selector} resolves, but its RSA public key looks "
                    "shorter than a normal 1024-bit key."
                ),
                (
                    "Rotate this selector to a provider-generated 2048-bit DKIM key "
                    "where supported."
                ),
                "TXT",
                record_name,
                target_record=target,
                evidence=[record],
            )
        )
    if has_report_evidence and selector not in observed_selector_set:
        findings.append(
            _finding(
                "dkim_selector_stale",
                "info",
                "DKIM selector has no recent report traffic",
                (
                    f"Selector {selector} resolves in DNS but was not seen in recent "
                    "DMARC aggregate report data."
                ),
                (
                    "Confirm whether this sender is still active before keeping the "
                    "selector published."
                ),
                "TXT",
                record_name,
                target_record=target,
                evidence=[record],
            )
        )
    return findings


async def _dkim_cname_target(provider: BaseDNSProvider, record_name: str) -> Optional[str]:
    cname_lookup = getattr(provider, "lookup_cname", None)
    cname_target = await cname_lookup(record_name) if callable(cname_lookup) else None
    return cname_target if isinstance(cname_target, str) else None


async def _dkim_cname_finding(
    provider: BaseDNSProvider,
    selector: str,
    record_name: str,
    target: DNSGuidanceRecord,
) -> Optional[DNSLintFinding]:
    cname_target = await _dkim_cname_target(provider, record_name)
    if not cname_target:
        return None
    try:
        cname_records = await provider.lookup_txt(cname_target)
    except LookupError:
        cname_records = []
    if any(
        "v=dkim1" in cname_record.lower() or "p=" in cname_record.lower()
        for cname_record in cname_records
    ):
        return None
    return _finding(
        "dkim_selector_cname_broken",
        "warning",
        "DKIM selector CNAME target is broken",
        (
            f"Selector {selector} points to {cname_target}, but the target "
            "does not expose a DKIM TXT record."
        ),
        (
            "Re-copy the provider DKIM CNAME target or complete provider-side "
            "domain authentication."
        ),
        "CNAME",
        record_name,
        target_record=target,
        evidence=[f"{record_name} -> {cname_target}"],
    )


def _dkim_missing_finding(
    selector: str, record_name: str, target: DNSGuidanceRecord
) -> DNSLintFinding:
    return _finding(
        "dkim_selector_missing",
        "warning",
        "DKIM selector is missing",
        f"Selector {selector} was observed or configured but did not resolve.",
        "Publish the provider's DKIM TXT or CNAME record for this selector.",
        "TXT",
        record_name,
        target_record=target,
    )


async def _dkim_selector_findings(
    provider: BaseDNSProvider,
    domain: str,
    result: DomainDNSResult,
    target: DNSGuidanceRecord,
    monitored_selectors: List[str],
    observed_selectors: List[str],
) -> List[DNSLintFinding]:
    findings: List[DNSLintFinding] = []
    resolved_selectors = set(result.dkim_selectors or [])
    observed_selector_set = set(observed_selectors or [])
    has_report_evidence = bool(observed_selector_set)

    for selector in monitored_selectors:
        record_name = f"{selector}._domainkey.{domain}"
        record = await _dkim_selector_record(provider, selector, domain)
        if record:
            findings.extend(
                _dkim_record_findings(
                    selector,
                    record_name,
                    record,
                    target,
                    has_report_evidence=has_report_evidence,
                    observed_selector_set=observed_selector_set,
                )
            )
            continue

        cname_finding = await _dkim_cname_finding(provider, selector, record_name, target)
        if cname_finding:
            findings.append(cname_finding)
            continue

        if selector not in resolved_selectors:
            findings.append(_dkim_missing_finding(selector, record_name, target))
    return findings


async def _dkim_findings(
    provider: BaseDNSProvider,
    domain: str,
    result: DomainDNSResult,
    targets: List[DNSGuidanceRecord],
    *,
    monitored_selectors: Optional[List[str]] = None,
    observed_selectors: Optional[List[str]] = None,
) -> List[DNSLintFinding]:
    target = _target_by_code(targets, "target_dkim")
    selectors_for_detail = list(
        dict.fromkeys(monitored_selectors or result.selectors_checked or [])
    )
    if result.dkim and selectors_for_detail:
        return await _dkim_selector_findings(
            provider,
            domain,
            result,
            target,
            selectors_for_detail,
            list(dict.fromkeys(observed_selectors or [])),
        )
    if result.dkim:
        return []
    checked = ", ".join(selectors_for_detail)
    detail = "No DKIM selector resolved for configured, observed, or common selectors."
    if checked:
        detail = f"{detail} Checked selectors: {checked}."
    return [
        _finding(
            "dkim_selector_missing",
            "warning",
            "DKIM selector is missing",
            detail,
            "Add the sending provider's selector in DMARQ and publish its DKIM TXT record.",
            "TXT",
            target.name,
            target_record=target,
        )
    ]


def _mta_sts_findings(
    result: MTAStsResult, targets: List[DNSGuidanceRecord]
) -> List[DNSLintFinding]:
    if result.status == "pass" and not result.warnings:
        return []
    target = _target_by_code(targets, "target_mta_sts")
    severity = "warning" if result.status == "pass" else "info"
    detail = "; ".join(result.warnings or result.errors or ["MTA-STS is not configured."])
    if result.status == "pass":
        recommendation = "Move the policy to mode: enforce once MX coverage is confirmed."
    elif result.dns_record and result.policy_text is None:
        recommendation = (
            f"Make {result.policy_url} reachable over HTTPS with a valid policy file, "
            "then rotate the _mta-sts TXT id when the policy changes."
        )
    elif result.dns_record:
        recommendation = (
            "Fix the MTA-STS policy file so it includes version: STSv1, mode, "
            "max_age, and at least one mx entry."
        )
    else:
        recommendation = "Publish _mta-sts TXT and validate the HTTPS policy before enforcing."
    return [
        _finding(
            "mta_sts_review" if result.status == "pass" else "mta_sts_missing",
            severity,
            "MTA-STS setup needs review" if result.status == "pass" else "MTA-STS is not ready",
            detail,
            recommendation,
            "TXT",
            target.name,
            target_record=target,
            evidence=[result.dns_record or ""],
        )
    ]


async def _tls_rpt_findings(
    domain: str, provider: BaseDNSProvider, targets: List[DNSGuidanceRecord]
) -> List[DNSLintFinding]:
    target = _target_by_code(targets, "target_tls_rpt")
    try:
        records = await provider.lookup_txt(target.name)
    except LookupError:
        records = []
    tls_rpt_records = [record for record in records if record.lower().startswith("v=tlsrptv1")]
    if not tls_rpt_records:
        return [
            _finding(
                "tls_rpt_missing",
                "info",
                "TLS-RPT record is missing",
                "No SMTP TLS Reporting TXT record was found.",
                "Publish a TLS-RPT record so DMARQ can ingest aggregate TLS delivery reports.",
                "TXT",
                target.name,
                target_record=target,
            )
        ]
    if len(tls_rpt_records) > 1:
        return [
            _finding(
                "tls_rpt_multiple_records",
                "warning",
                "Multiple TLS-RPT records found",
                "SMTP TLS Reporting expects one TXT record at _smtp._tls.",
                "Merge TLS-RPT reporting URIs into one record.",
                "TXT",
                target.name,
                target_record=target,
                evidence=tls_rpt_records,
            )
        ]
    if "rua=" not in tls_rpt_records[0].lower():
        return [
            _finding(
                "tls_rpt_rua_missing",
                "warning",
                "TLS-RPT rua is missing",
                "The TLS-RPT TXT record does not contain a reporting URI.",
                "Add rua=mailto:... to deliver TLS reports to DMARQ.",
                "TXT",
                target.name,
                target_record=target,
                evidence=tls_rpt_records,
            )
        ]
    return []


def _bimi_findings(
    result: BIMIResult, dmarc_policy: Optional[str], targets: List[DNSGuidanceRecord]
) -> List[DNSLintFinding]:
    target = _target_by_code(targets, "target_bimi")
    findings: List[DNSLintFinding] = []
    if dmarc_policy not in {"quarantine", "reject"}:
        findings.append(
            _finding(
                "bimi_dmarc_not_enforced",
                "info",
                "BIMI is waiting on DMARC enforcement",
                "BIMI readiness requires DMARC policy quarantine or reject.",
                "Treat BIMI as optional until DMARC enforcement is stable.",
                "TXT",
                target.name,
                target_record=target,
            )
        )
    if result.status == "pass" and not result.warnings:
        return findings
    detail = "; ".join(result.warnings or result.errors or ["No BIMI record is published."])
    findings.append(
        _finding(
            "bimi_review" if result.status == "pass" else "bimi_missing",
            "info",
            "BIMI setup needs review" if result.status == "pass" else "BIMI record is missing",
            detail,
            "Publish BIMI only after DMARC enforcement prerequisites are met.",
            "TXT",
            target.name,
            target_record=target,
            evidence=[result.dns_record or ""],
        )
    )
    return findings


def _actionable_dane_warnings(result: DANEResult) -> List[str]:
    return [
        warning
        for warning in result.warnings
        if not warning.startswith(
            "DMARQ validates TLSA syntax and MX coverage, but does not yet validate DNSSEC chains"
        )
    ]


def _dane_findings(result: DANEResult, targets: List[DNSGuidanceRecord]) -> List[DNSLintFinding]:
    target = _target_by_code(targets, "target_dane")
    warnings = _actionable_dane_warnings(result)
    if result.status == "pass" and not warnings:
        return []
    detail = "; ".join(warnings or result.errors or ["No DANE/TLSA records were found."])
    evidence = [record.record for record in result.records] or result.mx_hosts
    if result.status == "fail":
        return [
            _finding(
                "dane_missing",
                "info",
                "DANE TLSA records are not ready",
                detail,
                "Treat DANE as optional unless you operate DNSSEC-signed MX infrastructure.",
                "TLSA",
                target.name,
                target_record=target,
                evidence=evidence,
            )
        ]
    return [
        _finding(
            "dane_review",
            "warning",
            "DANE TLSA setup needs review",
            detail,
            "Review TLSA syntax, MX coverage, DNSSEC validation, and certificate rotation handling.",
            "TLSA",
            target.name,
            target_record=target,
            evidence=evidence,
        )
    ]


def _normalize_dns_value(value: str) -> str:
    return " ".join(str(value or "").strip().strip(".").split()).lower()


async def _current_mail_service_values(
    provider: BaseDNSProvider, record_type: str, name: str
) -> List[str]:
    if record_type == "TXT":
        try:
            return await provider.lookup_txt(name)
        except LookupError:
            return []
    if record_type == "CNAME":
        cname_lookup = getattr(provider, "lookup_cname", None)
        if not callable(cname_lookup):
            return []
        value = await cname_lookup(name)
        return [value] if isinstance(value, str) and value else []
    return []


async def _mail_service_dns_findings(
    provider: BaseDNSProvider,
    mail_service_records: List[Dict[str, str]],
) -> List[DNSLintFinding]:
    findings: List[DNSLintFinding] = []
    seen: set[tuple[str, str, str]] = set()
    for item in mail_service_records:
        record_type = str(item.get("record_type") or "").strip().upper()
        name = str(item.get("name") or "").strip().strip(".")
        value = str(item.get("value") or "").strip().strip(".")
        provider_name = str(item.get("provider_name") or item.get("provider") or "Mail service")
        purpose = str(item.get("purpose") or "sender verification").replace("_", " ")
        if record_type not in {"TXT", "CNAME"} or not name or not value:
            continue
        dedupe_key = (record_type, name.lower(), value)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)

        current_values = await _current_mail_service_values(provider, record_type, name)
        normalized_expected = _normalize_dns_value(value)
        normalized_current = {_normalize_dns_value(current) for current in current_values}
        if normalized_expected in normalized_current:
            continue

        target = DNSGuidanceRecord(
            code=f"target_mail_service_{provider_name.lower()}_{purpose.replace(' ', '_')}",
            record_type=record_type,
            name=name,
            value=value,
            purpose=f"{provider_name} {purpose} for authenticated sender setup.",
        )
        if current_values:
            findings.append(
                _finding(
                    "mail_service_record_conflict",
                    "warning",
                    f"{provider_name} DNS record value needs review",
                    (
                        f"{provider_name} requires a {record_type} record at {name}, "
                        "but DNS currently returns a different value."
                    ),
                    "Review the sender-domain requirement and update DNS after approval.",
                    record_type,
                    name,
                    target_record=target,
                    evidence=current_values,
                )
            )
            continue
        findings.append(
            _finding(
                "mail_service_record_missing",
                "warning",
                f"{provider_name} DNS record is missing",
                f"{provider_name} requires a {record_type} record at {name} for {purpose}.",
                "Publish the required sender-domain DNS record after approval.",
                record_type,
                name,
                target_record=target,
            )
        )
    return findings


def _status(findings: List[DNSLintFinding]) -> str:
    severities = {finding.severity for finding in findings}
    if "error" in severities:
        return "critical"
    if "warning" in severities:
        return "attention"
    return "ready"


def _plan_id(finding: DNSLintFinding) -> str:
    raw = f"{finding.code}-{finding.record_name}-{finding.record_type}".lower()
    return "".join(character if character.isalnum() else "-" for character in raw).strip("-")


def _operation_for_finding(finding: DNSLintFinding) -> str:
    code = finding.code
    if code.endswith("_missing") or code in {"dmarc_missing", "spf_missing"}:
        return "create"
    if code in {"dkim_selector_stale"}:
        return "review-remove"
    if code in {"dkim_selector_key_too_short"}:
        return "rotate"
    if code in {"tls_rpt_multiple_records", "spf_multiple_records"}:
        return "consolidate"
    if code in {"bimi_dmarc_not_enforced"}:
        return "defer"
    return "update"


def _provider_value_required(finding: DNSLintFinding) -> bool:
    if finding.code == "dkim_selector_stale":
        return False
    proposed = (finding.target_record.value if finding.target_record else "") or ""
    return "<" in proposed or finding.code in {
        "dkim_selector_missing",
        "dkim_selector_cname_broken",
        "dkim_selector_key_too_short",
    }


def _proposed_value(finding: DNSLintFinding) -> Optional[str]:
    if finding.code == "dkim_selector_cname_broken":
        return "<provider-current-dkim-cname-target>"
    if finding.code == "dkim_selector_stale":
        return None
    if finding.target_record:
        return finding.target_record.value
    return None


def _risk_for_finding(finding: DNSLintFinding) -> str:
    risks = {
        "dmarc_missing": (
            "Low delivery risk when starting with p=none; incorrect rua values can prevent "
            "DMARQ from receiving reports."
        ),
        "dmarc_monitoring_policy": (
            "Enforcement changes can reject legitimate mail if sender alignment is not ready."
        ),
        "spf_missing": "Medium risk if legitimate senders are omitted from the SPF record.",
        "spf_multiple_records": (
            "Medium risk: merging records incorrectly can remove an active sender."
        ),
        "spf_all_too_permissive": (
            "Low immediate delivery risk, but tightening to -all before sender coverage is "
            "complete can break forwarding or third-party senders."
        ),
        "dkim_selector_missing": (
            "Low DNS risk, but the value must come from the sending provider that owns "
            "the selector."
        ),
        "dkim_selector_cname_broken": (
            "Medium risk: replacing a CNAME with the wrong provider target keeps DKIM failing."
        ),
        "dkim_selector_key_too_short": (
            "Medium risk: rotate with a new selector before retiring the old one."
        ),
        "dkim_selector_stale": (
            "Medium risk: removing a selector still used by a sender breaks DKIM for that sender."
        ),
        "mta_sts_missing": (
            "Low risk in testing mode; enforce only after confirming all MX hosts support TLS."
        ),
        "tls_rpt_missing": "Low risk: TLS-RPT only controls report delivery.",
        "bimi_missing": "Low mail-flow risk; BIMI is a brand/readiness feature.",
        "dane_missing": (
            "Medium operational risk if enabled incorrectly; DANE depends on DNSSEC and exact "
            "TLSA/certificate lifecycle management."
        ),
        "dane_review": (
            "Medium operational risk: stale or malformed TLSA records can cause strict receivers "
            "to reject SMTP TLS delivery."
        ),
        "mail_service_record_missing": (
            "Low DNS risk when copied exactly; mail-service verification remains pending until "
            "DNS propagates."
        ),
        "mail_service_record_conflict": (
            "Medium risk: replacing a record that another active sender depends on can break "
            "that sender's authentication."
        ),
    }
    return risks.get(
        finding.code,
        "Review current evidence before changing DNS; publish during a controlled change window.",
    )


def _rollback_for_plan(finding: DNSLintFinding, operation: str) -> str:
    if operation == "create":
        return f"Delete the newly created {finding.record_type} record at {finding.record_name}."
    if operation == "review-remove":
        return (
            "Restore the removed record value from DNS provider history if later reports show "
            "the selector is still active."
        )
    if finding.evidence:
        return "Restore the previous value captured in evidence if authentication regresses."
    return "Revert to the previous DNS-provider version or zone-file backup."


def _expected_health_impact(finding: DNSLintFinding) -> str:
    if finding.severity == "error":
        return "Expected to remove a critical DNS-health finding after propagation."
    if finding.severity == "warning":
        return "Expected to reduce DNS-health warnings after propagation."
    return "Expected to improve hygiene and reduce future action-plan noise."


def _manual_steps_for_plan(finding: DNSLintFinding, operation: str) -> List[str]:
    steps = [
        "Open the authoritative DNS provider for this domain.",
        f"Find or create the {finding.record_type} record named {finding.record_name}.",
    ]
    proposed = _proposed_value(finding)
    if operation == "review-remove":
        steps.append("Confirm at least one recent report cycle shows no traffic for this selector.")
        steps.append("Remove the stale selector only after sender ownership is confirmed.")
    elif proposed:
        steps.append(f"Set the record value to: {proposed}")
    else:
        steps.append("Follow the finding remediation steps to choose the final DNS value.")
    steps.extend(finding.remediation_steps)
    steps.append("Refresh DMARQ DNS lint after DNS propagation.")
    return list(dict.fromkeys(steps))


def build_dns_change_plans(findings: List[DNSLintFinding]) -> List[DNSChangePlan]:
    """Create read-only operator change plans from DNS lint findings."""
    plans: List[DNSChangePlan] = []
    for finding in findings:
        operation = _operation_for_finding(finding)
        proposed_value = _proposed_value(finding)
        if operation == "defer":
            continue
        plans.append(
            DNSChangePlan(
                plan_id=_plan_id(finding),
                finding_code=finding.code,
                severity=finding.severity,
                operation=operation,
                record_type=finding.record_type,
                name=finding.record_name,
                proposed_value=proposed_value,
                current_values=list(finding.evidence),
                rationale=finding.action,
                risk=_risk_for_finding(finding),
                rollback=_rollback_for_plan(finding, operation),
                expected_health_impact=_expected_health_impact(finding),
                manual_steps=_manual_steps_for_plan(finding, operation),
                provider_value_required=_provider_value_required(finding),
            )
        )
    return plans


async def build_dns_guidance(
    domain: str,
    provider: BaseDNSProvider,
    result: DomainDNSResult,
    mta_sts: MTAStsResult,
    bimi: BIMIResult,
    dane: Optional[DANEResult] = None,
    *,
    monitored_selectors: Optional[List[str]] = None,
    observed_selectors: Optional[List[str]] = None,
    mail_service_records: Optional[List[Dict[str, str]]] = None,
) -> DNSGuidanceResult:
    """Build typed DNS lint findings and target records for a domain."""
    normalized_domain = domain.strip().strip(".").lower()
    dane_result = dane or DANEResult(errors=["No DANE/TLSA context was evaluated."])
    targets = _target_records(normalized_domain, result)
    targets.append(_dane_target_record(normalized_domain, dane_result))
    findings: List[DNSLintFinding] = []
    findings.extend(_dmarc_findings(normalized_domain, result, targets))
    findings.extend(await _spf_findings(normalized_domain, provider, result, targets))
    findings.extend(
        await _dkim_findings(
            provider,
            normalized_domain,
            result,
            targets,
            monitored_selectors=monitored_selectors,
            observed_selectors=observed_selectors,
        )
    )
    findings.extend(_mta_sts_findings(mta_sts, targets))
    findings.extend(await _tls_rpt_findings(normalized_domain, provider, targets))
    findings.extend(_bimi_findings(bimi, extract_dmarc_policy(result.dmarc_record), targets))
    findings.extend(_dane_findings(dane_result, targets))
    findings.extend(await _mail_service_dns_findings(provider, mail_service_records or []))
    return DNSGuidanceResult(
        domain=normalized_domain,
        status=_status(findings),
        findings=findings,
        target_records=targets,
        dns_provider=result.dns_provider,
        change_plans=build_dns_change_plans(findings),
    )
