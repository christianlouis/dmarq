import pytest

from app.services.bimi import BIMIResult
from app.services.dane import DANEResult, TLSARecord, TLSASuggestion
from app.services.dns_guidance import (
    DNSGuidanceRecord,
    DNSLintFinding,
    MailAuthSetupDefaults,
    _plan_changes,
    build_dns_change_plans,
    build_dns_guidance,
)
from app.services.dns_resolver import BaseDNSProvider, DomainDNSResult
from app.services.mta_sts import MTAStsResult


class FakeDNSProvider(BaseDNSProvider):
    def __init__(self, records: dict[str, list[str]]):
        self._records = records
        self._cnames: dict[str, str] = {}

    async def lookup_txt(self, name: str) -> list[str]:
        if name in self._records:
            return self._records[name]
        raise LookupError(f"NXDOMAIN: {name}")

    async def lookup_cname(self, name: str) -> str | None:
        return self._cnames.get(name)


@pytest.mark.asyncio
async def test_build_dns_guidance_returns_typed_findings_and_targets():
    provider = FakeDNSProvider({})
    dns = DomainDNSResult(
        dmarc=False,
        spf=False,
        dkim=False,
        selectors_checked=["selector1"],
    )
    mta_sts = MTAStsResult(errors=["No _mta-sts TXT record was found."])
    bimi = BIMIResult(errors=["No BIMI TXT record was found at the selector."])

    guidance = await build_dns_guidance("example.com", provider, dns, mta_sts, bimi)

    codes = {finding.code for finding in guidance.findings}
    assert guidance.status == "critical"
    assert {
        "dmarc_missing",
        "spf_missing",
        "dkim_selector_missing",
        "mta_sts_missing",
        "tls_rpt_missing",
        "bimi_missing",
    }.issubset(codes)
    assert {record.code for record in guidance.target_records} == {
        "target_dmarc",
        "target_spf",
        "target_dkim",
        "target_mta_sts",
        "target_tls_rpt",
        "target_bimi",
        "target_dane",
    }
    plan = next(plan for plan in guidance.change_plans if plan.finding_code == "dmarc_missing")
    assert plan.operation == "create"
    assert plan.record_type == "TXT"
    assert plan.name == "_dmarc.example.com"
    assert plan.proposed_value.startswith("v=DMARC1")
    assert plan.requires_approval is True
    assert plan.applies_automatically is False
    assert plan.provider_write_available is False
    assert plan.rollback.startswith("Delete the newly created")


@pytest.mark.asyncio
async def test_cached_guidance_keeps_proven_core_findings_without_dns_queries():
    """Cached page reads retain stored SPF/DKIM evidence without resolving DNS."""
    provider = FakeDNSProvider({})
    dns = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        spf=False,
        dkim=False,
        selectors_checked=["selector1"],
    )

    guidance = await build_dns_guidance(
        "example.com",
        provider,
        dns,
        MTAStsResult(status="pending"),
        BIMIResult(status="pending"),
        allow_live=False,
    )

    codes = {finding.code for finding in guidance.findings}
    assert {"spf_missing", "dkim_selector_missing"}.issubset(codes)
    assert "mta_sts_missing" not in codes
    assert "bimi_missing" not in codes


@pytest.mark.asyncio
async def test_build_dns_guidance_uses_configured_mail_auth_defaults():
    provider = FakeDNSProvider({})
    dns = DomainDNSResult(
        dmarc=False,
        spf=False,
        dkim=False,
        selectors_checked=["selector1"],
    )

    guidance = await build_dns_guidance(
        "example.com",
        provider,
        dns,
        MTAStsResult(status="pass"),
        BIMIResult(status="pass"),
        setup_defaults=MailAuthSetupDefaults(
            report_mailbox="dmarc-reports@central.example",
            tls_report_mailbox="tls-reports@central.example",
            policy="quarantine",
            percentage=50,
            adkim="s",
            aspf="s",
        ),
    )

    targets = {record.code: record for record in guidance.target_records}
    assert targets["target_dmarc"].value == (
        "v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@central.example; "
        "pct=50; adkim=s; aspf=s"
    )
    assert targets["target_tls_rpt"].value == "v=TLSRPTv1; rua=mailto:tls-reports@central.example"


@pytest.mark.asyncio
async def test_existing_dmarc_record_gets_additive_report_destination_plan_first():
    provider = FakeDNSProvider({})
    current = (
        "v=DMARC1; p=reject; rua=mailto:existing@example.net; "
        "ruf=mailto:forensic@example.net; aspf=s"
    )
    dns = DomainDNSResult(
        dmarc=True,
        dmarc_record=current,
        spf=True,
        spf_record="v=spf1 -all",
        dkim=True,
        dkim_selectors=["selector1"],
    )

    guidance = await build_dns_guidance(
        "example.com",
        provider,
        dns,
        MTAStsResult(status="pass"),
        BIMIResult(status="pass"),
        setup_defaults=MailAuthSetupDefaults(report_mailbox="reports@example.com"),
    )

    plan = guidance.change_plans[0]
    assert plan.finding_code == "dmarc_report_destination_missing"
    assert plan.operation == "update"
    assert plan.current_values == [current]
    assert plan.proposed_value == (
        "v=DMARC1; p=reject; "
        "rua=mailto:existing@example.net,mailto:reports@example.com; "
        "ruf=mailto:forensic@example.net; aspf=s"
    )
    assert plan.changes == [
        "Change rua from mailto:existing@example.net to "
        "mailto:existing@example.net,mailto:reports@example.com."
    ]
    assert "p=reject" in plan.proposed_value
    assert "ruf=mailto:forensic@example.net" in plan.proposed_value


@pytest.mark.asyncio
async def test_existing_dmarc_report_destination_is_not_duplicated():
    provider = FakeDNSProvider({})
    current = "v=DMARC1; p=none; rua=mailto:reports@example.com!10m"
    dns = DomainDNSResult(dmarc=True, dmarc_record=current, spf=True)

    guidance = await build_dns_guidance(
        "example.com",
        provider,
        dns,
        MTAStsResult(status="pass"),
        BIMIResult(status="pass"),
        setup_defaults=MailAuthSetupDefaults(report_mailbox="REPORTS@example.com"),
    )

    assert "dmarc_report_destination_missing" not in {finding.code for finding in guidance.findings}
    assert "dmarc_report_destination_missing" not in {
        plan.finding_code for plan in guidance.change_plans
    }


@pytest.mark.asyncio
async def test_empty_rua_tag_gets_one_valid_report_destination():
    provider = FakeDNSProvider({})
    current = "v=DMARC1; p=none; rua=   ; aspf=r"
    dns = DomainDNSResult(dmarc=True, dmarc_record=current, spf=True)

    guidance = await build_dns_guidance(
        "example.com",
        provider,
        dns,
        MTAStsResult(status="pass"),
        BIMIResult(status="pass"),
        setup_defaults=MailAuthSetupDefaults(report_mailbox="reports@example.com"),
    )

    plan = next(
        item
        for item in guidance.change_plans
        if item.finding_code == "dmarc_report_destination_missing"
    )
    assert "rua=mailto:reports@example.com" in plan.proposed_value
    assert "rua=," not in plan.proposed_value


@pytest.mark.asyncio
async def test_cached_unknown_dmarc_record_kind_stays_manual_only():
    provider = FakeDNSProvider({})
    current = "v=DMARC1; p=none; rua=mailto:existing@example.com"
    dns = DomainDNSResult(dmarc=True, dmarc_record=current, spf=True)

    guidance = await build_dns_guidance(
        "example.com",
        provider,
        dns,
        MTAStsResult(status="pass"),
        BIMIResult(status="pass"),
        setup_defaults=MailAuthSetupDefaults(report_mailbox="reports@example.com"),
        allow_live=False,
    )

    finding = next(
        item
        for item in guidance.findings
        if item.code == "dmarc_report_destination_provenance_unknown"
    )
    assert finding.primary_eligible is False
    assert "dmarc_report_destination_missing" not in {
        plan.finding_code for plan in guidance.change_plans
    }


@pytest.mark.asyncio
async def test_cached_confirmed_direct_dmarc_record_keeps_additive_plan():
    provider = FakeDNSProvider({})
    current = "v=DMARC1; p=none; rua=mailto:existing@example.com"
    dns = DomainDNSResult(
        dmarc=True,
        dmarc_record=current,
        dmarc_record_kind="txt",
        spf=True,
    )

    guidance = await build_dns_guidance(
        "example.com",
        provider,
        dns,
        MTAStsResult(status="pass"),
        BIMIResult(status="pass"),
        setup_defaults=MailAuthSetupDefaults(report_mailbox="reports@example.com"),
        allow_live=False,
    )

    assert guidance.change_plans[0].finding_code == "dmarc_report_destination_missing"


@pytest.mark.asyncio
async def test_external_report_destination_requires_authorization_first():
    provider = FakeDNSProvider({})
    current = "v=DMARC1; p=reject; rua=mailto:existing@example.com"
    dns = DomainDNSResult(
        dmarc=True,
        dmarc_record=current,
        dmarc_policy_domain="example.com",
        spf=True,
    )

    guidance = await build_dns_guidance(
        "example.com",
        provider,
        dns,
        MTAStsResult(status="pass"),
        BIMIResult(status="pass"),
        setup_defaults=MailAuthSetupDefaults(report_mailbox="reports@tenant.example"),
    )

    finding = next(
        item
        for item in guidance.findings
        if item.code == "dmarc_report_destination_authorization_missing"
    )
    assert finding.record_name == "example.com._report._dmarc.tenant.example"
    assert finding.target_record.value == "v=DMARC1"
    assert finding.primary_eligible is False
    assert "dmarc_report_destination_missing" not in {
        plan.finding_code for plan in guidance.change_plans
    }


@pytest.mark.asyncio
async def test_authorized_external_report_destination_gets_additive_plan():
    authorization_name = "example.com._report._dmarc.tenant.example"
    provider = FakeDNSProvider({authorization_name: ["v=DMARC1"]})
    current = "v=DMARC1; p=reject; rua=mailto:existing@example.com"
    dns = DomainDNSResult(
        dmarc=True,
        dmarc_record=current,
        dmarc_policy_domain="example.com",
        spf=True,
    )

    guidance = await build_dns_guidance(
        "example.com",
        provider,
        dns,
        MTAStsResult(status="pass"),
        BIMIResult(status="pass"),
        setup_defaults=MailAuthSetupDefaults(report_mailbox="reports@tenant.example"),
    )

    plan = guidance.change_plans[0]
    assert plan.finding_code == "dmarc_report_destination_missing"
    assert "mailto:reports@tenant.example" in plan.proposed_value


@pytest.mark.asyncio
async def test_cname_dmarc_policy_offers_safe_local_txt_migration():
    provider = FakeDNSProvider({})
    provider._cnames["_dmarc.example.com"] = "_dmarc.shared.example.net"
    current = "v=DMARC1; p=reject; rua=mailto:shared@example.net"
    dns = DomainDNSResult(dmarc=True, dmarc_record=current, spf=True)

    guidance = await build_dns_guidance(
        "example.com",
        provider,
        dns,
        MTAStsResult(status="pass"),
        BIMIResult(status="pass"),
        setup_defaults=MailAuthSetupDefaults(report_mailbox="reports@example.com"),
    )

    finding = next(
        item
        for item in guidance.findings
        if item.code == "dmarc_report_destination_cname_migration"
    )
    assert finding.primary_eligible is True
    assert finding.current_record_type == "CNAME"
    assert finding.current_record_values == ["_dmarc.shared.example.net"]
    assert finding.effective_value == current
    plan = next(
        item
        for item in guidance.change_plans
        if item.finding_code == "dmarc_report_destination_cname_migration"
    )
    assert plan.operation == "update"
    assert plan.current_record_type == "CNAME"
    assert plan.record_type == "TXT"
    assert plan.current_values == ["_dmarc.shared.example.net"]
    assert plan.effective_value == current
    assert plan.proposed_value == (
        "v=DMARC1; p=reject; " "rua=mailto:shared@example.net,mailto:reports@example.com"
    )
    assert "Leave the shared DMARC target unchanged." in plan.changes
    assert "previous CNAME" in plan.rollback


@pytest.mark.asyncio
async def test_cached_cname_dmarc_policy_keeps_inherited_finding():
    provider = FakeDNSProvider({})
    current = "v=DMARC1; p=reject; rua=mailto:shared@example.net"
    dns = DomainDNSResult(
        dmarc=True,
        dmarc_record=current,
        dmarc_record_kind="cname",
        dmarc_cname_target="_dmarc.shared.example.net",
        spf=True,
    )

    guidance = await build_dns_guidance(
        "example.com",
        provider,
        dns,
        MTAStsResult(status="pass"),
        BIMIResult(status="pass"),
        setup_defaults=MailAuthSetupDefaults(report_mailbox="reports@example.com"),
        allow_live=False,
    )

    finding = next(
        item
        for item in guidance.findings
        if item.code == "dmarc_report_destination_cname_migration"
    )
    assert finding.primary_eligible is True
    assert "_dmarc.shared.example.net" in finding.detail
    plan = next(
        item
        for item in guidance.change_plans
        if item.finding_code == "dmarc_report_destination_cname_migration"
    )
    assert plan.current_record_type == "CNAME"


@pytest.mark.asyncio
async def test_treewalk_policy_does_not_offer_record_type_migration():
    provider = FakeDNSProvider({})
    current = "v=DMARC1; p=reject; rua=mailto:shared@example.net"
    dns = DomainDNSResult(
        dmarc=True,
        dmarc_record=current,
        dmarc_record_kind="treewalk",
        dmarc_policy_domain="example.com",
        spf=True,
    )

    guidance = await build_dns_guidance(
        "mail.example.com",
        provider,
        dns,
        MTAStsResult(status="pass"),
        BIMIResult(status="pass"),
        setup_defaults=MailAuthSetupDefaults(report_mailbox="reports@mail.example.com"),
        allow_live=False,
    )

    assert "dmarc_report_destination_cname_migration" not in {
        item.code for item in guidance.findings
    }
    inherited = next(
        item for item in guidance.findings if item.code == "dmarc_report_destination_inherited"
    )
    assert inherited.primary_eligible is False


@pytest.mark.asyncio
async def test_cname_policy_with_local_mailbox_is_already_complete():
    provider = FakeDNSProvider({})
    current = "v=DMARC1; p=reject; rua=mailto:reports@example.com"
    dns = DomainDNSResult(
        dmarc=True,
        dmarc_record=current,
        dmarc_record_kind="cname",
        dmarc_cname_target="_dmarc.shared.example.net",
        spf=True,
    )

    guidance = await build_dns_guidance(
        "example.com",
        provider,
        dns,
        MTAStsResult(status="pass"),
        BIMIResult(status="pass"),
        setup_defaults=MailAuthSetupDefaults(report_mailbox="reports@example.com"),
        allow_live=False,
    )

    assert "dmarc_report_destination_cname_migration" not in {
        item.code for item in guidance.findings
    }


@pytest.mark.asyncio
async def test_mta_sts_target_includes_policy_file_with_observed_mx_hosts():
    provider = FakeDNSProvider(
        {"_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:tls@example.com"]}
    )
    dns = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        spf=True,
        spf_record="v=spf1 -all",
        dkim=True,
        dkim_selectors=["selector1"],
    )
    guidance = await build_dns_guidance(
        "example.com",
        provider,
        dns,
        MTAStsResult(status="fail"),
        BIMIResult(status="pass"),
        dane=DANEResult(mx_hosts=["mx1.example.com", "mx2.example.com"]),
    )

    target = next(record for record in guidance.target_records if record.code == "target_mta_sts")
    assert target.supporting_content == (
        "version: STSv1\nmode: testing\nmx: mx1.example.com\nmx: mx2.example.com\nmax_age: 86400"
    )
    assert target.supporting_content_url == "https://mta-sts.example.com/.well-known/mta-sts.txt"


@pytest.mark.asyncio
async def test_change_plan_shows_dmarc_tag_diff_and_suppresses_noop():
    provider = FakeDNSProvider(
        {"_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:tls@example.com"]}
    )
    target = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100"
    dns = DomainDNSResult(
        dmarc=True,
        dmarc_record=target,
        spf=True,
        spf_record="v=spf1 -all",
        dkim=True,
        dkim_selectors=["selector1"],
        dmarc_warnings=["DMARC adkim tag should be r or s."],
    )
    guidance = await build_dns_guidance(
        "example.com", provider, dns, MTAStsResult(status="pass"), BIMIResult(status="pass")
    )

    assert not [
        plan
        for plan in guidance.change_plans
        if plan.finding_code == "dmarc_alignment_value_invalid"
    ]

    finding = next(
        finding for finding in guidance.findings if finding.code == "dmarc_alignment_value_invalid"
    )
    finding.target_record.value = (
        "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; pct=100; adkim=r"
    )
    plans = build_dns_change_plans([finding])
    assert plans[0].current_values == [target]
    assert "Add adkim=r." in plans[0].changes


def test_change_plan_keeps_consolidation_when_one_rrset_value_matches():
    desired = "v=spf1 include:mail.example.com -all"
    finding = DNSLintFinding(
        code="spf_multiple_records",
        severity="error",
        title="Multiple SPF records found",
        detail="SPF requires exactly one record.",
        action="Merge the mechanisms into one SPF record.",
        record_type="TXT",
        record_name="example.com",
        target_record=DNSGuidanceRecord(
            code="target_spf",
            record_type="TXT",
            name="example.com",
            value=desired,
            purpose="SPF",
        ),
        evidence=[desired, "v=spf1 include:legacy.example.com -all"],
    )

    plans = build_dns_change_plans([finding])

    assert len(plans) == 1
    assert plans[0].operation == "consolidate"
    assert plans[0].current_values == finding.evidence


def test_change_plan_suppresses_equivalent_tag_values_in_different_order():
    finding = DNSLintFinding(
        code="dmarc_alignment_value_invalid",
        severity="warning",
        title="DMARC alignment mode needs review",
        detail="The DMARC record is otherwise healthy.",
        action="Use strict alignment for this domain.",
        record_type="TXT",
        record_name="_dmarc.example.com",
        target_record=DNSGuidanceRecord(
            code="target_dmarc",
            record_type="TXT",
            name="_dmarc.example.com",
            value="v=DMARC1; p=reject; rua=mailto:dmarc@example.com; adkim=s",
            purpose="DMARC",
        ),
        evidence=["rua=mailto:dmarc@example.com; adkim=s; p=reject; v=DMARC1"],
    )

    assert build_dns_change_plans([finding]) == []


def test_plan_changes_ignores_malformed_segments_in_tag_records():
    changes = _plan_changes(
        ["v=DMARC1; malformed-tag; p=none"],
        "v=DMARC1; p=reject",
    )

    assert changes == ["Change p from none to reject."]


@pytest.mark.asyncio
async def test_build_dns_guidance_preserves_zero_dmarc_percentage():
    provider = FakeDNSProvider({})
    dns = DomainDNSResult(
        dmarc=False,
        spf=True,
        spf_record="v=spf1 -all",
        dkim=True,
        dkim_selectors=["selector1"],
    )

    guidance = await build_dns_guidance(
        "example.com",
        provider,
        dns,
        MTAStsResult(status="pass"),
        BIMIResult(status="pass"),
        setup_defaults=MailAuthSetupDefaults(percentage=0),
    )

    targets = {record.code: record for record in guidance.target_records}
    assert "pct=0" in targets["target_dmarc"].value


@pytest.mark.asyncio
async def test_build_dns_guidance_localizes_high_value_remediation_steps_to_german():
    provider = FakeDNSProvider({})
    dns = DomainDNSResult(
        dmarc=False,
        spf=False,
        dkim=False,
        selectors_checked=["selector1"],
    )
    mta_sts = MTAStsResult(status="pass")
    bimi = BIMIResult(status="pass")

    guidance = await build_dns_guidance(
        "example.com",
        provider,
        dns,
        mta_sts,
        bimi,
        locale="de-DE",
    )

    findings = {finding.code: finding for finding in guidance.findings}
    assert "Oeffne die DNS-Zone" in findings["dmarc_missing"].remediation_steps[0]
    assert "Veroeffentliche genau einen TXT-Record" in findings["spf_missing"].remediation_steps[1]
    assert "Domain-Authentifizierung" in " ".join(
        findings["dkim_selector_missing"].remediation_steps
    )


@pytest.mark.asyncio
async def test_build_dns_guidance_falls_back_to_english_for_missing_translation():
    provider = FakeDNSProvider({"example.com": ["v=spf1 -all"]})
    dns = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        spf=True,
        spf_record="v=spf1 -all",
        dkim=True,
        dkim_selectors=["selector1"],
        dmarc_warnings=["Unsupported fo tag."],
    )
    mta_sts = MTAStsResult(status="pass")
    bimi = BIMIResult(status="pass")

    guidance = await build_dns_guidance(
        "example.com",
        provider,
        dns,
        mta_sts,
        bimi,
        locale="de",
    )

    warning = next(
        finding for finding in guidance.findings if finding.code == "dmarc_failure_option_invalid"
    )
    assert warning.remediation_steps[0] == "Open the linked DNS or report evidence in DMARQ."


@pytest.mark.asyncio
async def test_build_dns_guidance_lints_spf_and_tls_rpt_records():
    provider = FakeDNSProvider(
        {
            "example.com": [
                "v=spf1 include:_spf.example.com +all",
                "v=spf1 include:_spf2.example.com ~all",
            ],
            "_smtp._tls.example.com": ["v=TLSRPTv1"],
        }
    )
    dns = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        spf=True,
        spf_record="v=spf1 include:_spf.example.com +all",
        dkim=True,
        dkim_selectors=["selector1"],
    )
    mta_sts = MTAStsResult(status="pass")
    bimi = BIMIResult(status="pass")

    guidance = await build_dns_guidance("example.com", provider, dns, mta_sts, bimi)

    codes = {finding.code for finding in guidance.findings}
    assert "spf_multiple_records" in codes
    assert "spf_all_too_permissive" in codes
    assert "tls_rpt_rua_missing" in codes


@pytest.mark.asyncio
async def test_build_dns_guidance_ignores_dane_limitation_notice_for_pass_status():
    provider = FakeDNSProvider(
        {
            "example.com": ["v=spf1 -all"],
            "_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:tls@example.com"],
        }
    )
    dns = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        spf=True,
        spf_record="v=spf1 -all",
        dkim=True,
        dkim_selectors=["selector1"],
    )
    dane = DANEResult(
        status="pass",
        mx_hosts=["mx.example.com"],
        warnings=[
            "DMARQ validates TLSA syntax and MX coverage, but does not yet validate DNSSEC chains "
            "or compare TLSA hashes with live SMTP certificates."
        ],
    )

    guidance = await build_dns_guidance(
        "example.com",
        provider,
        dns,
        MTAStsResult(status="pass"),
        BIMIResult(status="pass"),
        dane=dane,
    )

    assert "dane_review" not in {finding.code for finding in guidance.findings}


@pytest.mark.asyncio
async def test_build_dns_guidance_uses_live_tlsa_suggestion_as_dane_target():
    provider = FakeDNSProvider(
        {
            "example.com": ["v=spf1 -all"],
            "_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:tls@example.com"],
        }
    )
    dns = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        spf=True,
        spf_record="v=spf1 -all",
        dkim=True,
        dkim_selectors=["selector1"],
    )
    dane = DANEResult(
        status="fail",
        port=25,
        mx_hosts=["mx.example.com"],
        errors=["No TLSA records were found for MX host(s): mx.example.com"],
        suggested_records=[
            TLSASuggestion(
                query_name="_25._tcp.mail.example.net",
                mx_host="mx.example.com",
                record=(
                    "3 1 1 " "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                ),
                association_data="a" * 64,
                status="ready",
            )
        ],
    )

    guidance = await build_dns_guidance(
        "example.com",
        provider,
        dns,
        MTAStsResult(status="pass"),
        BIMIResult(status="pass"),
        dane=dane,
    )

    target = next(record for record in guidance.target_records if record.code == "target_dane")
    assert target.name == "_25._tcp.mail.example.net"
    assert target.value == "3 1 1 " + "a" * 64
    assert "derived from the live STARTTLS certificate" in target.purpose


@pytest.mark.asyncio
async def test_build_dns_guidance_offers_each_uncovered_mx_tlsa_value():
    provider = FakeDNSProvider(
        {
            "example.com": ["v=spf1 -all"],
            "_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:tls@example.com"],
        }
    )
    dns = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        spf=True,
        spf_record="v=spf1 -all",
        dkim=True,
        dkim_selectors=["selector1"],
    )
    first_value = "3 1 1 " + "a" * 64
    second_value = "3 1 1 " + "b" * 64
    dane = DANEResult(
        status="partial",
        port=25,
        mx_hosts=["mx1.example.com", "mx2.example.com"],
        records=[
            TLSARecord(
                query_name="_25._tcp.mx1.example.com",
                mx_host="mx1.example.com",
                record=first_value,
                valid=True,
            )
        ],
        suggested_records=[
            TLSASuggestion(
                query_name="_25._tcp.mx1.example.com",
                mx_host="mx1.example.com",
                record=first_value,
                status="ready",
            ),
            TLSASuggestion(
                query_name="_25._tcp.mx2.example.com",
                mx_host="mx2.example.com",
                record=second_value,
                status="ready",
            ),
        ],
    )

    guidance = await build_dns_guidance(
        "example.com",
        provider,
        dns,
        MTAStsResult(status="pass"),
        BIMIResult(status="pass"),
        dane=dane,
    )

    plans = [plan for plan in guidance.change_plans if plan.record_type == "TLSA"]
    assert len(plans) == 1
    assert plans[0].name == "_25._tcp.mx2.example.com"
    assert plans[0].proposed_value == second_value


@pytest.mark.asyncio
async def test_build_dns_guidance_keeps_dane_review_when_covered_hosts_need_review():
    provider = FakeDNSProvider(
        {
            "example.com": ["v=spf1 -all"],
            "_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:tls@example.com"],
        }
    )
    dns = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        spf=True,
        spf_record="v=spf1 -all",
        dkim=True,
        dkim_selectors=["selector1"],
    )
    record_value = "3 1 1 " + "a" * 64
    dane = DANEResult(
        status="partial",
        mx_hosts=["mx.example.com"],
        records=[
            TLSARecord(
                query_name="_25._tcp.mx.example.com",
                mx_host="mx.example.com",
                record=record_value,
                valid=True,
            )
        ],
        suggested_records=[
            TLSASuggestion(
                query_name="_25._tcp.mx.example.com",
                mx_host="mx.example.com",
                record=record_value,
                status="ready",
            )
        ],
        warnings=["DNSSEC validation still needs operator review."],
    )

    guidance = await build_dns_guidance(
        "example.com",
        provider,
        dns,
        MTAStsResult(status="pass"),
        BIMIResult(status="pass"),
        dane=dane,
    )

    assert "dane_review" in {finding.code for finding in guidance.findings}


@pytest.mark.asyncio
async def test_build_dns_guidance_classifies_dmarc_warning_codes():
    provider = FakeDNSProvider(
        {
            "example.com": ["v=spf1 ?all"],
            "_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:tls@example.com"],
        }
    )
    dns = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=none",
        spf=True,
        spf_record="v=spf1 ?all",
        dkim=True,
        dkim_selectors=["selector1"],
        dmarc_warnings=[
            "External rua destination reports.example.net is missing authorization TXT.",
            "External ruf destination forensics.example.net is missing authorization TXT.",
            "Unsupported policy value p=monitor.",
            "DMARC adkim tag should be r or s.",
            "DMARC fo tag contains unsupported failure options.",
            "Record contains neither a valid p tag nor a rua tag.",
            "Unexpected DMARC lint warning.",
        ],
        dmarc_suggestions=["Add rua=mailto:... so aggregate reports can reach DMARQ."],
    )

    guidance = await build_dns_guidance(
        "example.com",
        provider,
        dns,
        MTAStsResult(status="pass"),
        BIMIResult(status="pass"),
    )

    codes = {finding.code for finding in guidance.findings}
    assert "dmarc_external_rua_unauthorized" in codes
    assert "dmarc_external_ruf_unauthorized" in codes
    assert "dmarc_policy_value_invalid" in codes
    assert "dmarc_alignment_value_invalid" in codes
    assert "dmarc_failure_option_invalid" in codes
    assert "dmarc_policy_or_reporting_missing" in codes
    assert "dmarc_lint_warning" in codes
    assert "dmarc_suggestion" in codes
    assert "dmarc_monitoring_policy" in codes
    assert "spf_all_neutral" in codes
    assert "bimi_dmarc_not_enforced" in codes
    monitoring = next(
        finding for finding in guidance.findings if finding.code == "dmarc_monitoring_policy"
    )
    assert monitoring.remediation_steps[0].startswith("Review DMARQ report evidence")


@pytest.mark.asyncio
async def test_build_dns_guidance_lints_more_spf_tls_mta_and_bimi_states():
    provider = FakeDNSProvider(
        {
            "example.com": [
                (
                    "v=spf1 include:a.example include:b.example include:c.example "
                    "include:d.example include:e.example include:f.example "
                    "include:g.example include:h.example include:i.example "
                    "include:j.example include:k.example"
                )
            ],
            "_smtp._tls.example.com": [
                "v=TLSRPTv1; rua=mailto:tls@example.com",
                "v=TLSRPTv1; rua=mailto:backup@example.com",
            ],
        }
    )
    dns = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com",
        spf=True,
        spf_record=(
            "v=spf1 include:a.example include:b.example include:c.example "
            "include:d.example include:e.example include:f.example "
            "include:g.example include:h.example include:i.example "
            "include:j.example include:k.example"
        ),
        dkim=True,
        dkim_selectors=["selector1"],
    )
    mta_sts = MTAStsResult(
        status="pass",
        dns_record="v=STSv1; id=20260625",
        warnings=["MTA-STS policy is valid but not enforcing mail delivery (testing)."],
    )
    bimi = BIMIResult(
        status="pass",
        dns_record="v=BIMI1; l=https://example.com/logo.svg",
        warnings=["No BIMI certificate URL is published; some mailbox providers require one."],
    )

    guidance = await build_dns_guidance("example.com", provider, dns, mta_sts, bimi)

    codes = {finding.code for finding in guidance.findings}
    assert "spf_all_missing" in codes
    assert "spf_dns_lookup_limit_risk" in codes
    assert "tls_rpt_multiple_records" in codes
    assert "mta_sts_review" in codes
    assert "bimi_review" in codes


@pytest.mark.asyncio
async def test_build_dns_guidance_lints_dkim_selector_health():
    provider = FakeDNSProvider(
        {
            "example.com": ["v=spf1 -all"],
            "_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:tls@example.com"],
            "google._domainkey.example.com": [
                "v=DKIM1; k=rsa; p="
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAgoodselector"
                "keymaterialthatislongenoughtolooklikeanormalrsa1024or2048key"
                "forlintpurposesonly1234567890abcdef"
            ],
            "short._domainkey.example.com": ["v=DKIM1; k=rsa; p=SHORT"],
        }
    )
    provider._cnames["mailchimp._domainkey.example.com"] = "missing._domainkey.mcsv.net"
    dns = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        spf=True,
        spf_record="v=spf1 -all",
        dkim=True,
        dkim_selectors=["google", "short"],
        selectors_checked=["google", "short", "mailchimp", "old"],
    )

    guidance = await build_dns_guidance(
        "example.com",
        provider,
        dns,
        MTAStsResult(status="pass"),
        BIMIResult(status="pass"),
        monitored_selectors=["google", "short", "mailchimp", "old"],
        observed_selectors=["google", "mailchimp"],
    )

    findings = {finding.code: finding for finding in guidance.findings}
    assert "dkim_selector_key_too_short" in findings
    assert "dkim_selector_cname_broken" in findings
    assert "dkim_selector_missing" in findings
    assert findings["dkim_selector_missing"].record_name == "old._domainkey.example.com"
    assert findings["dkim_selector_missing"].target_record.name == "old._domainkey.example.com"
    assert (
        findings["dkim_selector_cname_broken"].target_record.name
        == "mailchimp._domainkey.example.com"
    )
    assert (
        findings["dkim_selector_key_too_short"].target_record.name == "short._domainkey.example.com"
    )
    assert findings["dkim_selector_cname_broken"].record_type == "CNAME"
    assert findings["dkim_selector_key_too_short"].remediation_steps


@pytest.mark.asyncio
async def test_build_dns_guidance_creates_operator_plans_for_dkim_review_paths():
    provider = FakeDNSProvider(
        {
            "example.com": ["v=spf1 -all"],
            "_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:tls@example.com"],
            "stale._domainkey.example.com": [
                "v=DKIM1; k=rsa; p="
                "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAstaleselector"
                "keymaterialthatislongenoughtolooklikeanormalrsa1024or2048key"
                "forlintpurposesonly1234567890abcdef"
            ],
        }
    )
    provider._cnames["mailchimp._domainkey.example.com"] = "missing._domainkey.mcsv.net"
    dns = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        spf=True,
        spf_record="v=spf1 -all",
        dkim=True,
        dkim_selectors=["stale"],
        selectors_checked=["stale", "mailchimp"],
    )

    guidance = await build_dns_guidance(
        "example.com",
        provider,
        dns,
        MTAStsResult(status="pass"),
        BIMIResult(status="pass"),
        monitored_selectors=["stale", "mailchimp"],
        observed_selectors=["google"],
    )

    plans = {plan.finding_code: plan for plan in guidance.change_plans}
    assert plans["dkim_selector_stale"].operation == "review-remove"
    assert plans["dkim_selector_stale"].proposed_value is None
    assert plans["dkim_selector_stale"].provider_value_required is False
    assert any("recent report cycle" in step for step in plans["dkim_selector_stale"].manual_steps)
    assert plans["dkim_selector_cname_broken"].operation == "update"
    assert plans["dkim_selector_cname_broken"].proposed_value == (
        "<provider-current-dkim-cname-target>"
    )
    assert plans["dkim_selector_cname_broken"].provider_value_required is True


@pytest.mark.asyncio
async def test_build_dns_guidance_defers_bimi_until_dmarc_enforcement():
    provider = FakeDNSProvider(
        {
            "example.com": ["v=spf1 -all"],
            "_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:tls@example.com"],
        }
    )
    dns = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=none; rua=mailto:dmarc@example.com",
        spf=True,
        spf_record="v=spf1 -all",
        dkim=True,
        dkim_selectors=["selector1"],
    )

    guidance = await build_dns_guidance(
        "example.com",
        provider,
        dns,
        MTAStsResult(status="pass"),
        BIMIResult(status="pass"),
    )

    assert "bimi_dmarc_not_enforced" in {finding.code for finding in guidance.findings}
    assert "bimi_dmarc_not_enforced" not in {plan.finding_code for plan in guidance.change_plans}


@pytest.mark.asyncio
async def test_spf_lint_covers_redirect_void_and_duplicate_free_paths():
    provider = FakeDNSProvider(
        {
            "example.com": ["v=spf1 redirect=missing.example -all"],
            "_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:tls@example.com"],
        }
    )
    dns = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        spf=True,
        spf_record="v=spf1 redirect=missing.example a -all",
        dkim=True,
        dkim_selectors=["selector1"],
    )

    guidance = await build_dns_guidance(
        "example.com",
        provider,
        dns,
        MTAStsResult(status="pass"),
        BIMIResult(status="pass"),
    )

    codes = {finding.code for finding in guidance.findings}
    assert "spf_void_lookup" in codes
    assert "spf_duplicate_include" not in codes


@pytest.mark.asyncio
async def test_build_dns_guidance_accepts_valid_dkim_cname_target():
    provider = FakeDNSProvider(
        {
            "example.com": ["v=spf1 -all"],
            "_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:tls@example.com"],
            "provider._domainkey.vendor.example": ["v=DKIM1; k=rsa; p=VALIDKEY"],
        }
    )
    provider._cnames["mailchimp._domainkey.example.com"] = "provider._domainkey.vendor.example"
    dns = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        spf=True,
        spf_record="v=spf1 -all",
        dkim=True,
        dkim_selectors=["mailchimp"],
        selectors_checked=["mailchimp"],
    )

    guidance = await build_dns_guidance(
        "example.com",
        provider,
        dns,
        MTAStsResult(status="pass"),
        BIMIResult(status="pass"),
        monitored_selectors=["mailchimp"],
        observed_selectors=["mailchimp"],
    )

    assert "dkim_selector_cname_broken" not in {finding.code for finding in guidance.findings}


@pytest.mark.asyncio
async def test_build_dns_guidance_adds_postmark_dns_change_plans():
    provider = FakeDNSProvider(
        {
            "example.com": ["v=spf1 -all"],
            "_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:tls@example.com"],
            "pm._domainkey.example.com": ["old-dkim-value"],
        }
    )
    dns = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        spf=True,
        spf_record="v=spf1 -all",
        dkim=True,
        dkim_selectors=["selector1"],
    )

    guidance = await build_dns_guidance(
        "example.com",
        provider,
        dns,
        MTAStsResult(status="pass"),
        BIMIResult(status="pass"),
        mail_service_records=[
            {
                "provider": "postmark",
                "provider_name": "Postmark",
                "record_type": "TXT",
                "name": "pm._domainkey.example.com",
                "value": "new-dkim-value",
                "purpose": "dkim",
            },
            {
                "provider": "postmark",
                "provider_name": "Postmark",
                "record_type": "CNAME",
                "name": "pm-bounces.example.com",
                "value": "pm.mtasv.net",
                "purpose": "return_path",
            },
        ],
    )

    finding_codes = {finding.code for finding in guidance.findings}
    assert "mail_service_record_conflict" in finding_codes
    assert "mail_service_record_missing" in finding_codes
    conflict = next(
        plan
        for plan in guidance.change_plans
        if plan.finding_code == "mail_service_record_conflict"
    )
    missing = next(
        plan for plan in guidance.change_plans if plan.finding_code == "mail_service_record_missing"
    )
    assert conflict.operation == "update"
    assert conflict.record_type == "TXT"
    assert conflict.proposed_value == "new-dkim-value"
    assert conflict.provider_value_required is False
    assert conflict.current_values == ["old-dkim-value"]
    assert missing.operation == "create"
    assert missing.record_type == "CNAME"
    assert missing.proposed_value == "pm.mtasv.net"


@pytest.mark.asyncio
async def test_selector_history_cannot_become_primary_dns_remediation():
    provider = FakeDNSProvider(
        {
            "example.com": ["v=spf1 -all"],
            "_smtp._tls.example.com": ["v=TLSRPTv1; rua=mailto:tls@example.com"],
        }
    )
    dns = DomainDNSResult(
        dmarc=True,
        dmarc_record="v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        spf=True,
        spf_record="v=spf1 -all",
        dkim=False,
        selectors_checked=["active", "passing", "retired", "manual"],
    )
    selector_evidence = [
        {
            "selector": "active",
            "classification": "active_failing",
            "current_failure_count": 12,
        },
        {
            "selector": "passing",
            "classification": "active_passing",
            "current_pass_count": 8,
        },
        {
            "selector": "retired",
            "classification": "historical",
            "current_failure_count": 0,
        },
        {
            "selector": "manual",
            "classification": "manually_configured",
            "manual_configured": True,
        },
    ]

    guidance = await build_dns_guidance(
        "example.com",
        provider,
        dns,
        MTAStsResult(status="pass"),
        BIMIResult(status="pass"),
        monitored_selectors=["active", "passing", "retired", "manual"],
        observed_selectors=["active", "passing", "retired"],
        selector_evidence=selector_evidence,
    )

    dkim_findings = [finding for finding in guidance.findings if finding.code.startswith("dkim_")]
    dkim_plans = [plan for plan in guidance.change_plans if plan.finding_code.startswith("dkim_")]

    assert [finding.record_name for finding in dkim_findings] == ["active._domainkey.example.com"]
    assert [plan.name for plan in dkim_plans] == ["active._domainkey.example.com"]
    assert dkim_plans[0].provider_value_required is True
    assert dkim_plans[0].requires_approval is True
    assert (
        next(record for record in guidance.target_records if record.code == "target_dkim").name
        == "active._domainkey.example.com"
    )
    evidence = {item["selector"]: item for item in guidance.selector_evidence}
    assert evidence["active"]["dns_status"] == "missing"
    assert evidence["retired"]["dns_status"] == "missing"
