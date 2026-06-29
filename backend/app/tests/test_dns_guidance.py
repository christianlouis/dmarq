import pytest

from app.services.bimi import BIMIResult
from app.services.dns_guidance import build_dns_guidance
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
    }


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
    assert findings["dkim_selector_cname_broken"].record_type == "CNAME"
    assert findings["dkim_selector_key_too_short"].remediation_steps


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
