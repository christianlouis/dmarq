import pytest

from app.services.bimi import BIMIResult
from app.services.dns_guidance import build_dns_guidance
from app.services.dns_resolver import BaseDNSProvider, DomainDNSResult
from app.services.mta_sts import MTAStsResult


class FakeDNSProvider(BaseDNSProvider):
    def __init__(self, records: dict[str, list[str]]):
        self._records = records

    async def lookup_txt(self, name: str) -> list[str]:
        if name in self._records:
            return self._records[name]
        raise LookupError(f"NXDOMAIN: {name}")


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
            "DMARC adkim tag should be r or s.",
            "DMARC fo tag contains unsupported failure options.",
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
    assert "dmarc_alignment_value_invalid" in codes
    assert "dmarc_failure_option_invalid" in codes
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
