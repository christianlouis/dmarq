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
