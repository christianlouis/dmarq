from app.services.dns_fallbacks import dns_fallback_candidates
from app.services.dns_resolver import (
    BaseDNSProvider,
    CloudflareDNSProvider,
    DemoDNSProvider,
    PublicRecursiveDNSProvider,
)


class _CustomProvider(BaseDNSProvider):
    async def lookup_txt(self, _name: str):
        return []


class _CloudflareSubclass(CloudflareDNSProvider):
    pass


def test_dns_fallback_candidates_keep_demo_provider_isolated():
    provider = DemoDNSProvider()

    assert dns_fallback_candidates(provider) == [provider]


def test_dns_fallback_candidates_use_isinstance_for_public_provider():
    provider = PublicRecursiveDNSProvider()

    candidates = dns_fallback_candidates(provider)

    assert candidates[0] is provider
    assert sum(isinstance(candidate, PublicRecursiveDNSProvider) for candidate in candidates) == 1
    assert any(isinstance(candidate, CloudflareDNSProvider) for candidate in candidates)


def test_dns_fallback_candidates_do_not_duplicate_provider_subclasses():
    provider = _CloudflareSubclass()

    candidates = dns_fallback_candidates(provider)

    assert candidates[0] is provider
    assert sum(isinstance(candidate, CloudflareDNSProvider) for candidate in candidates) == 1
    assert any(isinstance(candidate, PublicRecursiveDNSProvider) for candidate in candidates)


def test_dns_fallback_candidates_add_both_public_resolvers_for_custom_provider():
    provider = _CustomProvider()

    candidates = dns_fallback_candidates(provider)

    assert candidates[0] is provider
    assert any(isinstance(candidate, PublicRecursiveDNSProvider) for candidate in candidates)
    assert any(isinstance(candidate, CloudflareDNSProvider) for candidate in candidates)
