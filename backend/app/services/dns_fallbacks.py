"""Shared DNS resolver fallback helpers."""

from __future__ import annotations

from typing import List

from app.services.dns_resolver import (
    BaseDNSProvider,
    CloudflareDNSProvider,
    DemoDNSProvider,
    PublicRecursiveDNSProvider,
)


def dns_fallback_candidates(provider: BaseDNSProvider) -> List[BaseDNSProvider]:
    """Return primary plus independent public fallback resolvers.

    Deployment-specific resolvers such as Akamai ETP can be useful as the
    primary view, but read-only DNS evidence should not degrade to "unknown"
    when that resolver is missing or slow and public DNS has a clear answer.
    """
    candidates: List[BaseDNSProvider] = [provider]
    if isinstance(provider, DemoDNSProvider):
        return candidates
    if not isinstance(provider, PublicRecursiveDNSProvider):
        candidates.append(PublicRecursiveDNSProvider())
    if not isinstance(provider, CloudflareDNSProvider):
        candidates.append(CloudflareDNSProvider())
    return candidates
