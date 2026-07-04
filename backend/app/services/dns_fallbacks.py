"""Shared DNS resolver fallback helpers."""

from __future__ import annotations

from typing import List

from app.services.dns_resolver import (
    BaseDNSProvider,
    CloudflareDNSProvider,
    PublicRecursiveDNSProvider,
)


def dns_fallback_candidates(provider: BaseDNSProvider) -> List[BaseDNSProvider]:
    """Return primary plus independent public fallback resolvers.

    Deployment-specific resolvers such as Akamai ETP can be useful as the
    primary view, but read-only DNS evidence should not degrade to "unknown"
    when that resolver is missing or slow and public DNS has a clear answer.
    """
    candidates: List[BaseDNSProvider] = [provider]
    if provider.__class__.__name__ == "DemoDNSProvider":
        return candidates
    if provider.__class__ is not PublicRecursiveDNSProvider:
        candidates.append(PublicRecursiveDNSProvider())
    if provider.__class__ is not CloudflareDNSProvider:
        candidates.append(CloudflareDNSProvider())
    return candidates
