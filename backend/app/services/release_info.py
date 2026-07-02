"""Runtime release metadata for support and in-product visibility."""

from __future__ import annotations

from typing import Any, Dict, Optional

from app import __version__


def _clean(value: Optional[str]) -> Optional[str]:
    if value is None:
        return None
    stripped = str(value).strip()
    return stripped or None


def _short_sha(value: Optional[str]) -> Optional[str]:
    cleaned = _clean(value)
    if not cleaned:
        return None
    return cleaned[:12]


def build_release_info(settings: Any) -> Dict[str, Any]:
    """Return safe build metadata and a short operator-facing changelog."""

    sha = _clean(getattr(settings, "DMARQ_BUILD_SHA", None))
    short_sha = _short_sha(sha)
    version = _clean(getattr(settings, "DMARQ_RELEASE_VERSION", None)) or __version__
    label = f"v{version}"
    if short_sha:
        label = f"{label} · {short_sha}"

    return {
        "service": "dmarq",
        "version": version,
        "label": label,
        "build": {
            "sha": sha,
            "short_sha": short_sha,
            "ref": _clean(getattr(settings, "DMARQ_BUILD_REF", None)),
            "image": _clean(getattr(settings, "DMARQ_BUILD_IMAGE", None)),
            "date": _clean(getattr(settings, "DMARQ_BUILD_DATE", None)),
        },
        "changes": [
            {
                "title": "Faster domain pages",
                "description": (
                    "Domain list and domain detail views use precomputed database "
                    "aggregates so report-heavy installs load with less waiting."
                ),
            },
            {
                "title": "Sender intelligence",
                "description": (
                    "Sending sources now include provider detection, network context, "
                    "first/last seen activity, and optional reputation feed checks."
                ),
            },
            {
                "title": "Self-hosted demo focus",
                "description": (
                    "The default demo and navigation emphasize the single-user, "
                    "multiple-domain self-hosted story."
                ),
            },
        ],
    }
