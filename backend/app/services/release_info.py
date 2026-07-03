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


def _image_tag(value: Optional[str]) -> Optional[str]:
    cleaned = _clean(value)
    if not cleaned:
        return None
    image_name = cleaned.rsplit("/", 1)[-1].split("@", 1)[0]
    if ":" not in image_name:
        return None
    return _clean(image_name.rsplit(":", 1)[-1])


def _image_tag_matches_short_sha(image_tag: Optional[str], short_sha: Optional[str]) -> bool:
    tag = _clean(image_tag)
    sha = _clean(short_sha)
    if not tag or not sha:
        return False
    return len(tag) >= 7 and sha.startswith(tag)


def build_release_info(settings: Any) -> Dict[str, Any]:
    """Return safe build metadata and a short operator-facing changelog."""

    sha = _clean(getattr(settings, "DMARQ_BUILD_SHA", None))
    short_sha = _short_sha(sha)
    version = _clean(getattr(settings, "DMARQ_RELEASE_VERSION", None)) or __version__
    image = _clean(getattr(settings, "DMARQ_BUILD_IMAGE", None))
    image_tag = _image_tag(image)
    environment = _clean(getattr(settings, "ENVIRONMENT", None)) or "development"
    label = f"v{version}"
    if short_sha:
        label = f"{label} · {short_sha}"

    return {
        "service": "dmarq",
        "version": version,
        "label": label,
        "environment": environment,
        "demo_mode": bool(getattr(settings, "DEMO_MODE", False)),
        "public_base_url": _clean(getattr(settings, "PUBLIC_BASE_URL", None)),
        "build": {
            "sha": sha,
            "short_sha": short_sha,
            "ref": _clean(getattr(settings, "DMARQ_BUILD_REF", None)),
            "image": image,
            "image_tag": image_tag,
            "date": _clean(getattr(settings, "DMARQ_BUILD_DATE", None)),
        },
        "rollout": {
            "endpoint": "/api/v1/health/release",
            "root_health_endpoint": "/health",
            "environment": environment,
            "image_tag_matches_short_sha": _image_tag_matches_short_sha(image_tag, short_sha),
        },
        "changelog_url": "https://github.com/christianlouis/dmarq/blob/main/CHANGELOG.md",
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
            {
                "title": "Cloudflare rights profiles",
                "description": (
                    "The Cloudflare connector exposes read-only, read-only plus Radar "
                    "context, and full DNS repair profiles so operators can choose the "
                    "least privilege needed for the next action."
                ),
            },
            {
                "title": "Safer DNS repair workflow",
                "description": (
                    "DNS changes remain human-approved, with provider imports, ownership "
                    "verification, repair previews, and audit-friendly settings separated "
                    "from automatic write actions."
                ),
            },
            {
                "title": "In-product release visibility",
                "description": (
                    "The current version, build image, git ref, build date, and recent "
                    "operator-facing fixes are available from the small release label in "
                    "the app shell."
                ),
            },
            {
                "title": "CSP hardening progress",
                "description": (
                    "Inline handlers and style bindings continue moving out of templates "
                    "toward external scripts and CSS so strict CSP can become the default."
                ),
            },
            {
                "title": "Actionable remediation groundwork",
                "description": (
                    "Domain and report detail views include clearer next steps, DNS lint "
                    "evidence, source intelligence, and safer repair context for DMARC "
                    "operations."
                ),
            },
        ],
    }
