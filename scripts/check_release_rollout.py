#!/usr/bin/env python3
"""Verify that a live DMARQ endpoint exposes the expected release metadata."""

from __future__ import annotations

import argparse
import json
import sys
import urllib.error
import urllib.request
from typing import Any, Dict, List, Optional


def _normalize_base_url(value: str) -> str:
    return value.rstrip("/")


def _fetch_release(base_url: str, timeout: float) -> Dict[str, Any]:
    url = f"{_normalize_base_url(base_url)}/api/v1/health/release"
    request = urllib.request.Request(url, headers={"Accept": "application/json"})
    with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310
        return json.loads(response.read().decode("utf-8"))


def _compare(
    release: Dict[str, Any],
    *,
    expected_version: Optional[str],
    expected_sha: Optional[str],
    expected_image: Optional[str],
    expected_environment: Optional[str],
) -> List[str]:
    failures: List[str] = []
    build = release.get("build") or {}
    if expected_version and release.get("version") != expected_version:
        failures.append(f"version expected {expected_version}, got {release.get('version')}")
    if expected_environment and release.get("environment") != expected_environment:
        failures.append(
            f"environment expected {expected_environment}, got {release.get('environment')}"
        )
    if expected_sha:
        live_sha = build.get("sha") or build.get("short_sha")
        if not live_sha or not str(live_sha).startswith(expected_sha):
            failures.append(f"build SHA expected prefix {expected_sha}, got {live_sha}")
    if expected_image and build.get("image") != expected_image:
        failures.append(f"image expected {expected_image}, got {build.get('image')}")
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base-url", required=True, help="DMARQ base URL, e.g. https://app.dmarq.org")
    parser.add_argument("--expected-version", help="Expected semantic release version")
    parser.add_argument("--expected-sha", help="Expected build SHA or short-SHA prefix")
    parser.add_argument("--expected-image", help="Expected container image reference")
    parser.add_argument("--expected-environment", help="Expected deployment environment label")
    parser.add_argument("--timeout", type=float, default=10.0, help="HTTP timeout in seconds")
    args = parser.parse_args()

    try:
        release = _fetch_release(args.base_url, args.timeout)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
        print(f"rollout check failed: could not read release endpoint: {exc}", file=sys.stderr)
        return 2

    failures = _compare(
        release,
        expected_version=args.expected_version,
        expected_sha=args.expected_sha,
        expected_image=args.expected_image,
        expected_environment=args.expected_environment,
    )
    if failures:
        print("rollout drift detected:", file=sys.stderr)
        for failure in failures:
            print(f"- {failure}", file=sys.stderr)
        return 1

    print(
        "rollout ok: "
        f"{release.get('label')} "
        f"{release.get('environment')} "
        f"{(release.get('build') or {}).get('image') or 'no-image'}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
