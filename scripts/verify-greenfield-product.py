#!/usr/bin/env python3
"""Exercise the documented standalone product flow against a running DMARQ."""

from __future__ import annotations

import argparse
import json
import secrets
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any, Optional

DEFAULT_FIXTURE = Path("backend/app/tests/fixtures/dmarc_aggregate/rfc7489-google.xml")


def _request(
    base_url: str,
    path: str,
    *,
    method: str = "GET",
    payload: Optional[dict[str, Any]] = None,
    body: Optional[bytes] = None,
    content_type: Optional[str] = None,
    expected_status: int = 200,
) -> Any:
    headers = {"Accept": "application/json"}
    data = body
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"
    elif content_type:
        headers["Content-Type"] = content_type

    request = urllib.request.Request(
        f"{base_url.rstrip('/')}{path}",
        data=data,
        headers=headers,
        method=method,
    )
    try:
        response = urllib.request.urlopen(request, timeout=30)  # noqa: S310
        status = response.status
        raw = response.read()
    except urllib.error.HTTPError as exc:
        status = exc.code
        raw = exc.read()
    if status != expected_status:
        detail = raw.decode("utf-8", errors="replace")[:1000]
        raise AssertionError(
            f"{method} {path} returned {status}, expected {expected_status}: {detail}"
        )
    if not raw:
        return None
    return json.loads(raw)


def _upload_fixture(base_url: str, fixture: Path, *, expected_status: int = 200) -> Any:
    boundary = f"----dmarq-greenfield-{secrets.token_hex(12)}"
    filename = fixture.name
    body = b"".join(
        [
            f"--{boundary}\r\n".encode(),
            (f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n').encode(),
            b"Content-Type: application/xml\r\n\r\n",
            fixture.read_bytes(),
            f"\r\n--{boundary}--\r\n".encode(),
        ]
    )
    return _request(
        base_url,
        "/api/v1/reports/upload",
        method="POST",
        body=body,
        content_type=f"multipart/form-data; boundary={boundary}",
        expected_status=expected_status,
    )


def _assert_persisted_product_state(base_url: str) -> None:
    status = _request(base_url, "/api/v1/setup/status")
    assert status["is_setup_complete"] is True
    assert status["total_domains"] == 1

    domains = _request(base_url, "/api/v1/reports/domains")
    assert domains == ["example.com"]

    stats = _request(base_url, "/api/v1/domains/example.com/stats")
    assert stats["reportCount"] == 1
    assert stats["totalEmails"] == 2
    assert stats["failedEmails"] == 0
    assert stats["complianceRate"] == 100.0

    reports = _request(base_url, "/api/v1/domains/example.com/reports")
    assert len(reports["reports"]) == 1
    assert reports["reports"][0]["id"] == "123456789"

    release = _request(base_url, "/api/v1/health/release")
    assert release["version"]
    assert release["environment"]


def _initialize(base_url: str, fixture: Path, owner_email: str) -> None:
    status = _request(base_url, "/api/v1/setup/status")
    assert status["is_setup_complete"] is False, "Expected a clean, unconfigured instance"

    _request(
        base_url,
        "/api/v1/setup/admin",
        method="POST",
        payload={"email": owner_email},
        expected_status=201,
    )
    _request(
        base_url,
        "/api/v1/setup/system",
        method="POST",
        payload={
            "app_name": "DMARQ Greenfield Acceptance",
            "base_url": base_url.rstrip("/"),
            "cloudflare_enabled": False,
        },
    )

    _import_fixture(base_url, fixture)


def _import_fixture(base_url: str, fixture: Path) -> None:
    uploaded = _upload_fixture(base_url, fixture)
    assert uploaded["success"] is True
    assert uploaded["domain"] == "example.com"
    assert uploaded["processed_records"] == 2

    duplicate = _upload_fixture(base_url, fixture, expected_status=409)
    assert "already been uploaded" in duplicate["detail"]
    _assert_persisted_product_state(base_url)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default="http://127.0.0.1:8080")
    parser.add_argument("--fixture", type=Path, default=DEFAULT_FIXTURE)
    parser.add_argument("--owner-email", default="greenfield-test@dmarq.org")
    parser.add_argument("--verify-existing", action="store_true")
    parser.add_argument("--configured", action="store_true")
    args = parser.parse_args()

    if not args.verify_existing and not args.fixture.is_file():
        parser.error(f"Fixture not found: {args.fixture}")

    try:
        if args.verify_existing:
            _assert_persisted_product_state(args.base_url)
            print("Greenfield product persistence verified.")
        elif args.configured:
            status = _request(args.base_url, "/api/v1/setup/status")
            assert status["is_setup_complete"] is True
            assert status["total_domains"] == 0
            _import_fixture(args.base_url, args.fixture)
            print("Configured greenfield fixture import and totals verified.")
        else:
            _initialize(args.base_url, args.fixture, args.owner_email)
            print("Greenfield setup, fixture import, totals, and duplicate handling verified.")
    except (AssertionError, OSError, ValueError, KeyError) as exc:
        print(f"Greenfield product verification failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
