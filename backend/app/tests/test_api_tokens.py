"""Focused tests for scoped API token helpers (#810)."""

from __future__ import annotations

import pytest

from app.services.api_tokens import parse_scopes


@pytest.mark.parametrize(
    ("stored_scopes", "expected"),
    [
        ("reports:read,posture:read", {"reports:read", "posture:read"}),
        (
            " Reports:Read, reports:read, , POSTURE:READ, ",
            {"reports:read", "posture:read"},
        ),
        ("", set()),
        (None, set()),
    ],
)
def test_parse_scopes_normalizes_stored_values(stored_scopes, expected) -> None:
    """Stored scope text remains safe to use after legacy or manual edits."""
    assert parse_scopes(stored_scopes) == expected
