"""Regression coverage for Sending Sources alignment (#814)."""

from __future__ import annotations

from pathlib import Path

APP_ROOT = Path(__file__).resolve().parents[1]


def _domain_details() -> str:
    return (APP_ROOT / "templates" / "domain_details.html").read_text(encoding="utf-8")


def _page_utilities() -> str:
    return (APP_ROOT / "static" / "css" / "page-utilities.css").read_text(encoding="utf-8")


def _sending_sources_section() -> str:
    body = _domain_details()
    start = body.index('id="sending-sources"')
    end = body.index('id="recent-reports"', start)
    return body[start:end]


def test_sending_sources_uses_aligned_auth_grid_not_wide_table() -> None:
    section = _sending_sources_section()
    css = _page_utilities()

    assert 'data-sending-sources-list' in section
    assert 'data-sending-source-auth' in section
    assert 'data-auth="spf"' in section
    assert 'data-auth="dkim"' in section
    assert 'data-auth="dmarc"' in section
    assert 'data-auth="disposition"' in section

    # Wide min-width cells caused status displacement / horizontal scroll.
    assert "min-w-52" not in section
    assert "min-w-60" not in section
    assert "min-w-44" not in section
    assert "min-w-72" not in section
    assert "{% call table() %}" not in section

    assert ".sending-source-grid" in css
    assert ".sending-source-auth" in css
    assert "@media (max-width: 767px)" in css
    assert "@media (min-width: 768px)" in css


def test_sending_sources_keeps_auth_and_recommendations_data() -> None:
    section = _sending_sources_section()
    assert "source.spf" in section
    assert "source.dkim" in section
    assert "source.dmarc" in section
    assert "source.disposition" in section
    assert "source.recommendations" in section
    assert "IP intelligence" in section
    assert "sending-source-intel" in section


def test_auth_status_cells_include_labels_beside_badges() -> None:
    section = _sending_sources_section()
    for label in ("SPF", "DKIM", "DMARC", "Disposition"):
        assert f'<span class="auth-label">{label}</span>' in section
