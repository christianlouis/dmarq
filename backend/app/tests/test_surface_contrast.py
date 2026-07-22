"""Regression coverage for surface contrast design tokens (#812)."""

from __future__ import annotations

import math
import re
from pathlib import Path

import pytest

BACKEND_ROOT = Path(__file__).resolve().parents[2]
APP_ROOT = BACKEND_ROOT / "app"


def _hex_to_rgb(value: str) -> tuple[float, float, float]:
    raw = value.lstrip("#")
    if len(raw) != 6:
        raise ValueError(f"expected 6-digit hex, got {value!r}")
    return tuple(int(raw[i : i + 2], 16) / 255.0 for i in (0, 2, 4))


def _channel_luminance(channel: float) -> float:
    return channel / 12.92 if channel <= 0.04045 else ((channel + 0.055) / 1.055) ** 2.4


def relative_luminance(hex_color: str) -> float:
    r, g, b = (_channel_luminance(c) for c in _hex_to_rgb(hex_color))
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def contrast_ratio(foreground: str, background: str) -> float:
    lighter = max(relative_luminance(foreground), relative_luminance(background))
    darker = min(relative_luminance(foreground), relative_luminance(background))
    return (lighter + 0.05) / (darker + 0.05)


def _css_var(source: str, name: str) -> str:
    match = re.search(rf"{re.escape(name)}:\s*(#[0-9a-fA-F]{{6}})", source)
    assert match, f"missing CSS variable {name}"
    return match.group(1).lower()


def _tailwind_theme_color(name: str) -> str:
    config = (BACKEND_ROOT / "tailwind.config.cjs").read_text(encoding="utf-8")
    match = re.search(rf"'{re.escape(name)}':\s*'(#[0-9a-fA-F]{{6}})'", config)
    assert match, f"missing daisyUI theme color {name}"
    return match.group(1).lower()


@pytest.fixture(scope="module")
def surface_tokens() -> dict[str, str]:
    utilities = (APP_ROOT / "static" / "css" / "page-utilities.css").read_text(
        encoding="utf-8"
    )
    styles = (APP_ROOT / "static" / "css" / "styles.css").read_text(encoding="utf-8")
    tokens = {
        "canvas": _css_var(utilities, "--dmarq-canvas"),
        "section": _css_var(utilities, "--dmarq-surface-section"),
        "card": _css_var(utilities, "--dmarq-surface-card"),
        "control": _css_var(utilities, "--dmarq-surface-control"),
        "border": _css_var(utilities, "--dmarq-border-strong"),
        "text": _css_var(utilities, "--dmarq-text"),
        "success": _css_var(utilities, "--dmarq-status-success"),
        "warning": _css_var(utilities, "--dmarq-status-warning"),
        "error": _css_var(utilities, "--dmarq-status-error"),
    }
    # styles.css must stay aligned with the runtime tokens.
    assert _css_var(styles, "--dmarq-canvas") == tokens["canvas"]
    assert _css_var(styles, "--dmarq-surface-card") == tokens["card"]
    return tokens


def test_surface_ladder_has_perceptible_contrast(surface_tokens: dict[str, str]) -> None:
    """Canvas, section, and card fills must differ enough to scan operational views."""
    canvas_l = relative_luminance(surface_tokens["canvas"])
    section_l = relative_luminance(surface_tokens["section"])
    card_l = relative_luminance(surface_tokens["card"])

    assert canvas_l < section_l < card_l
    assert section_l - canvas_l >= 0.05
    assert card_l - section_l >= 0.04
    assert card_l - canvas_l >= 0.12

    border_l = relative_luminance(surface_tokens["border"])
    assert abs(card_l - border_l) >= 0.15


def test_text_and_status_meet_wcag_aa(surface_tokens: dict[str, str]) -> None:
    """Body text and status colors remain AA against card/control surfaces."""
    text = surface_tokens["text"]
    for surface_key in ("canvas", "section", "card", "control"):
        ratio = contrast_ratio(text, surface_tokens[surface_key])
        assert ratio >= 4.5, f"{surface_key} text contrast {ratio:.2f} < 4.5"

    card = surface_tokens["card"]
    for status_key in ("success", "warning", "error"):
        ratio = contrast_ratio(surface_tokens[status_key], card)
        assert ratio >= 3.0, f"{status_key} status contrast {ratio:.2f} < 3.0"


def test_daisyui_theme_aligns_with_surface_tokens(surface_tokens: dict[str, str]) -> None:
    assert _tailwind_theme_color("base-100") == surface_tokens["card"]
    assert _tailwind_theme_color("base-200") != surface_tokens["card"]
    assert _tailwind_theme_color("base-300") == surface_tokens["border"]
    assert _tailwind_theme_color("base-content") == surface_tokens["text"]


def test_layout_and_card_use_surface_tokens() -> None:
    base = (APP_ROOT / "templates" / "layouts" / "base.html").read_text(encoding="utf-8")
    card = (APP_ROOT / "templates" / "components" / "ui" / "card.html").read_text(
        encoding="utf-8"
    )
    utilities = (APP_ROOT / "static" / "css" / "page-utilities.css").read_text(
        encoding="utf-8"
    )

    assert "dmarq-canvas" in base
    assert "bg-[#f4f3f2]" not in base
    assert "surface-card" in card
    assert ".surface-section" in utilities
    assert ".input.input-bordered" in utilities


def test_operational_views_keep_card_hierarchy() -> None:
    """Do not flatten advanced views — cards remain the primary surface container."""
    templates = {
        "index.html",
        "domains.html",
        "domain_details.html",
        "reports.html",
        "mail_sources.html",
        "settings.html",
    }
    for name in templates:
        body = (APP_ROOT / "templates" / name).read_text(encoding="utf-8")
        assert "card" in body.lower() or '{% call card()' in body
        # Narrow-width layout scaffolding remains present.
        assert "md:" in body or "sm:" in body or "lg:" in body


def test_relative_luminance_math_is_stable() -> None:
    assert math.isclose(relative_luminance("#ffffff"), 1.0, abs_tol=1e-6)
    assert relative_luminance("#000000") == 0.0
    assert contrast_ratio("#000000", "#ffffff") == pytest.approx(21.0)
