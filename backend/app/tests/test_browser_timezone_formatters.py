"""Browser timezone regressions for explicit API instants and calendar dates."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path


def _run_formatter(script_name: str, browser_timezone: str, value: str, function: str) -> str:
    static_dir = Path(__file__).resolve().parents[1] / "static" / "js"
    runner = r"""
const fs = require('fs');
const script = fs.readFileSync(process.argv[1], 'utf8');
const value = process.argv[2];
const functionName = process.argv[3];
const document = {
  addEventListener: () => {},
  documentElement: {
    dataset: {appTimezone: 'Europe/Berlin', appLocale: 'en'},
    lang: 'en', classList: {add: () => {}, remove: () => {}}, setAttribute: () => {},
  },
};
const window = {fetch: async () => ({ok: true})};
global.localStorage = {getItem: () => null, setItem: () => {}, removeItem: () => {}};
new Function('document', 'window', script)(document, window);
process.stdout.write(window[functionName](value));
"""
    result = subprocess.run(
        ["node", "-e", runner, str(static_dir / script_name), value, function],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "TZ": browser_timezone},
    )
    if result.returncode:
        raise AssertionError(result.stderr)
    return result.stdout


def test_datetime_formatter_is_independent_of_browser_timezone_at_dst_boundaries() -> None:
    for value, expected in [
        ("2026-07-16T10:00:00Z", "7/16/26, 12:00:00 PM"),
        ("2026-01-15T23:30:00Z", "1/16/26, 12:30:00 AM"),
    ]:
        outputs = {
            zone: _run_formatter("base-layout.js", zone, value, "dmarqFormatDateTime")
            for zone in ("America/Los_Angeles", "Europe/Berlin")
        }
        assert outputs["America/Los_Angeles"] == outputs["Europe/Berlin"] == expected


def test_date_formatter_preserves_calendar_date_across_browser_timezone() -> None:
    outputs = {
        zone: _run_formatter("localization.js", zone, "2026-07-16", "dmarqFormatDate")
        for zone in ("America/Los_Angeles", "Europe/Berlin", "Pacific/Kiritimati")
    }
    assert (
        outputs["America/Los_Angeles"]
        == outputs["Europe/Berlin"]
        == outputs["Pacific/Kiritimati"]
        == "7/16/2026"
    )
