#!/usr/bin/env python3
"""Reject accidental German operator copy outside explicit locale resources."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
SCAN_ROOTS = (ROOT / "backend" / "app", ROOT / "docs", ROOT / ".github")
EXCLUDED_PARTS = {
    "localization.py",
    "localization.js",
    "_REMEDIATION_STEPS_DE",
    "test_localization.py",
    "test_report_intake_recommendation.py",
    "test_dns_guidance.py",
    "test_diagnostic_plan.py",
    "diagnostic_plan.py",
    "report_intake_recommendation.py",
    "mail_health_guidance.py",
    "dns_guidance.py",
    "demo_provider.py",
    "demo_provider_seed.py",
    "provider_demo.html",
    "provider-demo-page.js",
    "base-layout.js",
    "base.html",
    "test_dashboard_template_security.py",
    "test_dns_endpoints.py",
}
GERMAN_MARKERS = re.compile(
    r"\b(?:für|fuer|nicht|noch|eine|einen|einem|einer|"
    r"keine|kann|muss|wird|werden|Prüfe|Pruefe|Öffne|Oeffne|Änder|Aender|"
    r"Bericht|Postfach|Sitzung|Kunde|Bestätige|Bestaetige)\b",
    re.IGNORECASE,
)


def allowed(path: Path) -> bool:
    return any(marker in path.name for marker in EXCLUDED_PARTS)


def main() -> int:
    findings = []
    for root in SCAN_ROOTS:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if not path.is_file() or allowed(path):
                continue
            if path.suffix not in {".py", ".js", ".html", ".md", ".yml", ".yaml"}:
                continue
            try:
                lines = path.read_text(encoding="utf-8").splitlines()
            except UnicodeDecodeError:
                continue
            for number, line in enumerate(lines, start=1):
                if GERMAN_MARKERS.search(line):
                    findings.append(f"{path.relative_to(ROOT)}:{number}: {line.strip()}")
    if findings:
        print("German source literals found outside approved locale resources:")
        print("\n".join(findings))
        return 1
    print("English canonical source check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
