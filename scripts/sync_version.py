#!/usr/bin/env python3
"""Sync the VERSION file from pyproject.toml after a version bump."""
import re
from pathlib import Path

root = Path(__file__).resolve().parent.parent

toml_content = (root / "pyproject.toml").read_text()
match = re.search(
    r'^\[project\]\s*\n(?:.*\n)*?version\s*=\s*"([^"]+)"',
    toml_content,
    re.MULTILINE,
)
if match:
    version = match.group(1)
    (root / "VERSION").write_text(version + "\n")
