#!/usr/bin/env python3
"""Check that every active direct requirement is represented by the lock."""

from __future__ import annotations

import argparse
from pathlib import Path

from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


def requirements(path: Path) -> list[Requirement]:
    result = []
    for raw in path.read_text().splitlines():
        raw = raw.strip()
        if raw and not raw.startswith("#"):
            result.append(Requirement(raw))
    return result


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("requirements", default="backend/requirements.txt", nargs="?")
    parser.add_argument("lock", default="backend/requirements.lock", nargs="?")
    args = parser.parse_args()

    locked: dict[str, Requirement] = {}
    for requirement in requirements(Path(args.lock)):
        name = canonicalize_name(requirement.name)
        if name in locked:
            raise SystemExit(f"duplicate lock entry: {requirement.name}")
        pins = list(requirement.specifier)
        if len(pins) != 1 or pins[0].operator != "==" or "*" in pins[0].version:
            raise SystemExit(f"lock entry is not an exact == pin: {requirement.name}")
        locked[name] = requirement

    for requirement in requirements(Path(args.requirements)):
        if requirement.marker and not requirement.marker.evaluate():
            continue
        name = canonicalize_name(requirement.name)
        candidate = locked.get(name)
        if candidate is None:
            raise SystemExit(f"missing lock entry: {requirement.name}")
        version = next(iter(candidate.specifier)).version
        if version not in requirement.specifier:
            raise SystemExit(
                f"{requirement.name} locked at {version}, does not satisfy "
                f"{requirement.specifier}"
            )

    print(f"validated {len(locked)} locked packages against direct requirements")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
