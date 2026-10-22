#!/bin/sh
# Regenerate backend/requirements.lock from the validated DMARQ image.
# The image digest is pinned so lock updates are explicit and reproducible.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
requirements="$repo_root/backend/requirements.txt"
lock="$repo_root/backend/requirements.lock"
image="${DMARQ_LOCK_IMAGE:-ghcr.io/christianlouis/dmarq@sha256:e468bb30a7a9d680f3a0b3c367f11abd8f89ed10bed200745d409bd4e644a83b}"

command -v docker >/dev/null 2>&1 || {
    echo "docker is required to regenerate $lock" >&2
    exit 1
}

tmp=$(mktemp)
trap 'rm -f "$tmp"' EXIT

docker run --rm --entrypoint python \
    -v "$requirements:/opt/dmarq-requirements.txt:ro" \
    "$image" -c '
from importlib.metadata import version
from pathlib import Path
from packaging.requirements import Requirement

for raw in Path("/opt/dmarq-requirements.txt").read_text().splitlines():
    raw = raw.strip()
    if not raw or raw.startswith("#"):
        continue
    requirement = Requirement(raw)
    if requirement.marker and not requirement.marker.evaluate():
        continue
    installed = version(requirement.name)
    if installed not in requirement.specifier:
        raise SystemExit(
            f"{requirement.name}=={installed} does not satisfy {requirement.specifier}"
        )
' 

docker run --rm --entrypoint sh "$image" -c 'pip freeze --local' \
    | sed '/^WARNING:/d' > "$tmp"

{
    echo "# Generated from $image by scripts/lock-requirements.sh."
    echo "# Do not edit by hand; regenerate from the pinned image digest."
    cat "$tmp"
} > "$lock"

echo "$lock: $(wc -l < "$tmp" | tr -d ' ') packages"
