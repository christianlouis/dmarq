#!/bin/sh
# Regenerate backend/requirements.lock from the validated DMARQ image.
# The image digest is pinned so lock updates are explicit and reproducible.
set -eu

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
requirements="$repo_root/backend/requirements.txt"
lock="$repo_root/backend/requirements.lock"
image="${DMARQ_LOCK_IMAGE:-ghcr.io/christianlouis/dmarq@sha256:09488e760201e94e1a735308df307d7b1d0160e02577d76a2df06c1edc03409e}"

command -v docker >/dev/null 2>&1 || {
    echo "docker is required to regenerate $lock" >&2
    exit 1
}

if ! printf '%s\n' "$image" | grep -Eq '@sha256:[0-9a-fA-F]{64}$'; then
    echo "DMARQ_LOCK_IMAGE must end in an immutable sha256 digest" >&2
    exit 1
fi

tmp=$(mktemp)
freeze_tmp=$(mktemp)
output_tmp=$(mktemp "$lock.tmp.XXXXXX")
trap 'rm -f "$tmp" "$freeze_tmp" "$output_tmp"' EXIT

# Resolve current requirements in a disposable container. Existing satisfying
# versions are retained; additions and raised minimums are resolved.
# Keeping docker output out of a pipeline prevents a failed run from producing
# an empty or partial lock.
docker run --rm --entrypoint sh \
    -v "$requirements:/opt/dmarq-requirements.txt:ro" \
    "$image" -c '
set -eu
python -m pip install --no-cache-dir --disable-pip-version-check \
    --upgrade-strategy only-if-needed -r /opt/dmarq-requirements.txt >/tmp/dmarq-pip-install.log
python - /opt/dmarq-requirements.txt <<'"'"'PY'"'"'
from importlib.metadata import version
from pathlib import Path
from packaging.requirements import Requirement
import sys

for raw in Path(sys.argv[1]).read_text().splitlines():
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
PY
python -m pip check >&2
pip freeze --local
' > "$freeze_tmp"

sed '/^WARNING:/d' "$freeze_tmp" > "$tmp"
revision=$(docker image inspect "$image" --format '{{index .Config.Labels "org.opencontainers.image.revision"}}')
if [ -z "$revision" ]; then
    echo "image has no OCI revision label: $image" >&2
    exit 1
fi
{
    echo "# Generated from $image by scripts/lock-requirements.sh."
    echo "# OCI revision: $revision."
    echo "# Do not edit by hand; regenerate from the pinned image digest."
    cat "$tmp"
} > "$output_tmp"
mv "$output_tmp" "$lock"

echo "$lock: $(wc -l < "$tmp" | tr -d ' ') packages"
