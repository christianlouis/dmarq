#!/bin/sh

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

config_file=$(mktemp "${TMPDIR:-/tmp}/dmarq-compose.XXXXXX")
trap 'rm -f "$config_file"' EXIT HUP INT TERM

docker compose config --format json > "$config_file"

python3 - "$config_file" "$ROOT_DIR/.env" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    config = json.load(handle)

env_file = {}
with open(sys.argv[2], encoding="utf-8") as handle:
    for raw_line in handle:
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env_file[key] = value.strip().strip('"').strip("'")

services = config["services"]
app = services["app"]
db = services["db"]

for key in ("ENVIRONMENT", "PUBLIC_BASE_URL", "AUTH_MODE", "AUTH_DISABLED", "DATABASE_URL"):
    assert app["environment"][key] == env_file[key], f"{key} from .env was not passed to app"

assert app["image"] == env_file["DMARQ_IMAGE"]
assert len(app["environment"]["SECRET_KEY"]) >= 32
assert len(app["environment"]["ADMIN_API_KEY"]) >= 32
assert "CHANGE_THIS" not in app["environment"]["SECRET_KEY"]
assert "CHANGE_THIS" not in app["environment"]["ADMIN_API_KEY"]
assert app["ports"][0]["target"] == 8080
assert app["ports"][0]["published"] == env_file["DMARQ_PORT"]
assert app["ports"][0]["host_ip"] == env_file["DMARQ_BIND_ADDRESS"]
assert not db.get("ports"), "PostgreSQL must not be published by the default stack"
assert db["environment"]["POSTGRES_DB"] == env_file["POSTGRES_DB"]
assert db["environment"]["POSTGRES_USER"] == env_file["POSTGRES_USER"]
assert db["environment"]["POSTGRES_PASSWORD"] == env_file["POSTGRES_PASSWORD"]
assert app["healthcheck"]["test"][-1].endswith("/healthz")

print("Docker Compose contract verified.")
PY
