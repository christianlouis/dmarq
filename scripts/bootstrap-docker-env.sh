#!/bin/sh

set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
ENV_FILE="$ROOT_DIR/.env"
EXAMPLE_FILE="$ROOT_DIR/.env.example"

umask 077

if ! command -v openssl >/dev/null 2>&1; then
    echo "openssl is required to generate stable DMARQ secrets." >&2
    exit 1
fi

if [ ! -f "$ENV_FILE" ]; then
    cp "$EXAMPLE_FILE" "$ENV_FILE"
    echo "Created .env from .env.example."
fi

read_value() {
    key=$1
    awk -F= -v key="$key" '
        $1 == key {
            value = substr($0, index($0, "=") + 1)
            gsub(/^"|"$/, "", value)
            print value
            exit
        }
    ' "$ENV_FILE"
}

write_value() {
    key=$1
    value=$2
    tmp_file=$(mktemp "${ENV_FILE}.XXXXXX")
    awk -v key="$key" -v value="$value" '
        BEGIN { replaced = 0 }
        $0 ~ ("^" key "=") {
            print key "=\"" value "\""
            replaced = 1
            next
        }
        { print }
        END {
            if (!replaced) {
                print key "=\"" value "\""
            }
        }
    ' "$ENV_FILE" > "$tmp_file"
    mv "$tmp_file" "$ENV_FILE"
}

ensure_generated_value() {
    key=$1
    placeholder=$2
    current=$(read_value "$key")
    if [ -z "$current" ] || [ "$current" = "$placeholder" ]; then
        write_value "$key" "$(openssl rand -hex 32)"
    fi
}

ensure_default_value() {
    key=$1
    default_value=$2
    if [ -z "$(read_value "$key")" ]; then
        write_value "$key" "$default_value"
    fi
}

ensure_default_value DMARQ_BIND_ADDRESS 127.0.0.1
ensure_default_value DMARQ_PORT 8080
ensure_default_value DMARQ_IMAGE ghcr.io/christianlouis/dmarq:docker-stable
ensure_default_value POSTGRES_DB dmarq
ensure_default_value POSTGRES_USER dmarq
ensure_generated_value SECRET_KEY CHANGE_THIS_TO_A_RANDOM_SECRET_IN_PRODUCTION
ensure_generated_value ADMIN_API_KEY CHANGE_THIS_TO_A_RANDOM_ADMIN_API_KEY
ensure_generated_value POSTGRES_PASSWORD CHANGE_THIS_DOCKER_POSTGRES_PASSWORD

postgres_user=$(read_value POSTGRES_USER)
postgres_db=$(read_value POSTGRES_DB)
postgres_password=$(read_value POSTGRES_PASSWORD)
database_url=$(read_value DATABASE_URL)

if [ -z "$database_url" ] || [ "$database_url" = "postgresql://dmarq:CHANGE_THIS_DOCKER_POSTGRES_PASSWORD@db:5432/dmarq" ]; then
    write_value DATABASE_URL "postgresql://${postgres_user}:${postgres_password}@db:5432/${postgres_db}"
fi

chmod 600 "$ENV_FILE"
echo "DMARQ Docker environment is ready in .env (secret values were not printed)."
