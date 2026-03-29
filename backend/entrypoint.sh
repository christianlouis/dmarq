#!/bin/sh
# entrypoint.sh – prepare the database and start the application.
#
# Responsibilities:
#   1. Create the data directory so SQLite can write its file there.
#   2. Ensure Alembic migration tracking is consistent (stamp existing
#      databases that were created before Alembic was introduced).
#   3. Apply all pending Alembic migrations (alembic upgrade head).
#   4. Hand off to the real application process.

set -e

DATA_DIR="${DATA_DIR:-/app/data}"
mkdir -p "$DATA_DIR"

echo "==> Running database migrations …"

# If the database already has tables but no alembic_version table (i.e. it
# was bootstrapped via SQLAlchemy create_all before this entrypoint was
# introduced), stamp it at the current head so that subsequent 'upgrade head'
# calls are no-ops rather than errors.
python - <<'PYEOF'
import sys
try:
    from sqlalchemy import inspect, text
    from app.core.database import engine

    with engine.connect() as conn:
        insp = inspect(conn)
        tables = insp.get_table_names()

    if "alembic_version" not in tables and tables:
        import subprocess
        print(
            "WARNING: database has tables but no alembic_version – "
            "stamping head to record current schema state."
        )
        result = subprocess.run(
            ["alembic", "stamp", "head"],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            print("ERROR: alembic stamp failed:", result.stderr, file=sys.stderr)
            sys.exit(1)
        print(result.stdout)
except Exception as exc:  # noqa: BLE001
    # If we cannot connect at all (e.g. Postgres not ready yet), let
    # 'alembic upgrade head' handle the error with a clear message.
    print(f"WARNING: pre-migration inspection skipped: {exc}")
PYEOF

alembic upgrade head
echo "==> Migrations complete."

echo "==> Starting application …"
exec uvicorn app.main:app --host 0.0.0.0 --port "${PORT:-8080}"
