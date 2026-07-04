"""Local browser-smoke server with deterministic DMARC report evidence."""

import atexit
import os
import sys
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(BACKEND_ROOT))

os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault("AUTH_DISABLED", "true")
os.environ.setdefault("ALLOW_AUTH_DISABLED_IN_PRODUCTION", "true")
os.environ.setdefault("SECRET_KEY", "browser-smoke-secret-key-change-me")
SMOKE_DB_PATH = Path(f"/tmp/dmarq-browser-smoke-{os.getpid()}.sqlite")
os.environ.setdefault(
    "DATABASE_URL",
    f"sqlite:///{SMOKE_DB_PATH.as_posix()}",
)
atexit.register(lambda: SMOKE_DB_PATH.unlink(missing_ok=True))
os.environ.setdefault("SOURCE_NETWORK_ENRICHMENT_ENABLED", "false")
os.environ.setdefault("SOURCE_REPUTATION_FEEDS_ENABLED", "false")

from app.main import app  # noqa: E402
from app.services.report_store import ReportStore  # noqa: E402


CKLNET_REPORT = {
    "domain": "cklnet.com",
    "report_id": "browser-smoke-cklnet",
    "org_name": "google.com",
    "email": "noreply-dmarc-support@google.com",
    "begin_timestamp": 1782864000,
    "end_timestamp": 1782950399,
    "begin_date": "2026-07-01",
    "end_date": "2026-07-02",
    "policy": {"p": "reject", "sp": "reject", "pct": "100"},
    "records": [
        {
            "source_ip": "50.31.205.203",
            "count": 8,
            "disposition": "none",
            "dkim_result": "pass",
            "spf_result": "pass",
            "header_from": "cklnet.com",
            "dkim": [{"domain": "cklnet.com", "selector": "pm", "result": "pass"}],
            "spf": [{"domain": "pm.mtasv.net", "result": "pass"}],
        },
        {
            "source_ip": "2a01:4f8:c17:311b::1",
            "count": 1,
            "disposition": "reject",
            "dkim_result": "fail",
            "spf_result": "pass",
            "header_from": "mx1.cklnet.com",
            "dkim": [{"domain": "mx1.cklnet.com", "selector": "mail", "result": "fail"}],
            "spf": [{"domain": "mx1.cklnet.com", "result": "pass"}],
        },
    ],
    "summary": {"total_count": 9, "passed_count": 8, "failed_count": 1, "pass_rate": 88.9},
}


DMARQ_REPORT = {
    "domain": "dmarq.org",
    "report_id": "browser-smoke-dmarq",
    "org_name": "google.com",
    "email": "noreply-dmarc-support@google.com",
    "begin_timestamp": 1782864000,
    "end_timestamp": 1782950399,
    "begin_date": "2026-07-01",
    "end_date": "2026-07-02",
    "policy": {"p": "quarantine", "sp": "quarantine", "pct": "100"},
    "records": [
        {
            "source_ip": "209.85.220.41",
            "count": 24,
            "disposition": "none",
            "dkim_result": "pass",
            "spf_result": "pass",
            "header_from": "dmarq.org",
            "dkim": [{"domain": "dmarq.org", "selector": "google", "result": "pass"}],
            "spf": [{"domain": "_spf.google.com", "result": "pass"}],
        }
    ],
    "summary": {"total_count": 24, "passed_count": 24, "failed_count": 0, "pass_rate": 100.0},
}


def seed_store() -> None:
    store = ReportStore.get_instance()
    store.clear()
    store.add_report(CKLNET_REPORT)
    store.add_report(DMARQ_REPORT)


seed_store()


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        app,
        host="127.0.0.1",
        port=int(os.environ.get("DMARQ_BROWSER_SMOKE_PORT", "18080")),
        log_level="warning",
    )
