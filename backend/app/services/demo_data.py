"""Deterministic demo data for public DMARQ demo environments."""

from __future__ import annotations

from datetime import date, datetime, time, timedelta, timezone
from typing import Any, Dict, Iterable, List, Optional

from app.services.report_store import ReportStore

DEMO_DOMAINS = ("dmarq.org", "dmarq.com")
DEMO_DAYS = 90

_SOURCE_PROFILES = {
    "dmarq.org": [
        {
            "ip": "203.0.113.10",
            "name": "primary-saas",
            "base": 950,
            "spf": "pass",
            "dkim": "pass",
            "selector": "selector1",
        },
        {
            "ip": "203.0.113.44",
            "name": "newsletter",
            "base": 420,
            "spf": "pass",
            "dkim": "fail",
            "selector": "news",
        },
        {
            "ip": "198.51.100.23",
            "name": "ticketing",
            "base": 180,
            "spf": "fail",
            "dkim": "pass",
            "selector": "zendesk",
        },
        {
            "ip": "192.0.2.66",
            "name": "legacy-crm",
            "base": 55,
            "spf": "fail",
            "dkim": "fail",
            "selector": "legacy",
        },
    ],
    "dmarq.com": [
        {
            "ip": "203.0.113.75",
            "name": "workspace-mail",
            "base": 610,
            "spf": "pass",
            "dkim": "pass",
            "selector": "google",
        },
        {
            "ip": "198.51.100.88",
            "name": "marketing",
            "base": 260,
            "spf": "pass",
            "dkim": "mixed",
            "selector": "mailchimp",
        },
        {
            "ip": "192.0.2.114",
            "name": "billing",
            "base": 130,
            "spf": "fail",
            "dkim": "pass",
            "selector": "stripe",
        },
        {
            "ip": "198.51.100.199",
            "name": "unknown-forwarder",
            "base": 35,
            "spf": "fail",
            "dkim": "fail",
            "selector": "unknown",
        },
    ],
}


def _utc_timestamp(day: date, boundary: time) -> int:
    return int(datetime.combine(day, boundary, tzinfo=timezone.utc).timestamp())


def _utc_iso_from_timestamp(value: int) -> str:
    return (
        datetime.fromtimestamp(value, tz=timezone.utc)
        .replace(tzinfo=None)
        .isoformat(timespec="seconds")
    )


def _policy_for_domain(domain: str) -> Dict[str, str]:
    if domain == "dmarq.org":
        return {
            "p": "quarantine",
            "sp": "reject",
            "pct": "100",
            "adkim": "s",
            "aspf": "r",
            "fo": "1",
            "discovery_method": "author",
        }
    return {
        "p": "none",
        "sp": "quarantine",
        "pct": "100",
        "adkim": "r",
        "aspf": "r",
        "fo": "1:d",
        "testing": "y",
        "discovery_method": "treewalk",
    }


def _result_for(profile: Dict[str, Any], day_index: int, domain: str) -> tuple[str, str]:
    spf = str(profile["spf"])
    dkim = str(profile["dkim"])
    if dkim == "mixed":
        dkim = "pass" if day_index % 3 else "fail"
    if profile["name"] == "legacy-crm" and day_index % 14 == 0:
        return "pass", "fail"
    if profile["name"] == "unknown-forwarder" and day_index % 11 == 0:
        return "fail", "pass"
    if domain == "dmarq.com" and profile["name"] == "marketing" and day_index % 10 == 0:
        return "pass", "fail"
    return spf, dkim


def _count_for(profile: Dict[str, Any], day_index: int) -> int:
    base = int(profile["base"])
    weekly_wave = ((day_index % 7) - 3) * max(2, base // 28)
    incident = 0
    if profile["name"] in {"legacy-crm", "unknown-forwarder"} and day_index % 13 == 0:
        incident = base * 2
    if profile["name"] == "newsletter" and day_index % 7 in {1, 4}:
        incident = base // 2
    return max(1, base + weekly_wave + incident)


def _record(domain: str, profile: Dict[str, Any], day_index: int) -> Dict[str, Any]:
    spf_result, dkim_result = _result_for(profile, day_index, domain)
    count = _count_for(profile, day_index)
    dmarc_pass = spf_result == "pass" or dkim_result == "pass"
    policy = _policy_for_domain(domain)
    disposition = "none"
    if not dmarc_pass and policy["p"] in {"quarantine", "reject"}:
        disposition = policy["p"]
    if not dmarc_pass and domain == "dmarq.com":
        disposition = "none"
    return {
        "source_ip": profile["ip"],
        "count": count,
        "disposition": disposition,
        "dkim_result": dkim_result,
        "spf_result": spf_result,
        "header_from": domain,
        "envelope_from": f"bounce.{domain}",
        "envelope_to": f"recipient-{day_index % 5}.example.net",
        "dkim": [
            {
                "domain": domain,
                "selector": profile["selector"],
                "result": dkim_result,
                "human_result": (
                    "signature verified"
                    if dkim_result == "pass"
                    else "body hash did not verify"
                ),
            }
        ],
        "spf": [
            {
                "domain": f"bounce.{domain}",
                "scope": "mfrom",
                "result": spf_result,
                "human_result": (
                    "sender authorized"
                    if spf_result == "pass"
                    else "sender not authorized by SPF"
                ),
            }
        ],
        "extensions": {
            "demo:source": profile["name"],
            "demo:scenario": "corner-case" if not dmarc_pass else "normal",
        },
    }


def _summary(records: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    rows = list(records)
    total = sum(int(record["count"]) for record in rows)
    passed = sum(
        int(record["count"])
        for record in rows
        if record["spf_result"] == "pass" or record["dkim_result"] == "pass"
    )
    failed = total - passed
    return {
        "total_count": total,
        "passed_count": passed,
        "failed_count": failed,
        "pass_rate": round((passed / total) * 100, 1) if total else 0.0,
    }


def build_demo_reports(today: Optional[date] = None, days: int = DEMO_DAYS) -> List[Dict[str, Any]]:
    """Return rolling synthetic DMARC aggregate reports through *today*."""
    anchor = today or datetime.now(timezone.utc).date()
    reports: List[Dict[str, Any]] = []
    start = anchor - timedelta(days=days - 1)
    for day_offset in range(days):
        report_day = start + timedelta(days=day_offset)
        day_index = (report_day - date(2026, 1, 1)).days
        for domain in DEMO_DOMAINS:
            records = [_record(domain, profile, day_index) for profile in _SOURCE_PROFILES[domain]]
            begin_ts = _utc_timestamp(report_day, time.min)
            end_ts = _utc_timestamp(report_day, time.max.replace(microsecond=0))
            reports.append(
                {
                    "domain": domain,
                    "report_id": f"demo-{domain}-{report_day.isoformat()}",
                    "org_name": "DMARQ Demo Receiver",
                    "email": "reports@demo.dmarq.org",
                    "extra_contact_info": "https://demo.dmarq.org",
                    "generator": "DMARQ demo data generator",
                    "variant": "rfc9990",
                    "schema_version": "1.0",
                    "xml_namespace": "urn:ietf:params:xml:ns:dmarc-2.0",
                    "begin_date": _utc_iso_from_timestamp(begin_ts),
                    "end_date": _utc_iso_from_timestamp(end_ts),
                    "begin_timestamp": begin_ts,
                    "end_timestamp": end_ts,
                    "policy": _policy_for_domain(domain),
                    "records": records,
                    "summary": _summary(records),
                    "extensions": {
                        "demo:rolling_window_days": str(days),
                        "demo:generated_for": anchor.isoformat(),
                    },
                }
            )
    return reports


def seed_demo_report_store(store: Optional[ReportStore] = None) -> int:
    """Replace the report store contents with rolling demo reports."""
    target = store or ReportStore.get_instance()
    target.clear()
    reports = build_demo_reports()
    for report in reports:
        target.add_report(report)
    return len(reports)
