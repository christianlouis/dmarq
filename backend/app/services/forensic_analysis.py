import json
import re
from collections import Counter
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

from app.models.report import ForensicReport
from app.services.forensic_redaction import ForensicRedactionPolicy, redact_forensic_value

AUTH_RESULT_PATTERN = re.compile(r"\b(dkim|spf|dmarc)=([a-zA-Z0-9_-]+)", re.IGNORECASE)
HEADER_DOMAIN_PATTERN = re.compile(r"\bheader\.d=([^;\s]+)", re.IGNORECASE)
MAILFROM_DOMAIN_PATTERN = re.compile(r"\bsmtp\.mailfrom=([^;\s]+)", re.IGNORECASE)
PRIORITY_ORDER = {"high": 3, "medium": 2, "low": 1}


def _clean_value(value: Any) -> str:
    return str(value or "").strip()


def _normalize(value: Any) -> str:
    return _clean_value(value).lower()


def _feedback_headers(row: ForensicReport) -> Dict[str, Any]:
    if not row.feedback_headers:
        return {}
    try:
        parsed = json.loads(row.feedback_headers)
    except (json.JSONDecodeError, TypeError):
        return {}
    return parsed if isinstance(parsed, dict) else {}


def _parse_authentication_results(value: str) -> Dict[str, str]:
    results: Dict[str, str] = {}
    for mechanism, result in AUTH_RESULT_PATTERN.findall(value or ""):
        results[mechanism.lower()] = result.lower()
    return results


def _first_match(pattern: re.Pattern[str], value: str) -> str:
    match = pattern.search(value or "")
    return match.group(1).lower().strip(".,") if match else ""


def _failure_kind(row: ForensicReport, auth_results: Dict[str, str]) -> str:
    reported = _normalize(row.auth_failure)
    if reported in {"dkim", "spf", "dmarc", "both"}:
        return reported
    failed = {name for name, result in auth_results.items() if result in {"fail", "softfail"}}
    if {"dkim", "spf"}.issubset(failed):
        return "both"
    for mechanism in ("dmarc", "dkim", "spf"):
        if mechanism in failed:
            return mechanism
    return reported or "unknown"


def _priority(row: ForensicReport, failure_kind: str) -> str:
    delivery = _normalize(row.delivery_result)
    if delivery in {"reject", "quarantine"}:
        return "high"
    if failure_kind in {"both", "dmarc"}:
        return "high"
    if failure_kind in {"dkim", "spf"}:
        return "medium"
    return "low"


def _diagnosis(failure_kind: str, auth_results: Dict[str, str], delivery_result: str) -> str:
    delivery = _normalize(delivery_result)
    rejected = delivery in {"reject", "quarantine"}
    suffix = " The receiver enforced the failure." if rejected else ""
    if failure_kind == "both":
        return "Both DKIM and SPF failed, so DMARC could not find an aligned pass." + suffix
    if failure_kind == "dmarc":
        return "DMARC failed after the receiver evaluated DKIM and SPF alignment." + suffix
    if failure_kind == "dkim":
        if auth_results.get("spf") == "pass":
            return "DKIM failed while SPF passed; focus on DKIM signing and alignment." + suffix
        return "DKIM failed for the reported message sample." + suffix
    if failure_kind == "spf":
        if auth_results.get("dkim") == "pass":
            return (
                "SPF failed while DKIM passed; focus on SPF authorization and alignment." + suffix
            )
        return "SPF failed for the reported message sample." + suffix
    return "The receiver reported an authentication failure, but did not include a clear mechanism."


def _recommendations(
    failure_kind: str,
    auth_results: Dict[str, str],
    source_ip: str,
    reported_domain: str,
) -> List[str]:
    actions: List[str] = []
    if failure_kind in {"dkim", "both", "dmarc"}:
        actions.append(
            "Confirm the sending system signs mail with a DKIM domain aligned to the visible From domain."
        )
        actions.append(
            "Check recent DKIM key, selector, and canonicalization changes for this sender."
        )
    if failure_kind in {"spf", "both", "dmarc"}:
        actions.append(
            "Verify the source IP or provider include is authorized in the domain SPF record."
        )
        actions.append(
            "Review forwarding paths, because forwarding commonly breaks SPF while preserving DKIM."
        )
    if auth_results.get("spf") == "pass" and failure_kind == "dkim":
        actions.append(
            "If SPF is aligned and passing, this may be a DKIM-only repair rather than a sender authorization issue."
        )
    if auth_results.get("dkim") == "pass" and failure_kind == "spf":
        actions.append(
            "If DKIM is aligned and passing, treat SPF repair as lower risk before changing DMARC policy."
        )
    if source_ip:
        actions.append(
            f"Compare {source_ip} with known mail sources for {reported_domain or 'this domain'}."
        )
    actions.append(
        "Keep using redacted forensic metadata; do not import or retain message bodies for this investigation."
    )
    return actions


def _signals(
    row: ForensicReport,
    feedback_headers: Dict[str, Any],
    auth_results: Dict[str, str],
    header_domain: str,
    mailfrom_domain: str,
) -> List[str]:
    signals = []
    if row.source_ip:
        signals.append(f"Source IP: {row.source_ip}")
    if row.reported_domain:
        signals.append(f"Reported domain: {row.reported_domain}")
    if row.auth_failure:
        signals.append(f"Failure: {row.auth_failure}")
    if row.delivery_result:
        signals.append(f"Delivery result: {row.delivery_result}")
    if header_domain:
        signals.append(f"DKIM header domain: {header_domain}")
    if mailfrom_domain:
        signals.append(f"SPF mail-from domain: {mailfrom_domain}")
    signals.extend(_rfc9991_feedback_signals(feedback_headers))
    for mechanism, result in sorted(auth_results.items()):
        signals.append(f"{mechanism.upper()} result: {result}")
    return signals


def _rfc9991_feedback_signals(feedback_headers: Dict[str, Any]) -> List[str]:
    signals = []
    identity_alignment = _clean_value(feedback_headers.get("identity_alignment"))
    if identity_alignment:
        signals.append(f"Identity alignment: {identity_alignment}")
    dkim_identity = _clean_value(feedback_headers.get("dkim_identity"))
    if dkim_identity:
        signals.append(f"DKIM identity: {dkim_identity}")
    dkim_selector = _clean_value(feedback_headers.get("dkim_selector"))
    if dkim_selector:
        signals.append(f"DKIM selector: {dkim_selector}")
    spf_dns = _clean_value(feedback_headers.get("spf_dns"))
    if spf_dns:
        signals.append(f"SPF DNS: {spf_dns}")
    if feedback_headers.get("dkim_canonicalized_header_present"):
        signals.append("DKIM canonicalized header was supplied but not stored")
    if feedback_headers.get("dkim_canonicalized_body_present"):
        signals.append("DKIM canonicalized body was supplied but not stored")
    return signals


def analyze_forensic_report(
    row: ForensicReport,
    redaction_policy: Optional[ForensicRedactionPolicy] = None,
) -> Dict[str, Any]:
    """Build a privacy-preserving operator analysis for one forensic sample."""
    feedback_headers = _feedback_headers(row)
    auth_results = _parse_authentication_results(row.authentication_results or "")
    header_domain = _first_match(
        HEADER_DOMAIN_PATTERN, row.authentication_results or ""
    ) or _normalize(feedback_headers.get("dkim_domain"))
    mailfrom_value = _first_match(MAILFROM_DOMAIN_PATTERN, row.authentication_results or "")
    mailfrom_domain = mailfrom_value.rsplit("@", 1)[-1] if "@" in mailfrom_value else mailfrom_value
    failure_kind = _failure_kind(row, auth_results)
    priority = _priority(row, failure_kind)
    reported_domain = _clean_value(row.reported_domain or (row.domain.name if row.domain else ""))
    source_ip = _clean_value(row.source_ip)

    analysis = {
        "id": row.id,
        "report_id": row.report_id,
        "domain": reported_domain,
        "source_ip": source_ip,
        "auth_failure": failure_kind,
        "delivery_result": _clean_value(row.delivery_result),
        "priority": priority,
        "diagnosis": _diagnosis(failure_kind, auth_results, row.delivery_result or ""),
        "recommendations": _recommendations(
            failure_kind,
            auth_results,
            source_ip,
            reported_domain,
        ),
        "signals": _signals(row, feedback_headers, auth_results, header_domain, mailfrom_domain),
        "authentication_results": auth_results,
        "dkim_domain": header_domain,
        "mail_from_domain": mailfrom_domain,
        "privacy_note": "Analysis uses redacted headers and metadata only; message bodies are not stored.",
    }
    return redact_forensic_value(analysis, redaction_policy) if redaction_policy else analysis


def _group_key(row: ForensicReport) -> Tuple[str, str, str, str]:
    return (
        _clean_value(row.reported_domain or (row.domain.name if row.domain else "")) or "unknown",
        _clean_value(row.source_ip) or "unknown",
        _normalize(row.auth_failure) or "unknown",
        _normalize(row.delivery_result) or "unknown",
    )


def _latest(left: Optional[datetime], right: Optional[datetime]) -> Optional[datetime]:
    if left is None:
        return right
    if right is None:
        return left
    return max(left, right)


def summarize_forensic_samples(
    rows: Iterable[ForensicReport],
    redaction_policy: Optional[ForensicRedactionPolicy] = None,
    total_available: Optional[int] = None,
) -> Dict[str, Any]:
    """Summarize forensic samples into investigation groups and top examples."""
    reports = list(rows)
    analyses = [analyze_forensic_report(row, redaction_policy=redaction_policy) for row in reports]
    priority_counts = Counter(item["priority"] for item in analyses)
    failure_counts = Counter(item["auth_failure"] for item in analyses)
    result_counts = Counter(item["delivery_result"] for item in analyses)
    grouped: Dict[Tuple[str, str, str, str], Dict[str, Any]] = {}

    for row, analysis in zip(reports, analyses):
        key = (
            analysis["domain"],
            analysis["source_ip"],
            analysis["auth_failure"],
            analysis["delivery_result"],
        )
        group = grouped.setdefault(
            key,
            {
                "key": "|".join(key),
                "domain": key[0],
                "source_ip": key[1],
                "auth_failure": analysis["auth_failure"],
                "delivery_result": analysis["delivery_result"],
                "count": 0,
                "priority": analysis["priority"],
                "latest_arrival": None,
                "diagnosis": analysis["diagnosis"],
                "recommendations": analysis["recommendations"][:3],
            },
        )
        group["count"] += 1
        group["latest_arrival"] = _latest(
            group["latest_arrival"], row.arrival_date or row.processed_at
        )
        if PRIORITY_ORDER[analysis["priority"]] > PRIORITY_ORDER[group["priority"]]:
            group["priority"] = analysis["priority"]
            group["diagnosis"] = analysis["diagnosis"]
            group["recommendations"] = analysis["recommendations"][:3]

    groups = sorted(
        grouped.values(),
        key=lambda item: (
            PRIORITY_ORDER[item["priority"]],
            item["count"],
            item["latest_arrival"] or datetime.min,
        ),
        reverse=True,
    )
    for group in groups:
        if group["latest_arrival"] is not None:
            group["latest_arrival"] = group["latest_arrival"].isoformat()

    samples = sorted(
        analyses,
        key=lambda item: (PRIORITY_ORDER[item["priority"]], item["id"] or 0),
        reverse=True,
    )
    return {
        "total_available": total_available if total_available is not None else len(reports),
        "analyzed": len(reports),
        "priority_counts": dict(priority_counts),
        "failure_counts": dict(failure_counts),
        "result_counts": dict(result_counts),
        "groups": groups,
        "samples": samples,
    }
