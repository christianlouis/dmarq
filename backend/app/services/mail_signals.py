"""Versioned, protocol-aware evidence signals for mail-health interpretation.

The signal envelope keeps protocol observations separate from DMARQ's
interpretation.  It is intentionally serializable and provider-neutral so the
same contract can later carry TLS-RPT, DSN, and provider delivery events
without re-labelling aggregate DMARC evidence as delivery evidence.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Mapping, Sequence

MAIL_SIGNAL_SCHEMA_VERSION = "dmarq.mail_signal.v1"

SIGNAL_FAMILIES = frozenset(
    {
        "dmarc_authentication",
        "dmarc_reported_disposition",
        "dmarc_failure_detail",
        "smtp_tls_report",
        "dsn_delivery_status",
        "provider_delivery_event",
        "dns_posture",
        "intake_health",
        "operator_reported_symptom",
    }
)

CLAIM_LEVELS = frozenset({"observed", "derived", "inferred", "operator_reported", "unknown"})

DELIVERY_CERTAINTIES = frozenset(
    {
        "not_applicable",
        "authentication_only",
        "receiver_disposition_reported",
        "transport_failure_reported",
        "non_delivery_reported",
        "delivery_reported",
        "inferred_only",
    }
)

PRIVACY_CLASSES = frozenset({"aggregate", "redacted", "restricted"})


def _stable_signal_id(parts: Mapping[str, Any]) -> str:
    encoded = json.dumps(parts, sort_keys=True, separators=(",", ":"), default=str)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _bounded_count(value: object) -> int:
    try:
        return max(0, int(value or 0))
    except (TypeError, ValueError):
        return 0


def _string_values(value: object) -> list[str]:
    if not isinstance(value, (list, tuple, set, frozenset)):
        return []
    return sorted({str(item).strip() for item in value if str(item).strip()})


@dataclass(frozen=True)
class MailSignal:
    """Common envelope for observed, derived, and operator-reported evidence."""

    family: str
    signal_type: str
    outcome: str
    claim_level: str
    delivery_certainty: str
    source_system: str
    workspace_id: int | None = None
    domain: str | None = None
    correlation_key: str | None = None
    observed_at: str | None = None
    window_start: int | None = None
    window_end: int | None = None
    reason_code: str | None = None
    count: int = 0
    confidence: str = "high"
    confidence_reasons: tuple[str, ...] = field(default_factory=tuple)
    freshness: str = "current"
    privacy_classification: str = "aggregate"
    evidence_refs: tuple[str, ...] = field(default_factory=tuple)
    guidance_key: str | None = None
    payload: Mapping[str, Any] = field(default_factory=dict)
    schema_version: str = MAIL_SIGNAL_SCHEMA_VERSION
    signal_id: str = ""

    def __post_init__(self) -> None:
        if self.family not in SIGNAL_FAMILIES:
            raise ValueError(f"Unsupported mail-signal family: {self.family}")
        if self.claim_level not in CLAIM_LEVELS:
            raise ValueError(f"Unsupported claim level: {self.claim_level}")
        if self.delivery_certainty not in DELIVERY_CERTAINTIES:
            raise ValueError(f"Unsupported delivery certainty: {self.delivery_certainty}")
        if self.privacy_classification not in PRIVACY_CLASSES:
            raise ValueError(
                f"Unsupported mail-signal privacy classification: {self.privacy_classification}"
            )
        if not self.signal_id:
            object.__setattr__(
                self,
                "signal_id",
                _stable_signal_id(
                    {
                        "schema_version": self.schema_version,
                        "workspace_id": self.workspace_id,
                        "domain": self.domain,
                        "family": self.family,
                        "signal_type": self.signal_type,
                        "correlation_key": self.correlation_key,
                        "window_start": self.window_start,
                        "window_end": self.window_end,
                        "evidence_refs": self.evidence_refs,
                    }
                ),
            )
        object.__setattr__(self, "count", _bounded_count(self.count))

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["confidence_reasons"] = list(self.confidence_reasons)
        result["evidence_refs"] = list(self.evidence_refs)
        result["payload"] = dict(self.payload)
        return result


def make_mail_signal(**values: Any) -> MailSignal:
    """Build and validate one signal from a typed source adapter."""
    return MailSignal(**values)


def _disposition_outcome(dispositions: Mapping[str, Any]) -> tuple[str, int]:
    normalized = {
        str(key).strip().lower(): _bounded_count(value)
        for key, value in dispositions.items()
        if _bounded_count(value)
    }
    if not normalized:
        return "unknown", 0
    if len(normalized) == 1:
        outcome, count = next(iter(normalized.items()))
        return outcome if outcome in {"none", "quarantine", "reject"} else "other", count
    return "mixed", sum(normalized.values())


def build_dmarc_source_signals(
    source: Mapping[str, Any],
    *,
    workspace_id: int | None,
    domain: str,
    evidence_refs: Sequence[str] = (),
) -> list[dict[str, Any]]:
    """Return separate authentication and receiver-disposition observations."""
    passed = _bounded_count(source.get("dmarc_pass_count"))
    failed = _bounded_count(source.get("dmarc_fail_count"))
    if passed and failed:
        authentication_outcome = "mixed"
    elif passed:
        authentication_outcome = "pass"
    elif failed:
        authentication_outcome = "fail"
    else:
        authentication_outcome = "unknown"

    source_ip = str(source.get("source_ip") or "unknown")
    correlation_key = f"{domain}:{source_ip}"
    common = {
        "workspace_id": workspace_id,
        "domain": domain,
        "correlation_key": correlation_key,
        "window_start": source.get("window_start"),
        "window_end": source.get("window_end"),
        "observed_at": str(source.get("captured_at") or "") or None,
        "source_system": "dmarc_aggregate_report",
        "claim_level": "observed",
        "freshness": str(source.get("freshness") or "current"),
        "privacy_classification": "aggregate",
        "evidence_refs": tuple(sorted({str(item) for item in evidence_refs if str(item)})),
    }
    authentication = make_mail_signal(
        **common,
        family="dmarc_authentication",
        signal_type="aggregate_authentication_result",
        outcome=authentication_outcome,
        reason_code=f"dmarc_authentication_{authentication_outcome}",
        count=passed + failed,
        delivery_certainty="authentication_only",
        guidance_key=f"mail_signal.dmarc_authentication.{authentication_outcome}",
        payload={
            "source_ip": source_ip,
            "passed": passed,
            "failed": failed,
            "spf_passed": _bounded_count(source.get("spf_pass_count")),
            "spf_failed": _bounded_count(source.get("spf_fail_count")),
            "dkim_passed": _bounded_count(source.get("dkim_pass_count")),
            "dkim_failed": _bounded_count(source.get("dkim_fail_count")),
            "header_from_domains": _string_values(source.get("header_from_domains")),
            "envelope_from_domains": _string_values(source.get("envelope_from_domains")),
            "spf_domains": _string_values(source.get("spf_domains")),
            "dkim_domains": _string_values(source.get("dkim_domains")),
            "dkim_selectors": _string_values(source.get("dkim_selectors")),
            "report_generators": _string_values(source.get("report_generators")),
        },
    )

    disposition_outcome, disposition_count = _disposition_outcome(
        source.get("disposition_counts") or {}
    )
    disposition = make_mail_signal(
        **common,
        family="dmarc_reported_disposition",
        signal_type="aggregate_receiver_disposition",
        outcome=disposition_outcome,
        reason_code=f"dmarc_reported_disposition_{disposition_outcome}",
        count=disposition_count,
        delivery_certainty="receiver_disposition_reported",
        guidance_key=f"mail_signal.dmarc_reported_disposition.{disposition_outcome}",
        payload={
            "source_ip": source_ip,
            "dispositions": {
                str(key).lower(): _bounded_count(value)
                for key, value in (source.get("disposition_counts") or {}).items()
            },
        },
    )
    return [authentication.to_dict(), disposition.to_dict()]


def build_intake_window_signal(
    *, workspace_id: int | None, window_start: int, window_end: int, has_evidence: bool
) -> dict[str, Any]:
    """Describe only whether persisted report evidence exists in a selected window."""
    outcome = "report_evidence_available" if has_evidence else "no_report_evidence_in_window"
    return make_mail_signal(
        family="intake_health",
        signal_type="report_evidence_window",
        outcome=outcome,
        claim_level="derived",
        delivery_certainty="not_applicable",
        source_system="dmarq_projection",
        workspace_id=workspace_id,
        window_start=window_start,
        window_end=window_end,
        reason_code=outcome,
        count=1 if has_evidence else 0,
        confidence="high",
        evidence_refs=(f"workspace:{workspace_id}",) if workspace_id is not None else (),
        guidance_key=f"mail_signal.intake_health.{outcome}",
    ).to_dict()


def _dmarc_signal_statement(family: str, outcome: str) -> str | None:
    authentication = {
        "pass": "The receiver recognized this use of the domain as authenticated.",
        "fail": "The receiver reported that this mail did not pass domain authentication.",
        "mixed": "The receiver reported both authenticated and unauthenticated mail from this source.",
    }
    dispositions = {
        "reject": "The reporting receiver recorded DMARC disposition reject.",
        "quarantine": "The reporting receiver recorded DMARC disposition quarantine.",
        "none": "The reporting receiver recorded no DMARC policy action for the failure.",
        "mixed": "The reporting receiver recorded more than one DMARC disposition for this source.",
    }
    if family == "dmarc_authentication":
        return authentication.get(outcome)
    if family == "dmarc_reported_disposition":
        return dispositions.get(outcome)
    return None


def guided_signal_statement(signal: Mapping[str, Any]) -> str:
    """Render a truthful English fallback from a normalized guidance key."""
    family = str(signal.get("family") or "")
    outcome = str(signal.get("outcome") or "unknown")
    dmarc_statement = _dmarc_signal_statement(family, outcome)
    if dmarc_statement:
        return dmarc_statement
    if family == "smtp_tls_report":
        return "A sending system reported a TLS delivery-path result."
    if (
        family == "dsn_delivery_status"
        and signal.get("delivery_certainty") == "non_delivery_reported"
    ):
        return "The sending system reported non-delivery."
    if family == "provider_delivery_event" and outcome == "delivered":
        return "The provider reported delivery according to its own event semantics."
    if family == "intake_health" and outcome == "no_report_evidence_in_window":
        return "DMARQ has no persisted report evidence in the selected window."
    return "DMARQ has structured evidence, but no plain-language statement is defined yet."


def signal_families() -> Iterable[str]:
    """Expose the stable taxonomy without leaking mutable internal state."""
    return tuple(sorted(SIGNAL_FAMILIES))
