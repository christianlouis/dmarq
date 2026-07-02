"""Health scoring for dashboard and domain posture summaries."""

from __future__ import annotations

from typing import Any, Dict, List, Optional

ACTIVE_POLICIES = {"quarantine", "reject"}


def health_grade(score: int, *, policy: Optional[str] = None, critical_actions: int = 0) -> str:
    """Return an SSL-Labs-style grade for a bounded health score."""
    policy_name = (policy or "").lower()
    if score >= 97 and policy_name == "reject" and critical_actions == 0:
        return "A+"
    if score >= 93:
        return "A"
    if score >= 90:
        return "A-"
    if score >= 87:
        return "B+"
    if score >= 83:
        return "B"
    if score >= 80:
        return "B-"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"


def _bounded(value: Any, *, lower: float = 0.0, upper: float = 100.0) -> float:
    try:
        number = float(value or 0)
    except (TypeError, ValueError):
        number = 0.0
    return max(lower, min(upper, number))


def _effective_dmarc_policy(domain: Dict[str, Any]) -> str:
    """Return the DMARC policy used for scoring, distinct from endpoint fallbacks."""
    if domain.get("dns_pending") and domain.get("dmarc_policy"):
        return str(domain.get("dmarc_policy") or "none").lower()
    if not domain.get("dmarc_status"):
        return "missing"
    return str(domain.get("dmarc_policy") or "none").lower()


def _policy_factor(policy: Optional[str]) -> float:
    policy_name = (policy or "").lower()
    if policy_name == "reject":
        return 100.0
    if policy_name == "quarantine":
        return 88.0
    if policy_name == "none":
        return 55.0
    return 25.0


def _dns_factor(domain: Dict[str, Any]) -> float:
    if domain.get("dns_pending"):
        return 70.0
    checks = [
        bool(domain.get("dmarc_status")),
        bool(domain.get("spf_status")),
        bool(domain.get("dkim_status")),
    ]
    base = (sum(1 for check in checks if check) / len(checks)) * 100
    warning_penalty = min(25, len(domain.get("dmarc_warnings") or []) * 8)
    return _bounded(base - warning_penalty)


def _confidence_factor(domain: Dict[str, Any]) -> float:
    emails = int(domain.get("total_emails") or 0)
    reports = int(domain.get("report_count") or domain.get("reports_processed") or 0)
    if reports >= 14 and emails >= 1000:
        return 100.0
    if reports >= 7 and emails >= 250:
        return 90.0
    if reports >= 3 and emails > 0:
        return 78.0
    if reports > 0 or emails > 0:
        return 62.0
    return 30.0


def _reputation_factor(domain: Dict[str, Any]) -> float:
    reputation = domain.get("source_reputation") or {}
    summary = reputation.get("summary") or {}
    highest_risk = _bounded(summary.get("highest_risk_score"))
    if int(summary.get("total_sources") or 0) == 0:
        return 70.0
    return _bounded(100.0 - highest_risk)


def _score_cap(domain: Dict[str, Any], confidence: float, *, policy: Optional[str] = None) -> int:
    policy = policy or _effective_dmarc_policy(domain)
    cap = 100
    if policy == "quarantine":
        cap = min(cap, 92)
    elif policy == "none":
        cap = min(cap, 74)
    elif policy not in ACTIVE_POLICIES:
        cap = min(cap, 59)
    if confidence < 70:
        cap = min(cap, 79)
    return cap


def _action(
    *,
    action_type: str,
    severity: str,
    title: str,
    detail: str,
    next_step: str,
    score_impact: int,
    domain: str,
    evidence: Optional[List[Dict[str, str]]] = None,
) -> Dict[str, Any]:
    return {
        "type": action_type,
        "severity": severity,
        "title": title,
        "detail": detail,
        "next_step": next_step,
        "score_impact": score_impact,
        "domain": domain,
        "evidence": evidence or [],
    }


def _domain_actions(domain: Dict[str, Any]) -> List[Dict[str, Any]]:
    domain_name = str(domain.get("domain_name") or domain.get("id") or "domain")
    pass_rate = _bounded(domain.get("pass_rate"))
    policy = str(domain.get("dmarc_policy") or "missing").lower()
    actions: List[Dict[str, Any]] = []
    dns_pending = bool(domain.get("dns_pending"))

    if dns_pending:
        actions.append(
            _action(
                action_type="dns_evidence_pending",
                severity="info",
                title="Refresh DNS evidence",
                detail="DNS health has not been checked for this domain in the current cache.",
                next_step="Open the domain or use Reload to fetch live DNS before making DNS decisions.",
                score_impact=0,
                domain=domain_name,
            )
        )
    if not dns_pending and not domain.get("dmarc_status"):
        actions.append(
            _action(
                action_type="missing_dmarc",
                severity="critical",
                title="Publish a DMARC policy record",
                detail="The domain cannot receive a strong health grade without a valid DMARC record.",
                next_step="Publish a v=DMARC1 record with rua reporting and start in p=none if needed.",
                score_impact=25,
                domain=domain_name,
            )
        )
    if not dns_pending and not domain.get("spf_status"):
        actions.append(
            _action(
                action_type="missing_spf",
                severity="high",
                title="Fix SPF coverage",
                detail="SPF is missing or unhealthy for this domain.",
                next_step="Publish or repair the SPF TXT record for legitimate sending infrastructure.",
                score_impact=12,
                domain=domain_name,
            )
        )
    if not dns_pending and not domain.get("dkim_status"):
        actions.append(
            _action(
                action_type="missing_dkim",
                severity="high",
                title="Fix DKIM selector coverage",
                detail="DKIM selectors from report data are not fully healthy.",
                next_step="Publish the missing selector or rotate the service DKIM configuration.",
                score_impact=12,
                domain=domain_name,
            )
        )
    if pass_rate < 90 and int(domain.get("total_emails") or 0) > 0:
        actions.append(
            _action(
                action_type="low_compliance",
                severity="high" if pass_rate < 75 else "medium",
                title="Investigate failing senders",
                detail=f"DMARC pass rate is {pass_rate:.1f}%, below the 90% enforcement target.",
                next_step="Open the domain detail page and fix the top failing sources before tightening policy.",
                score_impact=18 if pass_rate < 75 else 10,
                domain=domain_name,
                evidence=[
                    {"label": "pass_rate", "value": f"{pass_rate:.1f}%"},
                    {"label": "failed", "value": str(domain.get("failed_count") or 0)},
                ],
            )
        )
    if policy == "none" and domain.get("dmarc_status"):
        actions.append(
            _action(
                action_type="policy_none",
                severity="medium",
                title="Move out of monitoring mode",
                detail="p=none keeps DMARQ in observation mode and caps the health grade.",
                next_step="After known senders pass DMARC, stage p=quarantine and then p=reject.",
                score_impact=14,
                domain=domain_name,
                evidence=[{"label": "policy", "value": "p=none"}],
            )
        )
    if domain.get("dmarc_warnings"):
        actions.append(
            _action(
                action_type="dmarc_lint",
                severity="medium",
                title="Resolve DMARC lint warnings",
                detail="The DMARC record has lint warnings that reduce operator confidence.",
                next_step="Review the DNS health details and publish a corrected DMARC record.",
                score_impact=8,
                domain=domain_name,
                evidence=[
                    {"label": "warnings", "value": str(len(domain.get("dmarc_warnings") or []))}
                ],
            )
        )
    reputation = domain.get("source_reputation") or {}
    reputation_summary = reputation.get("summary") or {}
    listed = int(reputation_summary.get("listed") or 0)
    suspicious = int(reputation_summary.get("suspicious") or 0)
    if listed:
        actions.append(
            _action(
                action_type="source_reputation_listed",
                severity="critical",
                title="Review listed sending IPs",
                detail=f"{listed} observed sending source is listed or flagged by reputation data.",
                next_step=(
                    "Open sending sources, confirm ownership, and follow the named delisting "
                    "or provider remediation process before tightening policy."
                ),
                score_impact=18,
                domain=domain_name,
                evidence=[{"label": "listed_sources", "value": str(listed)}],
            )
        )
    elif suspicious:
        actions.append(
            _action(
                action_type="source_reputation_review",
                severity="high",
                title="Review suspicious sending IPs",
                detail=f"{suspicious} observed sending source needs reputation review.",
                next_step="Confirm whether the source is authorized and fix SPF/DKIM alignment.",
                score_impact=10,
                domain=domain_name,
                evidence=[{"label": "suspicious_sources", "value": str(suspicious)}],
            )
        )

    return sorted(actions, key=lambda item: item["score_impact"], reverse=True)


def _system_policy(domains: List[Dict[str, Any]]) -> Optional[str]:
    """Return reject when every domain enforces p=reject so A+ is reachable system-wide."""
    if not domains:
        return None
    if all(_effective_dmarc_policy(domain) == "reject" for domain in domains):
        return "reject"
    return None


def score_domain_health(domain: Dict[str, Any]) -> Dict[str, Any]:
    """Score a single domain summary row."""
    pass_rate = _bounded(domain.get("pass_rate"))
    dns = _dns_factor(domain)
    policy_name = _effective_dmarc_policy(domain)
    policy = _policy_factor(policy_name)
    confidence = _confidence_factor(domain)
    reputation = _reputation_factor(domain)
    raw_score = round(
        (pass_rate * 0.40)
        + (dns * 0.20)
        + (policy * 0.25)
        + (confidence * 0.10)
        + (reputation * 0.05)
    )
    score = min(raw_score, _score_cap(domain, confidence, policy=policy_name))
    actions = _domain_actions(domain)
    critical_actions = sum(1 for action in actions if action["severity"] == "critical")

    return {
        "domain": domain.get("domain_name") or domain.get("id"),
        "score": int(score),
        "grade": health_grade(int(score), policy=policy_name, critical_actions=critical_actions),
        "status": "healthy" if score >= 90 else "attention" if score >= 70 else "critical",
        "factors": {
            "dmarc_compliance": round(pass_rate, 1),
            "dns_posture": round(dns, 1),
            "policy_strength": round(policy, 1),
            "report_confidence": round(confidence, 1),
            "source_reputation": round(reputation, 1),
        },
        "actions": actions[:5],
    }


def build_health_summary(
    domains: List[Dict[str, Any]],
    domain_health: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Build system-level health from pre-computed per-domain health payloads."""
    by_domain = {
        str(item.get("domain")): item for item in domain_health if item.get("domain") is not None
    }

    def _domain_key(domain: Dict[str, Any]) -> str:
        return str(domain.get("domain_name") or domain.get("id"))

    missing_health = [
        _domain_key(domain) for domain in domains if _domain_key(domain) not in by_domain
    ]
    if missing_health:
        raise ValueError(f"Missing health payloads for domains: {', '.join(missing_health)}")

    total_weight = sum(max(1, int(domain.get("total_emails") or 0)) for domain in domains)
    if total_weight:
        score = round(
            sum(
                by_domain[_domain_key(domain)]["score"]
                * max(1, int(domain.get("total_emails") or 0))
                for domain in domains
            )
            / total_weight
        )
    else:
        score = 0

    all_actions = [action for item in domain_health for action in item.get("actions", [])]
    all_actions.sort(key=lambda item: item["score_impact"], reverse=True)
    critical_actions = sum(1 for action in all_actions if action["severity"] == "critical")
    attention_domains = sum(1 for item in domain_health if item["score"] < 90)

    return {
        "score": int(score),
        "grade": health_grade(
            int(score),
            policy=_system_policy(domains),
            critical_actions=critical_actions,
        ),
        "status": "healthy" if score >= 90 else "attention" if score >= 70 else "critical",
        "attention_domains": attention_domains,
        "domain_count": len(domain_health),
        "domains": domain_health,
        "top_actions": all_actions[:5],
    }
