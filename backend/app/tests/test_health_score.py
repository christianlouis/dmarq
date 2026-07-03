from unittest.mock import patch

import pytest

from app.services.health_score import build_health_summary, health_grade, score_domain_health


def test_health_grade_reserves_a_plus_for_reject_without_critical_actions():
    assert health_grade(99, policy="reject", critical_actions=0) == "A+"
    assert health_grade(99, policy="quarantine", critical_actions=0) == "A"
    assert health_grade(99, policy="reject", critical_actions=1) == "A"


def test_policy_none_caps_domain_score_and_creates_action():
    health = score_domain_health(
        {
            "domain_name": "example.com",
            "total_emails": 25_000,
            "failed_count": 0,
            "pass_rate": 99.2,
            "report_count": 30,
            "dmarc_status": True,
            "spf_status": True,
            "dkim_status": True,
            "dmarc_policy": "none",
            "dmarc_warnings": [],
        }
    )

    assert health["score"] == 74
    assert health["grade"] == "C"
    assert any(action["type"] == "policy_none" for action in health["actions"])


def test_low_compliance_and_missing_dns_create_prioritized_actions():
    health = score_domain_health(
        {
            "domain_name": "broken.example",
            "total_emails": 1000,
            "failed_count": 500,
            "pass_rate": 50.0,
            "report_count": 10,
            "dmarc_status": False,
            "spf_status": False,
            "dkim_status": True,
            "dmarc_policy": "missing",
            "dmarc_policy_source": "default",
            "dns_evidence_source": "live_dns",
            "dns_lookup_status": "ok",
            "dmarc_warnings": [],
        }
    )

    action_types = [action["type"] for action in health["actions"]]
    compliance_action = next(action for action in health["actions"] if action["type"] == "low_compliance")

    assert health["grade"] == "F"
    assert action_types[:2] == ["missing_dmarc", "low_compliance"]
    assert [item["label"] for item in compliance_action["evidence"][:2]] == [
        "pass_rate",
        "failed",
    ]
    assert "missing_spf" in action_types


def test_missing_dmarc_scores_worse_than_policy_none():
    """Missing DMARC must penalize more than a real p=none monitoring record."""
    shared = {
        "domain_name": "example.com",
        "total_emails": 25_000,
        "failed_count": 0,
        "pass_rate": 99.2,
        "report_count": 30,
        "spf_status": True,
        "dkim_status": True,
        "dmarc_warnings": [],
    }
    policy_none = score_domain_health(
        {**shared, "dmarc_status": True, "dmarc_policy": "none"}
    )
    missing_record = score_domain_health(
        {**shared, "dmarc_status": False, "dmarc_policy": "none"}
    )

    assert missing_record["score"] < policy_none["score"]
    assert any(action["type"] == "missing_dmarc" for action in missing_record["actions"])
    assert not any(action["type"] == "policy_none" for action in missing_record["actions"])


def test_dns_lookup_failure_preserves_report_policy_and_avoids_missing_dns_actions():
    """A resolver failure is not proof that DMARC/SPF/DKIM records are missing."""
    health = score_domain_health(
        {
            "domain_name": "cklnet.com",
            "total_emails": 20_000,
            "failed_count": 0,
            "pass_rate": 99.8,
            "report_count": 30,
            "dmarc_status": False,
            "spf_status": False,
            "dkim_status": False,
            "dmarc_policy": "reject",
            "dmarc_policy_source": "report",
            "dns_evidence_source": "lookup_failed",
            "dns_lookup_status": "failed",
            "dmarc_warnings": [],
            "dns_lookup_failed": True,
            "dns_lookup_error": "DNS lookup failed with TimeoutError.",
        }
    )

    action_types = [action["type"] for action in health["actions"]]
    dns_action = next(action for action in health["actions"] if action["type"] == "dns_evidence_unavailable")
    evidence = {item["label"]: item["value"] for item in dns_action["evidence"]}

    assert health["factors"]["policy_strength"] == 100.0
    assert health["factors"]["dns_posture"] == 65.0
    assert health["grade"] != "F"
    assert "dns_evidence_unavailable" in action_types
    assert dns_action["evidence"][0]["label"] == "lookup_error"
    assert evidence["dns_evidence"] == "DNS lookup failed"
    assert evidence["policy_source"] == "DMARC report policy"
    assert evidence["policy"] == "p=reject"
    assert "missing_dmarc" not in action_types
    assert "missing_spf" not in action_types
    assert "missing_dkim" not in action_types


def test_build_health_summary_weights_domain_scores_by_volume():
    domains = [
        {
            "domain_name": "large.example",
            "total_emails": 100_000,
            "failed_count": 100,
            "pass_rate": 99.9,
            "report_count": 30,
            "dmarc_status": True,
            "spf_status": True,
            "dkim_status": True,
            "dmarc_policy": "reject",
            "dmarc_warnings": [],
        },
        {
            "domain_name": "small.example",
            "total_emails": 100,
            "failed_count": 80,
            "pass_rate": 20.0,
            "report_count": 3,
            "dmarc_status": True,
            "spf_status": False,
            "dkim_status": False,
            "dmarc_policy": "none",
            "dmarc_warnings": ["External rua destination is not authorized."],
        },
    ]
    domain_health = [score_domain_health(domain) for domain in domains]
    summary = build_health_summary(domains, domain_health)

    assert summary["score"] >= 95
    assert summary["attention_domains"] == 1
    assert summary["top_actions"]


def test_build_health_summary_reuses_precomputed_domain_health():
    """Summary must not re-score domains when health payloads are already supplied."""
    domains = [
        {
            "domain_name": "cached.example",
            "total_emails": 1000,
            "pass_rate": 99.0,
            "report_count": 10,
            "dmarc_status": True,
            "spf_status": True,
            "dkim_status": True,
            "dmarc_policy": "reject",
            "dmarc_warnings": [],
        }
    ]
    precomputed = [
        {
            "domain": "cached.example",
            "score": 42,
            "grade": "F",
            "status": "critical",
            "factors": {},
            "actions": [],
        }
    ]

    with patch("app.services.health_score.score_domain_health") as mock_score:
        summary = build_health_summary(domains, precomputed)

    mock_score.assert_not_called()
    assert summary["domains"] is precomputed
    assert summary["score"] == 42


def test_build_health_summary_raises_on_missing_health_payload():
    domains = [{"domain_name": "a.com", "total_emails": 100}]
    with pytest.raises(ValueError):
        build_health_summary(domains, [])  # no matching health payload


def test_build_health_summary_a_plus_reachable_at_system_level():
    """System-level grade must reach A+ when all domains enforce reject at high scores."""
    domains = [
        {
            "domain_name": "primary.example",
            "total_emails": 100_000,
            "failed_count": 0,
            "pass_rate": 99.9,
            "report_count": 30,
            "dmarc_status": True,
            "spf_status": True,
            "dkim_status": True,
            "dmarc_policy": "reject",
            "dmarc_warnings": [],
        },
        {
            "domain_name": "secondary.example",
            "total_emails": 50_000,
            "failed_count": 0,
            "pass_rate": 99.5,
            "report_count": 20,
            "dmarc_status": True,
            "spf_status": True,
            "dkim_status": True,
            "dmarc_policy": "reject",
            "dmarc_warnings": [],
        },
    ]
    domain_health = [score_domain_health(domain) for domain in domains]
    summary = build_health_summary(domains, domain_health)

    assert summary["score"] >= 97
    assert summary["grade"] == "A+"
