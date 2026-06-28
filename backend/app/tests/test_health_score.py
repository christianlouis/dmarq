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
            "dmarc_warnings": [],
        }
    )

    action_types = [action["type"] for action in health["actions"]]

    assert health["grade"] == "F"
    assert action_types[:2] == ["missing_dmarc", "low_compliance"]
    assert "missing_spf" in action_types


def test_build_health_summary_weights_domain_scores_by_volume():
    summary = build_health_summary(
        [
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
    )

    assert summary["score"] >= 95
    assert summary["attention_domains"] == 1
    assert summary["top_actions"]
