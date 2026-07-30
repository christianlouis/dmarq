"""Contract tests for localized, skill-adaptive mail-health presentation."""

from copy import deepcopy

from app.services.mail_health_guidance import (
    CATALOG,
    PRIMARY_CONCLUSIONS,
    missing_catalog_entries,
    render_mail_health_guidance,
)


def _assessment(key: str) -> dict:
    return {
        "assessment_id": "stable-facts",
        "outcome": "healthy",
        "title": "Source title",
        "summary": "Source summary",
        "next_step": "Source action",
        "confidence": "High",
        "intended_mail_impact": "likely_not_affected",
        "urgency": "none",
        "conclusion": {"key": key, "parameters": {}},
        "known_facts": ["Observed fact"],
        "supporting_signals": [{"signal_id": "signal-1"}],
    }


def test_primary_catalog_is_complete_in_english_and_german():
    assert missing_catalog_entries() == {"en": [], "de": []}
    for locale in ("en", "de"):
        for key in PRIMARY_CONCLUSIONS:
            assert (
                all(CATALOG[locale][key].values())
                or CATALOG[locale][key]["no_action_explanation"] == ""
            )


def test_all_context_and_depth_combinations_preserve_assessment_facts():
    for key in PRIMARY_CONCLUSIONS:
        assessment = _assessment(key)
        original = deepcopy(assessment)
        for locale in ("en", "de"):
            for depth in ("guided", "standard", "expert"):
                for context in ("watch", "diagnose", "evidence"):
                    presentation = render_mail_health_guidance(
                        assessment, locale=locale, depth=depth, context=context
                    )
                    assert presentation["headline"]
                    assert presentation["next_action_label"]
                    assert presentation["verification_text"]
                    assert presentation["locale"] == locale
        assert assessment == original


def test_evidence_and_expert_reveal_exact_evidence_without_changing_authorization():
    assessment = _assessment("mail_health.healthy")
    guided_watch = render_mail_health_guidance(
        assessment, locale="en", depth="guided", context="watch"
    )
    expert_watch = render_mail_health_guidance(
        assessment, locale="en", depth="expert", context="watch"
    )
    guided_evidence = render_mail_health_guidance(
        assessment, locale="en", depth="guided", context="evidence"
    )

    assert guided_watch["show_exact_evidence"] is False
    assert expert_watch["show_exact_evidence"] is True
    assert guided_evidence["show_exact_evidence"] is True
