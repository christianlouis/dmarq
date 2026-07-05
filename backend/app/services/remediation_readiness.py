"""Shared read-only remediation repair-readiness metadata."""

from __future__ import annotations

from typing import Dict

OPERATOR_REVIEW_READINESS_LEVELS = {
    "needs_classification",
    "needs_reputation_review",
    "manual_repair",
    "needs_operator_review",
}

_READINESS_BY_STAGE = {
    "preview_ready": {
        "readiness_level": "ready_for_preview",
        "readiness_label": "Ready for provider preview",
        "readiness_score": 80,
    },
    "blocked": {
        "readiness_level": "blocked",
        "readiness_label": "Blocked before repair",
        "readiness_score": 20,
    },
    "classification_required": {
        "readiness_level": "needs_classification",
        "readiness_label": "Needs sender classification",
        "readiness_score": 35,
    },
    "reputation_review": {
        "readiness_level": "needs_reputation_review",
        "readiness_label": "Needs reputation review",
        "readiness_score": 40,
    },
    "manual_repair": {
        "readiness_level": "manual_repair",
        "readiness_label": "Manual repair path",
        "readiness_score": 50,
    },
}

_DEFAULT_READINESS = {
    "readiness_level": "needs_operator_review",
    "readiness_label": "Needs operator review",
    "readiness_score": 30,
}


def repair_readiness_for_stage(stage: str) -> Dict[str, int | str]:
    """Return the canonical readiness level, label, and score for a stage."""
    return dict(_READINESS_BY_STAGE.get(stage, _DEFAULT_READINESS))
