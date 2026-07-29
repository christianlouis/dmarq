"""Versioned user and workspace guidance-profile resolution."""

from __future__ import annotations

import json
from typing import Any, Dict, Iterable, Optional

from app.models.user import User
from app.models.workspace import Workspace

PROFILE_VERSION = 1
EXPLANATION_DEPTHS = {"guided", "standard", "expert"}
WORK_CONTEXTS = {"watch", "diagnose", "evidence"}
INSTALLATION_GOALS = {
    "troubleshoot_delivery",
    "understand_reports",
    "investigate_bounces",
    "improve_authentication",
    "protect_against_spoofing",
    "continuous_monitoring",
    "audit_or_compliance",
    "learn_or_explore",
    "other",
}
SOVEREIGNTY_PREFERENCES = {
    "keep_data_local",
    "privacy_first",
    "balanced",
    "convenience_first",
    "not_sure",
}
REPORT_INTAKE_PREFERENCES = {
    "manual_upload",
    "local_imap",
    "proton_bridge",
    "gmail",
    "m365",
    "cloudflare_worker",
    "webhook",
    "not_sure",
}

LEGACY_GOAL_MAP = {
    "delivery_problem": "troubleshoot_delivery",
    "spam_or_inconsistent": "improve_authentication",
    "reports_confusing": "understand_reports",
    "suspected_abuse": "protect_against_spoofing",
    "preventive_monitoring": "continuous_monitoring",
    "curious": "learn_or_explore",
}
PRIMARY_GOAL_LEGACY_MAP = {value: key for key, value in LEGACY_GOAL_MAP.items()}


def _json_value(raw: object, fallback: Any) -> Any:
    if not raw:
        return fallback
    try:
        return json.loads(str(raw))
    except (TypeError, ValueError, json.JSONDecodeError):
        return fallback


def encode_json(value: object) -> str:
    """Serialize profile data consistently for portable Text columns."""
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


def ordered_goals(workspace: Workspace) -> list[str]:
    """Return valid, unique goals while preserving operator priority."""
    raw = _json_value(workspace.guidance_installation_goals, [])
    candidates: Iterable[object] = raw if isinstance(raw, list) else []
    goals: list[str] = []
    for value in candidates:
        goal = str(value or "").strip()
        if goal in INSTALLATION_GOALS and goal not in goals:
            goals.append(goal)
    if not goals and workspace.mail_health_goal:
        legacy = LEGACY_GOAL_MAP.get(workspace.mail_health_goal, workspace.mail_health_goal)
        if legacy in INSTALLATION_GOALS:
            goals.append(legacy)
    return goals


def mail_context(workspace: Workspace) -> Dict[str, Any]:
    """Return only the supported non-secret structured mail context."""
    raw = _json_value(workspace.guidance_mail_context, {})
    return raw if isinstance(raw, dict) else {}


def resolve_guidance_profile(
    workspace: Workspace,
    user: Optional[User],
    *,
    available: bool,
) -> Dict[str, Any]:
    """Resolve user preference, workspace fallback, then conservative defaults."""
    has_user_preference = bool(
        user
        and (
            user.guidance_depth
            or user.guidance_context
            or user.guidance_teaching_hints_enabled is not None
        )
    )
    depth = (
        user.guidance_depth if user and user.guidance_depth else workspace.guidance_depth
    ) or "standard"
    context = (
        user.guidance_context if user and user.guidance_context else workspace.guidance_context
    ) or "watch"
    if depth not in EXPLANATION_DEPTHS:
        depth = "standard"
    if context not in WORK_CONTEXTS:
        context = "watch"
    teaching_hints = (
        user.guidance_teaching_hints_enabled
        if user and user.guidance_teaching_hints_enabled is not None
        else (
            workspace.guidance_teaching_hints_enabled
            if workspace.guidance_teaching_hints_enabled is not None
            else depth == "guided"
        )
    )
    goals = ordered_goals(workspace)
    sovereignty = workspace.sovereignty_preference or "not_sure"
    if sovereignty not in SOVEREIGNTY_PREFERENCES:
        sovereignty = "not_sure"

    return {
        "available": bool(available),
        "enabled": bool(workspace.guided_mail_health_enabled) and bool(available),
        "requested_enabled": bool(workspace.guided_mail_health_enabled),
        "depth": depth,
        "context": context,
        "teaching_hints_enabled": bool(teaching_hints),
        "preference_scope": "user" if has_user_preference else "workspace",
        "profile_version": PROFILE_VERSION,
        "goal": workspace.mail_health_goal,
        "installation_goals": goals,
        "sovereignty_preference": sovereignty,
        "mail_context": mail_context(workspace),
        "notification_posture": workspace.notification_posture or "actionable_only",
        "interview_version": workspace.guidance_interview_version or PROFILE_VERSION,
        "interview_completed": workspace.guidance_interview_completed_at is not None,
    }
