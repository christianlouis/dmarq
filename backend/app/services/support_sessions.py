"""Signed, time-boxed customer support sessions for provider operators."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
from uuid import uuid4

from fastapi import Request
from jose import JWTError, jwt

from app.core.config import get_settings

SUPPORT_SESSION_COOKIE = "dmarq_support_session"
SUPPORT_SESSION_TOKEN_TYPE = "support_session"
SUPPORT_SESSION_TTL_MINUTES = 30


def create_support_session_token(
    *,
    workspace_id: int,
    organization_id: Optional[int],
    target_user_id: int,
    target_user_email: str,
    target_user_role: str,
    operator: Dict[str, Any],
    reason: str,
    account_name: Optional[str] = None,
    customer_number: Optional[str] = None,
    plan_code: Optional[str] = None,
    plan_label: Optional[str] = None,
    read_only: bool = True,
    ttl_minutes: int = SUPPORT_SESSION_TTL_MINUTES,
) -> tuple[str, Dict[str, Any]]:
    """Create a signed token and API-safe session metadata."""
    settings = get_settings()
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=max(5, min(ttl_minutes, 120)))
    session_id = uuid4().hex
    payload = {
        "type": SUPPORT_SESSION_TOKEN_TYPE,
        "session_id": session_id,
        "workspace_id": int(workspace_id),
        "organization_id": int(organization_id) if organization_id is not None else None,
        "target_user_id": int(target_user_id),
        "target_user_email": target_user_email,
        "target_user_role": target_user_role,
        "operator": operator,
        "reason": reason,
        "account_name": account_name,
        "customer_number": customer_number,
        "plan_code": plan_code,
        "plan_label": plan_label,
        "read_only": bool(read_only),
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
    }
    token = jwt.encode(payload, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return token, support_session_metadata(payload)


def decode_support_session_token(token: Optional[str]) -> Optional[Dict[str, Any]]:
    """Decode a valid support-session token without leaking token contents."""
    if not token:
        return None
    settings = get_settings()
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
    except JWTError:
        return None
    if payload.get("type") != SUPPORT_SESSION_TOKEN_TYPE:
        return None
    try:
        payload["workspace_id"] = int(payload["workspace_id"])
        payload["target_user_id"] = int(payload["target_user_id"])
    except (KeyError, TypeError, ValueError):
        return None
    return payload


def support_session_from_request(request: Request) -> Optional[Dict[str, Any]]:
    """Return a valid support-session payload from the current request."""
    return decode_support_session_token(request.cookies.get(SUPPORT_SESSION_COOKIE))


def support_session_auth_context(request: Request) -> Optional[Dict[str, Any]]:
    """Map a support session to the target customer's normal user context."""
    payload = support_session_from_request(request)
    if payload is None:
        return None
    return {
        "auth_type": SUPPORT_SESSION_TOKEN_TYPE,
        "user_id": payload["target_user_id"],
        "workspace_id": payload["workspace_id"],
        "organization_id": payload.get("organization_id"),
        "support_session_id": payload.get("session_id"),
        "operator": payload.get("operator") or {},
        "reason": payload.get("reason"),
        "account_name": payload.get("account_name"),
        "customer_number": payload.get("customer_number"),
        "plan_code": payload.get("plan_code"),
        "plan_label": payload.get("plan_label"),
        "support_read_only": bool(payload.get("read_only", True)),
    }


def support_session_metadata(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Return the customer-visible, API-safe portion of a session payload."""
    expires_at = payload.get("exp")
    started_at = payload.get("iat")
    return {
        "id": payload.get("session_id"),
        "workspace_id": payload.get("workspace_id"),
        "organization_id": payload.get("organization_id"),
        "target_user_id": payload.get("target_user_id"),
        "target_user_email": payload.get("target_user_email"),
        "target_user_role": payload.get("target_user_role"),
        "operator": payload.get("operator") or {},
        "reason": payload.get("reason"),
        "account_name": payload.get("account_name"),
        "customer_number": payload.get("customer_number"),
        "plan_code": payload.get("plan_code"),
        "plan_label": payload.get("plan_label"),
        "started_at": (
            datetime.fromtimestamp(int(started_at), timezone.utc).isoformat()
            if started_at is not None
            else None
        ),
        "expires_at": (
            datetime.fromtimestamp(int(expires_at), timezone.utc).isoformat()
            if expires_at is not None
            else None
        ),
        "read_only": bool(payload.get("read_only", True)),
    }
