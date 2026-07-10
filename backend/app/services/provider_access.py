"""Deployment-wide access control for the provider site-manager surface."""

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.services.workspace_access import user_for_auth_context


def provider_operator_access_allowed(
    db: Session,
    auth_context: dict,
    *,
    allow_provider_token: bool = False,
) -> bool:
    """Return whether the caller may manage tenants across the deployment."""
    settings = get_settings()
    auth_type = (auth_context or {}).get("auth_type")
    if auth_type in {"api_key", "disabled"}:
        return True
    if allow_provider_token and auth_type == "provider_api_token":
        return True
    if settings.DEMO_MODE and settings.PROVIDER_DEMO_ENABLED:
        return True

    user = user_for_auth_context(db, auth_context)
    return bool(
        user and user.is_active and user.email.strip().lower() in settings.provider_operator_emails
    )


def require_provider_operator_access(
    db: Session,
    auth_context: dict,
    *,
    allow_provider_token: bool = False,
) -> None:
    """Raise HTTP 403 unless the caller is an explicit provider operator."""
    if provider_operator_access_allowed(
        db,
        auth_context,
        allow_provider_token=allow_provider_token,
    ):
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Provider operator access is required",
    )
