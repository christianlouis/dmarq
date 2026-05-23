from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import api_key_header, require_admin_auth, security_bearer
from app.models.domain import Domain
from app.models.mail_source import MailSource
from app.models.setting import Setting

router = APIRouter()

# Simple in-memory storage for setup status (for Milestone 1)
setup_status = {
    "is_setup_complete": False,
    "admin_email": None,
    "app_name": "DMARQ",
}

SETUP_COMPLETE_KEY = "setup.is_complete"
SETUP_ADMIN_EMAIL_KEY = "setup.admin_email"
GENERAL_APP_NAME_KEY = "general.app_name"
GENERAL_BASE_URL_KEY = "general.base_url"


def _setting_value(db: Session, key: str) -> Optional[str]:
    row = db.query(Setting).filter(Setting.key == key).first()
    return row.value if row else None


def _is_true(value: Optional[str]) -> bool:
    return str(value).strip().lower() in {"1", "true", "yes", "on"}


def _upsert_setting(
    db: Session,
    key: str,
    value: Optional[str],
    *,
    description: str,
    value_type: str = "string",
    category: str = "setup",
) -> None:
    row = db.query(Setting).filter(Setting.key == key).first()
    if row is None:
        db.add(
            Setting(
                key=key,
                value=value,
                description=description,
                value_type=value_type,
                category=category,
            )
        )
        return

    row.value = value
    row.description = row.description or description
    row.value_type = row.value_type or value_type
    row.category = row.category or category


def _refresh_setup_status_from_db(db: Session) -> dict:
    """Merge persisted setup state into the legacy in-memory setup status."""
    persisted_complete = _is_true(_setting_value(db, SETUP_COMPLETE_KEY))
    if persisted_complete:
        setup_status["is_setup_complete"] = True

    persisted_admin_email = _setting_value(db, SETUP_ADMIN_EMAIL_KEY)
    if persisted_admin_email:
        setup_status["admin_email"] = persisted_admin_email

    persisted_app_name = _setting_value(db, GENERAL_APP_NAME_KEY)
    if persisted_app_name:
        setup_status["app_name"] = persisted_app_name

    return setup_status


def _setup_is_complete(db: Session) -> bool:
    return bool(setup_status["is_setup_complete"]) or _is_true(
        _setting_value(db, SETUP_COMPLETE_KEY)
    )


class SetupStatusResponse(BaseModel):
    """Setup status response"""

    is_setup_complete: bool
    app_name: str
    total_domains: int = 0
    total_mail_sources: int = 0
    enabled_mail_sources: int = 0


class AdminSetupRequest(BaseModel):
    """Admin user setup request body"""

    email: EmailStr
    username: str
    password: str


class SystemConfigRequest(BaseModel):
    """System configuration setup request body"""

    app_name: str
    base_url: str


async def require_setup_write_auth(
    request: Request,
    db: Session = Depends(get_db),
    api_key: Optional[str] = Security(api_key_header),
    bearer: Optional[HTTPAuthorizationCredentials] = Security(security_bearer),
) -> dict:
    """Allow unauthenticated first-time setup writes, then require admin auth."""
    if not _setup_is_complete(db):
        return {"auth_type": "initial_setup"}
    return await require_admin_auth(request=request, api_key=api_key, bearer=bearer)


@router.get("/status", response_model=SetupStatusResponse)
async def get_setup_status(db: Session = Depends(get_db)):
    """Get the current setup status"""
    current_status = _refresh_setup_status_from_db(db)
    return SetupStatusResponse(
        is_setup_complete=current_status["is_setup_complete"],
        app_name=current_status["app_name"],
        total_domains=db.query(Domain.id).count(),
        total_mail_sources=db.query(MailSource.id).count(),
        enabled_mail_sources=db.query(MailSource.id)
        .filter(MailSource.enabled == True)  # noqa: E712
        .count(),
    )


@router.post("/admin", status_code=201)
async def setup_admin(
    request: AdminSetupRequest,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_setup_write_auth),
):
    """
    Setup admin user during initial system configuration.
    For Milestone 1, this simply stores the admin email in memory.
    """
    if _setup_is_complete(db):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Setup already completed"
        )

    # Store admin email
    setup_status["admin_email"] = request.email
    _upsert_setting(
        db,
        SETUP_ADMIN_EMAIL_KEY,
        request.email,
        description="Email address configured during initial setup",
    )
    db.commit()

    return {"message": "Admin user setup completed"}


@router.post("/system", status_code=200)
async def setup_system(
    request: SystemConfigRequest,
    db: Session = Depends(get_db),
    _auth: dict = Depends(require_setup_write_auth),
):
    """
    Setup system configuration.
    For Milestone 1, this simply stores the app name in memory.
    """
    # Store app name
    setup_status["app_name"] = request.app_name
    setup_status["is_setup_complete"] = True
    _upsert_setting(
        db,
        GENERAL_APP_NAME_KEY,
        request.app_name,
        description="Application display name shown in the UI",
        category="general",
    )
    _upsert_setting(
        db,
        GENERAL_BASE_URL_KEY,
        request.base_url,
        description="Public base URL for this DMARQ instance",
        category="general",
    )
    _upsert_setting(
        db,
        SETUP_COMPLETE_KEY,
        "true",
        description="Whether initial setup has been completed",
        value_type="boolean",
    )
    db.commit()

    return {"message": "System settings saved successfully"}
