from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, Security, status
from fastapi.security import HTTPAuthorizationCredentials
from pydantic import BaseModel, EmailStr

from app.core.security import api_key_header, require_admin_auth, security_bearer

router = APIRouter()

# Simple in-memory storage for setup status (for Milestone 1)
setup_status = {
    "is_setup_complete": False,
    "admin_email": None,
    "app_name": "DMARQ",
}


class SetupStatusResponse(BaseModel):
    """Setup status response"""

    is_setup_complete: bool
    app_name: str


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
    api_key: Optional[str] = Security(api_key_header),
    bearer: Optional[HTTPAuthorizationCredentials] = Security(security_bearer),
) -> dict:
    """Allow unauthenticated first-time setup writes, then require admin auth."""
    if not setup_status["is_setup_complete"]:
        return {"auth_type": "initial_setup"}
    return await require_admin_auth(request=request, api_key=api_key, bearer=bearer)


@router.get("/status", response_model=SetupStatusResponse)
async def get_setup_status():
    """Get the current setup status"""
    return SetupStatusResponse(
        is_setup_complete=setup_status["is_setup_complete"],
        app_name=setup_status["app_name"],
    )


@router.post("/admin", status_code=201)
async def setup_admin(
    request: AdminSetupRequest,
    _auth: dict = Depends(require_setup_write_auth),
):
    """
    Setup admin user during initial system configuration.
    For Milestone 1, this simply stores the admin email in memory.
    """
    if setup_status["is_setup_complete"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail="Setup already completed"
        )

    # Store admin email
    setup_status["admin_email"] = request.email

    return {"message": "Admin user setup completed"}


@router.post("/system", status_code=200)
async def setup_system(
    request: SystemConfigRequest,
    _auth: dict = Depends(require_setup_write_auth),
):
    """
    Setup system configuration.
    For Milestone 1, this simply stores the app name in memory.
    """
    # Store app name
    setup_status["app_name"] = request.app_name
    setup_status["is_setup_complete"] = True

    return {"message": "System settings saved successfully"}
