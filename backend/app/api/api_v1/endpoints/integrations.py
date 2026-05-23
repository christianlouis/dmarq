"""Integration template endpoints."""

from fastapi import APIRouter, Depends

from app.core.security import require_admin_auth
from app.services.siem_templates import get_siem_templates
from app.services.ticketing_chatops_templates import get_ticketing_chatops_templates

router = APIRouter()


@router.get("/siem/templates")
async def siem_templates(_auth: dict = Depends(require_admin_auth)):
    """Return versioned schemas and examples for SIEM ingestion."""
    return get_siem_templates()


@router.get("/ticketing-chatops/templates")
async def ticketing_chatops_templates(_auth: dict = Depends(require_admin_auth)):
    """Return ticketing and chatops workflow templates."""
    return get_ticketing_chatops_templates()
