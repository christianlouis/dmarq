from fastapi import APIRouter

from app.api.api_v1.endpoints import domains, health, reports, setup, imap

api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(health.router, tags=["health"])
api_router.include_router(domains.router, prefix="/domains", tags=["domains"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])
api_router.include_router(setup.router, prefix="/setup", tags=["setup"])
api_router.include_router(imap.router, prefix="/imap", tags=["imap"])