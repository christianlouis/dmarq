from fastapi import APIRouter

from app.api.api_v1.endpoints import domains, health, imap, mail_sources, reports, setup, stats

api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(health.router, tags=["health"])
api_router.include_router(domains.router, prefix="/domains", tags=["domains"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])
api_router.include_router(setup.router, prefix="/setup", tags=["setup"])
api_router.include_router(imap.router, prefix="/imap", tags=["imap"])
api_router.include_router(stats.router, prefix="/stats", tags=["stats"])
api_router.include_router(mail_sources.router, prefix="/mail-sources", tags=["mail-sources"])
