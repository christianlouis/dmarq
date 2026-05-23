from fastapi import APIRouter

from app.api.api_v1.endpoints import (
    api_tokens,
    auth,
    domains,
    forensics,
    health,
    imap,
    mail_sources,
    public,
    reports,
    settings,
    setup,
    stats,
    tls_reports,
    webhook,
)

api_router = APIRouter()

# Include all endpoint routers
api_router.include_router(auth.router, prefix="/auth", tags=["auth"])
api_router.include_router(api_tokens.router, prefix="/api-tokens", tags=["api-tokens"])
api_router.include_router(health.router, tags=["health"])
api_router.include_router(public.router, prefix="/public", tags=["public-api"])
api_router.include_router(domains.router, prefix="/domains", tags=["domains"])
api_router.include_router(reports.router, prefix="/reports", tags=["reports"])
api_router.include_router(forensics.router, prefix="/forensics", tags=["forensics"])
api_router.include_router(setup.router, prefix="/setup", tags=["setup"])
api_router.include_router(imap.router, prefix="/imap", tags=["imap"])
api_router.include_router(stats.router, prefix="/stats", tags=["stats"])
api_router.include_router(mail_sources.router, prefix="/mail-sources", tags=["mail-sources"])
api_router.include_router(settings.router, prefix="/settings", tags=["settings"])
api_router.include_router(tls_reports.router, prefix="/tls-reports", tags=["tls-reports"])
api_router.include_router(webhook.router, prefix="/webhook", tags=["webhook"])
