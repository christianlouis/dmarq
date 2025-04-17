from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
import os

from app.api.api_v1.api import api_router
from app.core.config import get_settings

settings = get_settings()


def create_app() -> FastAPI:
    """Create and configure the FastAPI application"""
    app = FastAPI(
        title=settings.PROJECT_NAME,
        openapi_url=f"{settings.API_V1_STR}/openapi.json",
        version="0.1.0",
    )

    # Set all CORS enabled origins
    if settings.BACKEND_CORS_ORIGINS:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=[str(origin) for origin in settings.BACKEND_CORS_ORIGINS],
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # Include API router
    app.include_router(api_router, prefix=settings.API_V1_STR)
    
    # Mount static files directory
    app.mount("/static", StaticFiles(directory=os.path.join(os.path.dirname(__file__), "static")), name="static")
    
    return app


app = create_app()

# Initialize Jinja2 templates
templates_dir = os.path.join(os.path.dirname(__file__), "templates")
templates = Jinja2Templates(directory=templates_dir)


@app.get("/", response_class=HTMLResponse)
async def root(request: Request):
    """Root endpoint that serves the main HTML page"""
    return templates.TemplateResponse(
        "index.html", 
        {"request": request, "app_name": settings.PROJECT_NAME}
    )


# Frontend routes that should return the SPA template
@app.get("/dashboard", response_class=HTMLResponse)
@app.get("/login", response_class=HTMLResponse)
@app.get("/setup", response_class=HTMLResponse)
@app.get("/domains", response_class=HTMLResponse)
@app.get("/reports", response_class=HTMLResponse)
@app.get("/settings", response_class=HTMLResponse)
async def serve_spa(request: Request):
    """Serve the SPA for frontend routes"""
    return templates.TemplateResponse(
        "index.html", 
        {"request": request, "app_name": settings.PROJECT_NAME}
    )

# Fallback for other routes (404 handling)
@app.get("/{path:path}", response_class=HTMLResponse)
async def catch_all(request: Request, path: str):
    """Catch-all route that serves the main HTML page for client-side routing"""
    return templates.TemplateResponse(
        "index.html", 
        {"request": request, "app_name": settings.PROJECT_NAME}
    )