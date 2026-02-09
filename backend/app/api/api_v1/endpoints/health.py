from app.api.api_v1.endpoints.setup import setup_status
from fastapi import APIRouter

router = APIRouter()


@router.get("/health", status_code=200)
async def health_check():
    """
    Health check endpoint to verify API status.
    For Milestone 1, this simply returns status information without checking a database.
    """
    return {
        "status": "ok",
        "version": "0.1.0",
        "service": "dmarq",
        "is_setup_complete": setup_status["is_setup_complete"],
    }
