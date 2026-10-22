"""
SentinelX — Health Check Route
"""

from datetime import datetime, timezone

from fastapi import APIRouter

from api.core.config import get_settings

router = APIRouter()
settings = get_settings()


@router.get("/health", response_model=dict)
async def health_check():
    """Application health check endpoint."""
    return {
        "status": "healthy",
        "app": settings.app_name,
        "version": settings.app_version,
        "environment": settings.app_env,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }
