"""
SentinelX — Authentication Routes
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from api.core.database import get_db
from api.schemas.auth import LoginRequest, TokenResponse, RefreshTokenRequest
from api.schemas.user import UserCreate, UserResponse
from api.services.auth_service import AuthService

router = APIRouter()


@router.post("/login", response_model=TokenResponse)
async def login(
    body: LoginRequest,
    db: AsyncSession = Depends(get_db),
):
    """Authenticate and receive JWT tokens."""
    service = AuthService(db)
    return await service.login(body.email, body.password)


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(
    body: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
):
    """Refresh an access token using a valid refresh token."""
    service = AuthService(db)
    return await service.refresh_token(body.refresh_token)


@router.post("/register", response_model=UserResponse, status_code=201)
async def register(
    body: UserCreate,
    db: AsyncSession = Depends(get_db),
):
    """Register a new user account."""
    service = AuthService(db)
    user = await service.register(
        email=body.email,
        password=body.password,
        full_name=body.full_name,
        role=body.role.value,
    )
    return UserResponse.model_validate(user)
