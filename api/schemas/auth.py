"""
SentinelX — Authentication Schemas
"""

from pydantic import BaseModel, EmailStr, Field


class LoginRequest(BaseModel):
    """Login credentials."""

    email: EmailStr
    password: str = Field(..., min_length=1)


class TokenResponse(BaseModel):
    """JWT token pair response."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds


class RefreshTokenRequest(BaseModel):
    """Token refresh request."""

    refresh_token: str


class PasswordChangeRequest(BaseModel):
    """Password change request."""

    current_password: str
    new_password: str = Field(..., min_length=8, max_length=128)
