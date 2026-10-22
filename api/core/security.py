"""
SentinelX — Security Utilities
JWT token management, password hashing, and RBAC enforcement.
"""

import uuid
from datetime import datetime, timedelta, timezone
from enum import StrEnum
from functools import wraps
from typing import Any

import jwt
from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
import bcrypt
from sqlalchemy.ext.asyncio import AsyncSession

from api.core.config import get_settings
from api.core.database import get_db

settings = get_settings()

# ──── Password Hashing ────


def hash_password(password: str) -> str:
    """Hash a plain-text password using bcrypt directly."""
    pwd_bytes = password.encode("utf-8")[:72]
    salt = bcrypt.gensalt(rounds=12)
    return bcrypt.hashpw(pwd_bytes, salt).decode("utf-8")


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain-text password against a bcrypt hash."""
    pwd_bytes = plain_password.encode("utf-8")[:72]
    try:
        return bcrypt.checkpw(pwd_bytes, hashed_password.encode("utf-8"))
    except Exception:
        return False


# ──── JWT Tokens ────


class TokenType(StrEnum):
    ACCESS = "access"
    REFRESH = "refresh"


def create_token(
    subject: str | uuid.UUID,
    token_type: TokenType = TokenType.ACCESS,
    extra_claims: dict[str, Any] | None = None,
) -> str:
    """Create a JWT token with the given subject and type."""
    now = datetime.now(timezone.utc)

    if token_type == TokenType.ACCESS:
        expires_delta = timedelta(minutes=settings.jwt_access_token_expire_minutes)
    else:
        expires_delta = timedelta(days=settings.jwt_refresh_token_expire_days)

    payload = {
        "sub": str(subject),
        "type": token_type.value,
        "iat": now,
        "exp": now + expires_delta,
        "jti": str(uuid.uuid4()),
    }

    if extra_claims:
        payload.update(extra_claims)

    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict[str, Any]:
    """Decode and validate a JWT token. Raises HTTPException on failure."""
    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[settings.jwt_algorithm],
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
            headers={"WWW-Authenticate": "Bearer"},
        )


def create_access_token(user_id: str | uuid.UUID, role: str) -> str:
    """Create an access token with user role embedded."""
    return create_token(user_id, TokenType.ACCESS, extra_claims={"role": role})


def create_refresh_token(user_id: str | uuid.UUID) -> str:
    """Create a refresh token."""
    return create_token(user_id, TokenType.REFRESH)


# ──── RBAC ────


class UserRole(StrEnum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


# Role hierarchy: admin > analyst > viewer
ROLE_HIERARCHY = {
    UserRole.ADMIN: 3,
    UserRole.ANALYST: 2,
    UserRole.VIEWER: 1,
}

security_scheme = HTTPBearer(auto_error=True)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: AsyncSession = Depends(get_db),
) -> dict[str, Any]:
    """
    FastAPI dependency to extract and validate the current user from JWT.
    Returns a dict with user_id and role.
    """
    payload = decode_token(credentials.credentials)

    if payload.get("type") != TokenType.ACCESS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token type. Access token required.",
        )

    user_id = payload.get("sub")
    role = payload.get("role")

    if not user_id or not role:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
        )

    # Import here to avoid circular imports
    from api.repositories.user_repository import UserRepository

    user_repo = UserRepository(db)
    user = await user_repo.get_by_id(uuid.UUID(user_id))

    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated",
        )

    return {
        "user_id": user.id,
        "email": user.email,
        "full_name": user.full_name,
        "role": user.role,
    }


def require_role(minimum_role: UserRole):
    """
    Dependency factory that enforces minimum role level.
    Usage: Depends(require_role(UserRole.ANALYST))
    """
    async def role_checker(
        current_user: dict[str, Any] = Depends(get_current_user),
    ) -> dict[str, Any]:
        user_role = current_user.get("role", "")
        user_level = ROLE_HIERARCHY.get(UserRole(user_role), 0)
        required_level = ROLE_HIERARCHY.get(minimum_role, 0)

        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Insufficient permissions. Requires {minimum_role.value} role or higher.",
            )

        return current_user

    return role_checker
