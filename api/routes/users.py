"""
SentinelX — User Management Routes
"""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession

from api.core.database import get_db
from api.core.security import get_current_user, require_role, UserRole, hash_password
from api.repositories.user_repository import UserRepository
from api.schemas.user import UserCreate, UserUpdate, UserResponse, UserListResponse

router = APIRouter()


@router.get("/me", response_model=UserResponse)
async def get_current_user_profile(
    current_user: dict = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get the current user's profile."""
    repo = UserRepository(db)
    user = await repo.get_by_id(current_user["user_id"])
    return UserResponse.model_validate(user)


@router.get("/", response_model=UserListResponse)
async def list_users(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    current_user: dict = Depends(require_role(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    """List all users (Admin only)."""
    repo = UserRepository(db)
    users, total = await repo.get_all(page=page, per_page=per_page)
    return UserListResponse(
        users=[UserResponse.model_validate(u) for u in users],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.post("/", response_model=UserResponse, status_code=201)
async def create_user(
    body: UserCreate,
    current_user: dict = Depends(require_role(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    """Create a new user (Admin only)."""
    repo = UserRepository(db)
    existing = await repo.get_by_email(body.email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Email already registered",
        )

    from api.models.user import User
    user = User(
        email=body.email,
        hashed_password=hash_password(body.password),
        full_name=body.full_name,
        role=body.role.value,
        is_active=True,
    )
    created = await repo.create(user)
    return UserResponse.model_validate(created)


@router.patch("/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: uuid.UUID,
    body: UserUpdate,
    current_user: dict = Depends(require_role(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    """Update a user (Admin only)."""
    repo = UserRepository(db)
    user = await repo.get_by_id(user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )

    updates = body.model_dump(exclude_unset=True)
    if "email" in updates and updates["email"] is not None and updates["email"] != user.email:
        existing = await repo.get_by_email(updates["email"])
        if existing and existing.id != user.id:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Email '{updates['email']}' is already registered",
            )
    if "role" in updates and updates["role"] is not None:
        updates["role"] = updates["role"].value
    updated = await repo.update(user, updates)
    return UserResponse.model_validate(updated)


@router.delete("/{user_id}", status_code=204)
async def delete_user(
    user_id: uuid.UUID,
    current_user: dict = Depends(require_role(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    """Delete a user (Admin only)."""
    repo = UserRepository(db)
    user = await repo.get_by_id(user_id)
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found",
        )
    if user.id == current_user["user_id"]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account",
        )
    await repo.delete(user)
