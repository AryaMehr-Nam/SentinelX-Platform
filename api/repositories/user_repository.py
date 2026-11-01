"""
SentinelX — User Repository
Data access layer for User operations.
"""

import uuid
from collections.abc import Sequence

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.user import User


class UserRepository:
    """Repository for User database operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_by_id(self, user_id: uuid.UUID) -> User | None:
        """Get a user by their UUID."""
        result = await self.session.execute(select(User).where(User.id == user_id))
        return result.scalar_one_or_none()

    async def get_by_email(self, email: str) -> User | None:
        """Get a user by their email address."""
        result = await self.session.execute(select(User).where(User.email == email))
        return result.scalar_one_or_none()

    async def get_all(self, page: int = 1, per_page: int = 20) -> tuple[Sequence[User], int]:
        """Get all users with pagination."""
        offset = (page - 1) * per_page

        # Count total
        count_result = await self.session.execute(select(func.count(User.id)))
        total = count_result.scalar_one()

        # Fetch page
        result = await self.session.execute(
            select(User).order_by(User.created_at.desc()).offset(offset).limit(per_page)
        )
        users = result.scalars().all()
        return users, total

    async def create(self, user: User) -> User:
        """Create a new user."""
        self.session.add(user)
        await self.session.flush()
        await self.session.refresh(user)
        return user

    async def update(self, user: User, updates: dict) -> User:
        """Update a user with the given fields."""
        for key, value in updates.items():
            if value is not None and hasattr(user, key):
                setattr(user, key, value)
        await self.session.flush()
        await self.session.refresh(user)
        return user

    async def delete(self, user: User) -> None:
        """Delete a user."""
        await self.session.delete(user)
        await self.session.flush()
