"""
SentinelX — Async Database Configuration
SQLAlchemy 2.0 async engine and session management with multi-database support (PostgreSQL & SQLite).
"""

import logging
import uuid
from collections.abc import AsyncGenerator
from datetime import UTC, datetime

from sqlalchemy import MetaData, func
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from api.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# Naming convention for constraints (makes Alembic migrations deterministic)
convention = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}

metadata = MetaData(naming_convention=convention)


def _build_engine(database_url: str):
    """Build an async engine tailored to dialect (PostgreSQL vs SQLite)."""
    if "sqlite" not in database_url:
        try:
            return create_async_engine(
                database_url,
                echo=settings.database_echo,
                pool_size=20,
                max_overflow=10,
                pool_pre_ping=True,
                pool_recycle=3600,
            )
        except Exception as exc:
            logger.warning(
                f"Could not initialize engine for {database_url}: {exc}. Defaulting to SQLite."
            )

    return create_async_engine(
        "sqlite+aiosqlite:///./sentinelx.db",
        echo=settings.database_echo,
        connect_args={"check_same_thread": False},
    )


def get_sync_database_url(database_url: str | None = None) -> str:
    """Derive a synchronous database URL for Celery workers and background tasks."""
    url = database_url or settings.database_url
    if "sqlite" in url:
        return url.replace("+aiosqlite", "")
    return url.replace("+asyncpg", "")


def build_sync_engine():
    """Create a synchronous SQLAlchemy engine with SQLite fallback."""
    from sqlalchemy import create_engine

    sync_url = get_sync_database_url()
    try:
        engine = create_engine(sync_url)
        # Test connection
        with engine.connect():
            pass
        return engine
    except Exception as exc:
        logger.warning(
            f"Could not initialize sync engine for {sync_url}: {exc}. Defaulting to SQLite."
        )
        return create_engine("sqlite:///./sentinelx.db")


engine = _build_engine(settings.database_url)

async_session_factory = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""

    metadata = metadata

    id: Mapped[uuid.UUID] = mapped_column(
        primary_key=True,
        default=uuid.uuid4,
    )
    created_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(UTC),
        server_default=func.now(),
    )


async def get_db() -> AsyncGenerator[AsyncSession]:
    """FastAPI dependency that yields an async database session."""
    async with async_session_factory() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db() -> None:
    """Create all tables. If PostgreSQL is unreachable, fallback to SQLite automatically."""
    global engine, async_session_factory

    # Try connecting with the primary configured database
    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        logger.info(
            f"Database initialized successfully with URL: {settings.database_url.split('@')[-1] if '@' in settings.database_url else settings.database_url}"
        )
    except Exception as exc:
        if "sqlite" not in settings.database_url:
            logger.warning(
                f"Primary database ({settings.database_url.split('@')[-1] if '@' in settings.database_url else settings.database_url}) "
                f"is unavailable: {exc}. Falling back to local SQLite: sqlite+aiosqlite:///./sentinelx.db"
            )
            fallback_url = "sqlite+aiosqlite:///./sentinelx.db"
            engine = _build_engine(fallback_url)
            async_session_factory = async_sessionmaker(
                engine,
                class_=AsyncSession,
                expire_on_commit=False,
            )
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
            logger.info("Local SQLite database initialized successfully (fallback mode active).")
        else:
            raise exc


async def close_db() -> None:
    """Dispose the engine connection pool."""
    global engine
    if engine is not None:
        await engine.dispose()
