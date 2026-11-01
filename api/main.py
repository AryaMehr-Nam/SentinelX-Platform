"""
SentinelX — FastAPI Application Factory
Main application entry point with middleware stack, lifecycle events, and route registration.
"""

import logging
import sys
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.gzip import GZipMiddleware

from api.core.config import get_settings
from api.core.database import close_db, init_db
from api.core.elasticsearch import close_elasticsearch, init_elasticsearch
from api.core.redis import close_redis, init_redis

settings = get_settings()

# ──── Logging Configuration ────

logging.basicConfig(
    level=logging.DEBUG if settings.app_debug else logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("sentinelx")


# ──── Application Lifecycle ────


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None]:
    """Manage startup and shutdown events."""
    logger.info(f"Starting {settings.app_name} v{settings.app_version}")
    logger.info(f"Environment: {settings.app_env}")

    # Startup
    await init_db()
    logger.info("Database tables initialized")

    await init_redis()
    logger.info("Redis connection pool initialized")

    await init_elasticsearch()
    logger.info("Elasticsearch indices initialized")

    # Seed admin user & WAF rules
    await _seed_admin_user()
    await _seed_waf_rules()

    logger.info(f"{settings.app_name} is ready to accept requests")
    yield

    # Shutdown
    logger.info(f"Shutting down {settings.app_name}...")
    await close_redis()
    await close_elasticsearch()
    await close_db()
    logger.info("All connections closed. Goodbye.")


async def _seed_admin_user() -> None:
    """Create the default admin user if it doesn't exist."""
    from api.core.database import async_session_factory
    from api.core.security import UserRole, hash_password
    from api.repositories.user_repository import UserRepository

    async with async_session_factory() as session:
        repo = UserRepository(session)
        existing = await repo.get_by_email(settings.admin_email)
        if existing is None:
            from api.models.user import User

            admin = User(
                email=settings.admin_email,
                hashed_password=hash_password(settings.admin_password),
                full_name="SentinelX Admin",
                role=UserRole.ADMIN,
                is_active=True,
            )
            session.add(admin)
            await session.commit()
            logger.info(f"Admin user seeded: {settings.admin_email}")
        else:
            logger.debug("Admin user already exists, skipping seed")


async def _seed_waf_rules() -> None:
    """Seed WAF rules from YAML files into the database if empty."""
    from pathlib import Path

    from api.core.database import async_session_factory
    from api.models.waf_rule import WAFRule
    from api.repositories.waf_repository import WAFRuleRepository
    from waf.engine import RuleEngine

    async with async_session_factory() as session:
        repo = WAFRuleRepository(session)
        rules = await repo.get_all()
        if not rules:
            engine = RuleEngine()
            rules_dir = Path(__file__).resolve().parent.parent / "waf" / "rules"
            engine.load_rules_from_directory(rules_dir)
            for r in engine.get_all_rules():
                rule_obj = WAFRule(
                    rule_id=r.id,
                    name=r.name,
                    description=r.description,
                    category=r.category,
                    action=r.action,
                    priority=r.priority,
                    is_enabled=True,
                    rule_definition={
                        "match_type": r.match_type,
                        "targets": r.targets,
                        "patterns": r.patterns,
                        "metadata": r.metadata,
                    },
                )
                session.add(rule_obj)
            await session.commit()
            logger.info(f"Seeded {len(engine.get_all_rules())} WAF rules into database")


# ──── App Factory ────


def create_app() -> FastAPI:
    """Create and configure the FastAPI application."""
    application = FastAPI(
        title=settings.app_name,
        description="Open Source Web Security Platform — WAF, Threat Intelligence, and SOC Dashboard",
        version=settings.app_version,
        docs_url="/docs" if not settings.is_production else None,
        redoc_url="/redoc" if not settings.is_production else None,
        openapi_url="/openapi.json" if not settings.is_production else None,
        lifespan=lifespan,
    )

    # ──── Middleware Stack (order matters: last added = first executed) ────

    # GZip compression for responses
    application.add_middleware(GZipMiddleware, minimum_size=1000)

    # CORS
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["X-Request-ID", "X-RateLimit-Remaining"],
    )

    # WAF Middleware (only if enabled)
    if settings.waf_enabled:
        from waf.middleware import WAFMiddleware

        application.add_middleware(WAFMiddleware)

    # ──── Exception Handlers ────

    @application.exception_handler(RequestValidationError)
    async def validation_exception_handler(request: Request, exc: RequestValidationError):
        body_repr = exc.body
        if isinstance(body_repr, (bytes, bytearray)):
            try:
                body_repr = body_repr.decode("utf-8", errors="replace")
            except Exception:
                body_repr = str(body_repr)

        return JSONResponse(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            content={
                "error": "Validation Error",
                "detail": exc.errors(),
                "body": body_repr,
            },
        )

    @application.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.exception(f"Unhandled exception: {exc}")
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={
                "error": "Internal Server Error",
                "detail": "An unexpected error occurred. Please try again later.",
            },
        )

    # ──── Register Routes ────
    _register_routes(application)

    return application


def _register_routes(app: FastAPI) -> None:
    """Register all API route modules."""
    from api.routes.auth import router as auth_router
    from api.routes.dashboard_stats import router as dashboard_stats_router
    from api.routes.health import router as health_router
    from api.routes.threats import router as threats_router
    from api.routes.users import router as users_router
    from api.routes.waf_logs import router as waf_logs_router
    from api.routes.websocket import router as ws_router

    api_prefix = "/api/v1"

    app.include_router(health_router, prefix=api_prefix, tags=["Health"])
    app.include_router(auth_router, prefix=f"{api_prefix}/auth", tags=["Authentication"])
    app.include_router(users_router, prefix=f"{api_prefix}/users", tags=["Users"])
    app.include_router(waf_logs_router, prefix=f"{api_prefix}/waf", tags=["WAF"])
    app.include_router(threats_router, prefix=f"{api_prefix}/threats", tags=["Threats"])
    app.include_router(dashboard_stats_router, prefix=f"{api_prefix}/dashboard", tags=["Dashboard"])
    app.include_router(ws_router, prefix=api_prefix, tags=["Realtime"])


app = create_app()
