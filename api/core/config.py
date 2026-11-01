"""
SentinelX — Application Configuration
Centralized settings management using Pydantic Settings.
All configuration is loaded from environment variables or .env files.
"""

from functools import lru_cache
from typing import Any

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ──── Application ────
    app_name: str = "SentinelX"
    app_version: str = "1.0.0"
    app_env: str = "development"
    app_debug: bool = True
    app_host: str = "0.0.0.0"
    app_port: int = 8000

    # ──── Database ────
    database_url: str = "postgresql+asyncpg://sentinelx:sentinelx-secret@localhost:5432/sentinelx"
    database_echo: bool = False

    # ──── Redis ────
    redis_url: str = "redis://:sentinelx-redis@localhost:6379/0"

    # ──── Elasticsearch ────
    elasticsearch_url: str = "http://localhost:9200"
    elasticsearch_index_prefix: str = "sentinelx"

    # ──── JWT Authentication ────
    jwt_secret_key: str = "change-this-to-a-secure-random-string-in-production"
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7

    # ──── CORS ────
    cors_origins: list[str] = [
        "http://localhost:3000",
        "http://localhost:5173",
    ]

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: Any) -> list[str]:
        if isinstance(v, str):
            import json

            try:
                return json.loads(v)
            except (json.JSONDecodeError, TypeError):
                return [origin.strip() for origin in v.split(",")]
        return v

    # ──── WAF Configuration ────
    waf_enabled: bool = True
    waf_mode: str = "block"  # "block" | "log" | "off"
    waf_log_level: str = "info"
    rate_limit_requests: int = 100
    rate_limit_window_seconds: int = 60

    # ──── Celery ────
    celery_broker_url: str = "redis://:sentinelx-redis@localhost:6379/1"
    celery_result_backend: str = "redis://:sentinelx-redis@localhost:6379/2"

    # ──── AI / LLM ────
    llm_provider: str = "ollama"  # "ollama" | "openai" | "anthropic"
    llm_model: str = "llama3"
    llm_api_base: str = "http://localhost:11434"
    llm_api_key: str = ""

    # ──── Threat Intelligence ────
    virustotal_api_key: str = ""
    abuseipdb_api_key: str = ""

    # ──── Admin Seed ────
    admin_email: str = "admin@sentinelx.io"
    admin_password: str = "sentinelx-admin"

    @property
    def is_production(self) -> bool:
        return self.app_env == "production"

    @property
    def is_testing(self) -> bool:
        return self.app_env == "testing"

    @property
    def elasticsearch_waf_index(self) -> str:
        return f"{self.elasticsearch_index_prefix}-waf-logs"

    @property
    def elasticsearch_audit_index(self) -> str:
        return f"{self.elasticsearch_index_prefix}-audit-logs"


@lru_cache
def get_settings() -> Settings:
    """Cached singleton settings instance."""
    return Settings()
