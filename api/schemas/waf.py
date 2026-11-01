"""
SentinelX — WAF Schemas
"""

import uuid
from datetime import datetime
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ThreatType(StrEnum):
    SQLI = "sqli"
    XSS = "xss"
    PATH_TRAVERSAL = "path_traversal"
    CMD_INJECTION = "cmd_injection"
    RATE_LIMIT = "rate_limit"
    OTHER = "other"


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ActionTaken(StrEnum):
    BLOCKED = "blocked"
    LOGGED = "logged"
    CHALLENGED = "challenged"


# ──── WAF Log Schemas ────


class WAFLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    source_ip: str
    country_code: str | None = None
    request_method: str
    request_path: str
    matched_rule_id: str | None = None
    threat_type: str
    severity: str
    action_taken: str
    user_agent: str | None = None
    created_at: datetime


class WAFLogListResponse(BaseModel):
    logs: list[WAFLogResponse]
    total: int
    page: int
    per_page: int


class WAFLogFilter(BaseModel):
    threat_type: ThreatType | None = None
    severity: Severity | None = None
    source_ip: str | None = None
    action_taken: ActionTaken | None = None
    start_date: datetime | None = None
    end_date: datetime | None = None


# ──── WAF Rule Schemas ────


class WAFRuleCreate(BaseModel):
    rule_id: str = Field(..., min_length=1, max_length=50, pattern=r"^[A-Z0-9\-]+$")
    name: str = Field(..., min_length=1, max_length=255)
    description: str | None = None
    category: str = Field(..., pattern=r"^(sqli|xss|path_traversal|cmd_injection|custom)$")
    rule_definition: dict[str, Any]
    is_enabled: bool = True
    priority: int = Field(default=50, ge=1, le=100)
    action: str = Field(default="block", pattern=r"^(block|log|challenge)$")


class WAFRuleUpdate(BaseModel):
    name: str | None = Field(None, min_length=1, max_length=255)
    description: str | None = None
    rule_definition: dict[str, Any] | None = None
    is_enabled: bool | None = None
    priority: int | None = Field(None, ge=1, le=100)
    action: str | None = Field(None, pattern=r"^(block|log|challenge)$")


class WAFRuleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    rule_id: str
    name: str
    description: str | None = None
    category: str
    rule_definition: dict[str, Any]
    is_enabled: bool
    priority: int
    action: str
    created_at: datetime
    updated_at: datetime | None = None


# ──── Blocked IP Schemas ────


class BlockedIPCreate(BaseModel):
    ip_address: str = Field(..., min_length=7, max_length=45)
    reason: str = Field(..., min_length=1)
    block_type: str = Field(default="manual", pattern=r"^(manual|auto|geoip)$")
    country_code: str | None = Field(None, max_length=3)
    blocked_until: datetime | None = None
    is_permanent: bool = False


class BlockedIPResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    ip_address: str
    reason: str
    block_type: str
    country_code: str | None = None
    blocked_until: datetime | None = None
    is_permanent: bool
    created_at: datetime
