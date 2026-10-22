"""
SentinelX — Threat Schemas
"""

import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ThreatReportCreate(BaseModel):
    """Schema for reporting a threat (from extension or API)."""
    url: str = Field(..., min_length=1)
    risk_score: float = Field(..., ge=0, le=100)
    threat_type: str | None = None
    details: dict[str, Any] | None = None
    source: str = Field(default="extension", pattern=r"^(extension|api|manual)$")


class PhishingDomainResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    domain: str
    status: str
    risk_score: float | None = None
    threat_intel_data: dict[str, Any] | None = None
    created_at: datetime
    reviewed_at: datetime | None = None


class AIThreatSummaryResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    waf_log_id: uuid.UUID
    threat_classification: str
    human_readable_explanation: str
    estimated_severity: str
    estimated_impact: str | None = None
    mitigation_strategies: list[str] | None = None
    llm_provider: str
    llm_model: str
    analysis_duration_ms: float | None = None
    created_at: datetime


# ──── Dashboard Statistics ────

class DashboardOverview(BaseModel):
    """Aggregated metrics for the SOC dashboard overview."""
    total_requests_24h: int = 0
    blocked_threats_24h: int = 0
    active_blocked_ips: int = 0
    global_risk_score: float = 0.0
    threat_trend: list[dict[str, Any]] = []
    top_threat_types: list[dict[str, Any]] = []
    top_source_countries: list[dict[str, Any]] = []
    severity_distribution: dict[str, int] = {}


class AttackStreamEntry(BaseModel):
    """Single entry in the live attack stream."""
    id: uuid.UUID
    timestamp: datetime
    source_ip: str
    country_code: str | None = None
    threat_type: str
    severity: str
    request_path: str
    action_taken: str
    matched_rule_id: str | None = None
