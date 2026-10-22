"""
SentinelX — Dashboard Statistics Routes
Aggregated metrics for the SOC dashboard.
"""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from api.core.database import get_db
from api.core.security import require_role, UserRole
from api.repositories.waf_repository import BlockedIPRepository, WAFLogRepository
from api.schemas.threat import DashboardOverview
from api.services.threat_service import ThreatService

router = APIRouter()


@router.get("/overview", response_model=DashboardOverview)
async def get_dashboard_overview(
    current_user: dict = Depends(require_role(UserRole.VIEWER)),
    db: AsyncSession = Depends(get_db),
):
    """Get aggregated dashboard overview metrics."""
    waf_repo = WAFLogRepository(db)
    blocked_ip_repo = BlockedIPRepository(db)
    threat_service = ThreatService(db)

    stats = await waf_repo.get_stats_24h()
    active_blocked = await blocked_ip_repo.count_active()
    risk_score = await threat_service.get_global_risk_score()

    return DashboardOverview(
        total_requests_24h=stats["total_requests_24h"],
        blocked_threats_24h=stats["blocked_threats_24h"],
        active_blocked_ips=active_blocked,
        global_risk_score=risk_score,
        threat_trend=stats["threat_trend"],
        top_threat_types=stats["top_threat_types"],
        top_source_countries=stats["top_source_countries"],
        severity_distribution=stats["severity_distribution"],
    )


@router.get("/attack-stream", response_model=dict)
async def get_attack_stream(
    current_user: dict = Depends(require_role(UserRole.VIEWER)),
    db: AsyncSession = Depends(get_db),
):
    """Get the latest attack events for the live stream."""
    repo = WAFLogRepository(db)
    logs, total = await repo.get_recent(page=1, per_page=100)
    return {
        "events": [
            {
                "id": str(log.id),
                "timestamp": log.created_at.isoformat(),
                "source_ip": log.source_ip,
                "country_code": log.country_code,
                "threat_type": log.threat_type,
                "severity": log.severity,
                "request_path": log.request_path,
                "action_taken": log.action_taken,
                "matched_rule_id": log.matched_rule_id,
            }
            for log in logs
        ],
        "total": total,
    }
