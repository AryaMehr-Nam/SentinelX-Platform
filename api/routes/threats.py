"""
SentinelX — Threat Intelligence Routes
"""

import uuid

from fastapi import APIRouter, Depends, Query, Request
from sqlalchemy.ext.asyncio import AsyncSession

from api.core.database import get_db
from api.core.security import get_current_user, require_role, UserRole
from api.schemas.threat import (
    AIThreatSummaryResponse,
    PhishingDomainResponse,
    ThreatReportCreate,
)
from api.services.threat_service import ThreatService

router = APIRouter()


@router.post("/report", response_model=PhishingDomainResponse, status_code=201)
async def report_threat(
    body: ThreatReportCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Report a potentially malicious URL/domain.
    This endpoint is intentionally public to allow the browser extension
    to report threats without authentication.
    """
    client_ip = request.client.host if request.client else None
    service = ThreatService(db)
    domain = await service.report_threat(
        url=body.url,
        risk_score=body.risk_score,
        threat_type=body.threat_type,
        details=body.details,
        reporter_ip=client_ip,
    )
    return PhishingDomainResponse.model_validate(domain)


@router.get("/domains", response_model=dict)
async def list_phishing_domains(
    status_filter: str | None = Query(None, alias="status"),
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=20, ge=1, le=100),
    current_user: dict = Depends(require_role(UserRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """List reported phishing domains (Analyst+)."""
    service = ThreatService(db)
    domains, total = await service.get_phishing_domains(
        status_filter=status_filter, page=page, per_page=per_page
    )
    return {
        "domains": [PhishingDomainResponse.model_validate(d) for d in domains],
        "total": total,
        "page": page,
        "per_page": per_page,
    }


@router.patch("/domains/{domain_id}/status", response_model=PhishingDomainResponse)
async def update_domain_status(
    domain_id: uuid.UUID,
    new_status: str = Query(..., pattern=r"^(pending|confirmed|false_positive)$"),
    current_user: dict = Depends(require_role(UserRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """Update the review status of a phishing domain (Analyst+)."""
    service = ThreatService(db)
    domain = await service.update_domain_status(domain_id, new_status)
    return PhishingDomainResponse.model_validate(domain)


@router.get("/ai-summaries", response_model=list[AIThreatSummaryResponse])
async def list_ai_summaries(
    limit: int = Query(default=20, ge=1, le=100),
    current_user: dict = Depends(require_role(UserRole.VIEWER)),
    db: AsyncSession = Depends(get_db),
):
    """List recent AI-generated threat analysis summaries."""
    from api.repositories.waf_repository import AIThreatSummaryRepository
    repo = AIThreatSummaryRepository(db)
    summaries = await repo.get_recent(limit=limit)
    return [AIThreatSummaryResponse.model_validate(s) for s in summaries]
