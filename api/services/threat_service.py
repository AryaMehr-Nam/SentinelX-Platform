"""
SentinelX — Threat Service
Business logic for threat reporting and phishing domain management.
"""

import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from fastapi import HTTPException, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.phishing_domain import PhishingDomain
from api.repositories.waf_repository import (
    AIThreatSummaryRepository,
    BlockedIPRepository,
    WAFLogRepository,
)


class ThreatService:
    """Service for threat intelligence operations."""

    def __init__(self, session: AsyncSession):
        self.session = session
        self.waf_log_repo = WAFLogRepository(session)
        self.blocked_ip_repo = BlockedIPRepository(session)
        self.ai_summary_repo = AIThreatSummaryRepository(session)

    async def report_threat(
        self,
        url: str,
        risk_score: float,
        threat_type: str | None = None,
        details: dict[str, Any] | None = None,
        reporter_ip: str | None = None,
        reporter_user_id: uuid.UUID | None = None,
    ) -> PhishingDomain:
        """Report a potentially malicious URL/domain."""
        parsed = urlparse(url)
        domain = parsed.hostname or url

        # Check if domain is already reported
        result = await self.session.execute(
            select(PhishingDomain).where(PhishingDomain.domain == domain)
        )
        existing = result.scalar_one_or_none()

        if existing is not None:
            # Update the existing report with new data
            existing.risk_score = max(existing.risk_score or 0, risk_score)
            if details:
                old_data = existing.threat_intel_data or {}
                old_data.update(details)
                existing.threat_intel_data = old_data
            await self.session.flush()
            await self.session.refresh(existing)
            return existing

        # Create new report
        phishing = PhishingDomain(
            domain=domain,
            reported_by_ip=reporter_ip,
            reported_by_user=reporter_user_id,
            status="pending",
            risk_score=risk_score,
            threat_intel_data=details or {"threat_type": threat_type},
        )
        self.session.add(phishing)
        await self.session.flush()
        await self.session.refresh(phishing)

        # Dispatch async threat intel lookup via Celery
        try:
            from api.workers.threat_intel import analyze_domain
            analyze_domain.delay(str(phishing.id), domain)
        except Exception:
            pass  # Celery may not be running in all environments

        return phishing

    async def get_phishing_domains(
        self,
        status_filter: str | None = None,
        page: int = 1,
        per_page: int = 20,
    ) -> tuple[list[PhishingDomain], int]:
        """Get reported phishing domains with filtering."""
        query = select(PhishingDomain)
        count_query = select(func.count(PhishingDomain.id))

        if status_filter:
            query = query.where(PhishingDomain.status == status_filter)
            count_query = count_query.where(PhishingDomain.status == status_filter)

        count_result = await self.session.execute(count_query)
        total = count_result.scalar_one()

        offset = (page - 1) * per_page
        result = await self.session.execute(
            query.order_by(PhishingDomain.created_at.desc())
            .offset(offset)
            .limit(per_page)
        )
        domains = list(result.scalars().all())
        return domains, total

    async def update_domain_status(
        self, domain_id: uuid.UUID, new_status: str
    ) -> PhishingDomain:
        """Update the review status of a reported domain."""
        result = await self.session.execute(
            select(PhishingDomain).where(PhishingDomain.id == domain_id)
        )
        domain = result.scalar_one_or_none()
        if domain is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Domain report not found",
            )
        domain.status = new_status
        domain.reviewed_at = datetime.now(timezone.utc)
        await self.session.flush()
        await self.session.refresh(domain)
        return domain

    async def get_global_risk_score(self) -> float:
        """Calculate a global risk score based on recent activity."""
        stats = await self.waf_log_repo.get_stats_24h()
        blocked = stats.get("blocked_threats_24h", 0)
        total = stats.get("total_requests_24h", 0)
        severity = stats.get("severity_distribution", {})

        if total == 0:
            return 0.0

        # Weighted severity scoring
        critical = severity.get("critical", 0) * 4
        high = severity.get("high", 0) * 3
        medium = severity.get("medium", 0) * 2
        low = severity.get("low", 0) * 1

        weighted_threats = critical + high + medium + low
        block_ratio = blocked / max(total, 1)

        # Score: 0-100 scale
        score = min(100.0, (weighted_threats * 0.5 + block_ratio * 50))
        return round(score, 1)
