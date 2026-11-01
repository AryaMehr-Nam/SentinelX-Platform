"""
SentinelX — WAF Repository
Data access layer for WAF logs, rules, and blocked IPs.
"""

import uuid
from collections.abc import Sequence
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.models.ai_threat_summary import AIThreatSummary
from api.models.blocked_ip import BlockedIP
from api.models.waf_log import WAFLog
from api.models.waf_rule import WAFRule


class WAFLogRepository:
    """Repository for WAF log database operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, log: WAFLog) -> WAFLog:
        self.session.add(log)
        await self.session.flush()
        await self.session.refresh(log)
        return log

    async def get_by_id(self, log_id: uuid.UUID) -> WAFLog | None:
        result = await self.session.execute(select(WAFLog).where(WAFLog.id == log_id))
        return result.scalar_one_or_none()

    async def get_recent(
        self,
        page: int = 1,
        per_page: int = 50,
        threat_type: str | None = None,
        severity: str | None = None,
        source_ip: str | None = None,
        action_taken: str | None = None,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> tuple[Sequence[WAFLog], int]:
        """Get WAF logs with filtering and pagination."""
        conditions = []
        if threat_type:
            conditions.append(WAFLog.threat_type == threat_type)
        if severity:
            conditions.append(WAFLog.severity == severity)
        if source_ip:
            conditions.append(WAFLog.source_ip == source_ip)
        if action_taken:
            conditions.append(WAFLog.action_taken == action_taken)
        if start_date:
            conditions.append(WAFLog.created_at >= start_date)
        if end_date:
            conditions.append(WAFLog.created_at <= end_date)

        where_clause = and_(*conditions) if conditions else True

        count_result = await self.session.execute(select(func.count(WAFLog.id)).where(where_clause))
        total = count_result.scalar_one()

        offset = (page - 1) * per_page
        result = await self.session.execute(
            select(WAFLog)
            .where(where_clause)
            .order_by(desc(WAFLog.created_at))
            .offset(offset)
            .limit(per_page)
        )
        logs = result.scalars().all()
        return logs, total

    async def get_stats_24h(self) -> dict[str, Any]:
        """Get aggregated statistics for the last 24 hours."""
        since = datetime.now(UTC) - timedelta(hours=24)

        total_result = await self.session.execute(
            select(func.count(WAFLog.id)).where(WAFLog.created_at >= since)
        )
        total = total_result.scalar_one()

        blocked_result = await self.session.execute(
            select(func.count(WAFLog.id)).where(
                and_(WAFLog.created_at >= since, WAFLog.action_taken == "blocked")
            )
        )
        blocked = blocked_result.scalar_one()

        # Threat type distribution
        type_result = await self.session.execute(
            select(WAFLog.threat_type, func.count(WAFLog.id))
            .where(WAFLog.created_at >= since)
            .group_by(WAFLog.threat_type)
            .order_by(desc(func.count(WAFLog.id)))
        )
        threat_types = [{"type": row[0], "count": row[1]} for row in type_result.all()]

        # Severity distribution
        severity_result = await self.session.execute(
            select(WAFLog.severity, func.count(WAFLog.id))
            .where(WAFLog.created_at >= since)
            .group_by(WAFLog.severity)
        )
        severity_dist = {row[0]: row[1] for row in severity_result.all()}

        # Top countries
        country_result = await self.session.execute(
            select(WAFLog.country_code, func.count(WAFLog.id))
            .where(and_(WAFLog.created_at >= since, WAFLog.country_code.isnot(None)))
            .group_by(WAFLog.country_code)
            .order_by(desc(func.count(WAFLog.id)))
            .limit(10)
        )
        top_countries = [{"country": row[0], "count": row[1]} for row in country_result.all()]

        # Hourly trend (last 24 hours) - dialect aware
        bind = self.session.bind
        dialect_name = getattr(bind, "dialect", None)
        dialect_str = getattr(dialect_name, "name", "") if dialect_name else ""
        if dialect_str == "sqlite":
            hour_expr = func.strftime("%Y-%m-%d %H:00:00", WAFLog.created_at).label("hour")
        else:
            hour_expr = func.date_trunc("hour", WAFLog.created_at).label("hour")

        trend_result = await self.session.execute(
            select(
                hour_expr,
                func.count(WAFLog.id),
            )
            .where(WAFLog.created_at >= since)
            .group_by("hour")
            .order_by("hour")
        )
        trend = [
            {
                "time": row[0].isoformat() if hasattr(row[0], "isoformat") else str(row[0]),
                "count": row[1],
            }
            for row in trend_result.all()
        ]

        return {
            "total_requests_24h": total,
            "blocked_threats_24h": blocked,
            "top_threat_types": threat_types,
            "severity_distribution": severity_dist,
            "top_source_countries": top_countries,
            "threat_trend": trend,
        }


class WAFRuleRepository:
    """Repository for WAF rule database operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_all(self, enabled_only: bool = False) -> Sequence[WAFRule]:
        query = select(WAFRule).order_by(WAFRule.priority)
        if enabled_only:
            query = query.where(WAFRule.is_enabled == True)
        result = await self.session.execute(query)
        return result.scalars().all()

    async def get_by_rule_id(self, rule_id: str) -> WAFRule | None:
        result = await self.session.execute(select(WAFRule).where(WAFRule.rule_id == rule_id))
        return result.scalar_one_or_none()

    async def create(self, rule: WAFRule) -> WAFRule:
        self.session.add(rule)
        await self.session.flush()
        await self.session.refresh(rule)
        return rule

    async def update(self, rule: WAFRule, updates: dict) -> WAFRule:
        for key, value in updates.items():
            if value is not None and hasattr(rule, key):
                setattr(rule, key, value)
        await self.session.flush()
        await self.session.refresh(rule)
        return rule

    async def delete(self, rule: WAFRule) -> None:
        await self.session.delete(rule)
        await self.session.flush()


class BlockedIPRepository:
    """Repository for blocked IP database operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_all(self) -> Sequence[BlockedIP]:
        result = await self.session.execute(select(BlockedIP).order_by(desc(BlockedIP.created_at)))
        return result.scalars().all()

    async def get_by_ip(self, ip_address: str) -> BlockedIP | None:
        result = await self.session.execute(
            select(BlockedIP).where(BlockedIP.ip_address == ip_address)
        )
        return result.scalar_one_or_none()

    async def is_blocked(self, ip_address: str) -> bool:
        """Check if an IP is currently blocked (respecting expiration)."""
        entry = await self.get_by_ip(ip_address)
        if entry is None:
            return False
        if entry.is_permanent:
            return True
        if entry.blocked_until and entry.blocked_until < datetime.now(UTC):
            # Block has expired, remove it
            await self.session.delete(entry)
            await self.session.flush()
            return False
        return True

    async def create(self, blocked_ip: BlockedIP) -> BlockedIP:
        self.session.add(blocked_ip)
        await self.session.flush()
        await self.session.refresh(blocked_ip)
        return blocked_ip

    async def delete_by_ip(self, ip_address: str) -> bool:
        entry = await self.get_by_ip(ip_address)
        if entry:
            await self.session.delete(entry)
            await self.session.flush()
            return True
        return False

    async def count_active(self) -> int:
        result = await self.session.execute(select(func.count(BlockedIP.id)))
        return result.scalar_one()


class AIThreatSummaryRepository:
    """Repository for AI threat summary operations."""

    def __init__(self, session: AsyncSession):
        self.session = session

    async def create(self, summary: AIThreatSummary) -> AIThreatSummary:
        self.session.add(summary)
        await self.session.flush()
        await self.session.refresh(summary)
        return summary

    async def get_by_waf_log_id(self, waf_log_id: uuid.UUID) -> AIThreatSummary | None:
        result = await self.session.execute(
            select(AIThreatSummary).where(AIThreatSummary.waf_log_id == waf_log_id)
        )
        return result.scalar_one_or_none()

    async def get_recent(self, limit: int = 20) -> Sequence[AIThreatSummary]:
        result = await self.session.execute(
            select(AIThreatSummary).order_by(desc(AIThreatSummary.created_at)).limit(limit)
        )
        return result.scalars().all()
