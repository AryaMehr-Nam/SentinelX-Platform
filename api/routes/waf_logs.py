"""
SentinelX — WAF Log & Rule Management Routes
"""

import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from api.core.database import get_db
from api.core.security import get_current_user, require_role, UserRole
from api.models.blocked_ip import BlockedIP
from api.models.waf_rule import WAFRule
from api.repositories.waf_repository import (
    BlockedIPRepository,
    WAFLogRepository,
    WAFRuleRepository,
)
from api.schemas.waf import (
    BlockedIPCreate,
    BlockedIPResponse,
    WAFLogFilter,
    WAFLogListResponse,
    WAFLogResponse,
    WAFRuleCreate,
    WAFRuleResponse,
    WAFRuleUpdate,
)

router = APIRouter()


# ──── WAF Logs ────


@router.get("/logs", response_model=WAFLogListResponse)
async def list_waf_logs(
    page: int = Query(default=1, ge=1),
    per_page: int = Query(default=50, ge=1, le=200),
    threat_type: str | None = None,
    severity: str | None = None,
    source_ip: str | None = None,
    action_taken: str | None = None,
    start_date: datetime | None = None,
    end_date: datetime | None = None,
    current_user: dict = Depends(require_role(UserRole.VIEWER)),
    db: AsyncSession = Depends(get_db),
):
    """List WAF logs with filtering and pagination."""
    repo = WAFLogRepository(db)
    logs, total = await repo.get_recent(
        page=page,
        per_page=per_page,
        threat_type=threat_type,
        severity=severity,
        source_ip=source_ip,
        action_taken=action_taken,
        start_date=start_date,
        end_date=end_date,
    )
    return WAFLogListResponse(
        logs=[WAFLogResponse.model_validate(log) for log in logs],
        total=total,
        page=page,
        per_page=per_page,
    )


@router.get("/logs/{log_id}", response_model=WAFLogResponse)
async def get_waf_log(
    log_id: uuid.UUID,
    current_user: dict = Depends(require_role(UserRole.VIEWER)),
    db: AsyncSession = Depends(get_db),
):
    """Get a specific WAF log entry."""
    repo = WAFLogRepository(db)
    log = await repo.get_by_id(log_id)
    if log is None:
        raise HTTPException(status_code=404, detail="WAF log not found")
    return WAFLogResponse.model_validate(log)


# ──── WAF Rules ────


@router.get("/rules", response_model=list[WAFRuleResponse])
async def list_waf_rules(
    enabled_only: bool = Query(default=False),
    current_user: dict = Depends(require_role(UserRole.VIEWER)),
    db: AsyncSession = Depends(get_db),
):
    """List all WAF rules."""
    repo = WAFRuleRepository(db)
    rules = await repo.get_all(enabled_only=enabled_only)
    if not rules:
        from waf.engine import get_rule_engine
        engine = get_rule_engine()
        engine_rules = engine.get_all_rules()
        return [
            WAFRuleResponse(
                id=uuid.uuid4(),
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
                created_at=datetime.now(),
                updated_at=datetime.now(),
            )
            for r in engine_rules
        ]
    return [WAFRuleResponse.model_validate(r) for r in rules]


@router.post("/rules", response_model=WAFRuleResponse, status_code=201)
async def create_waf_rule(
    body: WAFRuleCreate,
    current_user: dict = Depends(require_role(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    """Create a new WAF rule (Admin only)."""
    repo = WAFRuleRepository(db)
    existing = await repo.get_by_rule_id(body.rule_id)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Rule with ID '{body.rule_id}' already exists",
        )
    rule = WAFRule(**body.model_dump())
    created = await repo.create(rule)
    return WAFRuleResponse.model_validate(created)


@router.patch("/rules/{rule_id}", response_model=WAFRuleResponse)
async def update_waf_rule(
    rule_id: str,
    body: WAFRuleUpdate,
    current_user: dict = Depends(require_role(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    """Update a WAF rule (Admin only)."""
    repo = WAFRuleRepository(db)
    rule = await repo.get_by_rule_id(rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    updates = body.model_dump(exclude_unset=True)
    updated = await repo.update(rule, updates)
    return WAFRuleResponse.model_validate(updated)


@router.delete("/rules/{rule_id}", status_code=204)
async def delete_waf_rule(
    rule_id: str,
    current_user: dict = Depends(require_role(UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    """Delete a WAF rule (Admin only)."""
    repo = WAFRuleRepository(db)
    rule = await repo.get_by_rule_id(rule_id)
    if rule is None:
        raise HTTPException(status_code=404, detail="Rule not found")
    await repo.delete(rule)


# ──── Blocked IPs ────


@router.get("/blocked-ips", response_model=list[BlockedIPResponse])
async def list_blocked_ips(
    current_user: dict = Depends(require_role(UserRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """List all blocked IPs."""
    repo = BlockedIPRepository(db)
    ips = await repo.get_all()
    return [BlockedIPResponse.model_validate(ip) for ip in ips]


@router.post("/blocked-ips", response_model=BlockedIPResponse, status_code=201)
async def block_ip(
    body: BlockedIPCreate,
    current_user: dict = Depends(require_role(UserRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """Block an IP address."""
    repo = BlockedIPRepository(db)
    existing = await repo.get_by_ip(body.ip_address)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"IP {body.ip_address} is already blocked",
        )
    blocked = BlockedIP(
        **body.model_dump(),
        blocked_by=current_user["user_id"],
    )
    created = await repo.create(blocked)
    return BlockedIPResponse.model_validate(created)


@router.delete("/blocked-ips/{ip_address}", status_code=204)
async def unblock_ip(
    ip_address: str,
    current_user: dict = Depends(require_role(UserRole.ANALYST)),
    db: AsyncSession = Depends(get_db),
):
    """Unblock an IP address."""
    repo = BlockedIPRepository(db)
    removed = await repo.delete_by_ip(ip_address)
    if not removed:
        raise HTTPException(status_code=404, detail="IP not found in block list")
