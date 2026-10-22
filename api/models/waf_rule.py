"""
SentinelX — WAF Rule Model
Stores WAF rule definitions in the database for dynamic management.
"""

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import Boolean, Integer, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column

from api.core.database import Base


class WAFRule(Base):
    __tablename__ = "waf_rules"

    rule_id: Mapped[str] = mapped_column(
        String(50), unique=True, nullable=False, index=True
    )
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    category: Mapped[str] = mapped_column(
        String(30), nullable=False, default="custom", index=True
    )
    rule_definition: Mapped[dict[str, Any]] = mapped_column(JSON, nullable=False)
    is_enabled: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True
    )
    priority: Mapped[int] = mapped_column(
        Integer, nullable=False, default=50
    )
    action: Mapped[str] = mapped_column(
        String(20), nullable=False, default="block"
    )
    updated_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(timezone.utc),
        onupdate=lambda: datetime.now(timezone.utc),
        nullable=True,
    )

    def __repr__(self) -> str:
        return f"<WAFRule {self.rule_id} category={self.category} action={self.action}>"
