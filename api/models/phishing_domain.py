"""
SentinelX — Phishing Domain Model
"""

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import JSON, DateTime, Float, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column

from api.core.database import Base


class PhishingDomain(Base):
    __tablename__ = "phishing_domains"

    domain: Mapped[str] = mapped_column(String(512), unique=True, nullable=False, index=True)
    reported_by_ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    reported_by_user: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending", index=True)
    threat_intel_data: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    risk_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    def __repr__(self) -> str:
        return f"<PhishingDomain {self.domain} status={self.status}>"
