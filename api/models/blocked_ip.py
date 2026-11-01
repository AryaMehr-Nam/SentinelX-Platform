"""
SentinelX — Blocked IP Model
"""

import uuid
from datetime import datetime

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.core.database import Base


class BlockedIP(Base):
    __tablename__ = "blocked_ips"

    ip_address: Mapped[str] = mapped_column(String(45), unique=True, nullable=False, index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    block_type: Mapped[str] = mapped_column(String(20), nullable=False, default="manual")
    country_code: Mapped[str | None] = mapped_column(String(3), nullable=True)
    blocked_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    is_permanent: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    blocked_by: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True
    )

    # Relationships
    blocked_by_user = relationship("User", back_populates="blocked_ips", lazy="selectin")

    def __repr__(self) -> str:
        return f"<BlockedIP {self.ip_address} type={self.block_type}>"
