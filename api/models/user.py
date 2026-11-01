"""
SentinelX — User Model
"""

from datetime import UTC, datetime

from sqlalchemy import Boolean, DateTime, String, text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.core.database import Base


class User(Base):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(320), unique=True, index=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(128), nullable=False)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(
        String(20), nullable=False, default="viewer", server_default=text("'viewer'")
    )
    is_active: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=True, server_default=text("true")
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
        nullable=True,
    )

    # Relationships
    audit_logs = relationship("AuditLog", back_populates="user", lazy="selectin")
    blocked_ips = relationship("BlockedIP", back_populates="blocked_by_user", lazy="selectin")

    def __repr__(self) -> str:
        return f"<User {self.email} role={self.role}>"
