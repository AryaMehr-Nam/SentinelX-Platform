"""
SentinelX — Audit Log Model
"""

import uuid
from typing import Any

from sqlalchemy import JSON, ForeignKey, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.core.database import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource: Mapped[str] = mapped_column(String(255), nullable=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=True)
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)

    # Relationships
    user = relationship("User", back_populates="audit_logs", lazy="selectin")

    def __repr__(self) -> str:
        return f"<AuditLog action={self.action} user={self.user_id}>"
