"""
SentinelX — WAF Log Model
Records every request intercepted by the WAF engine.
"""

from typing import Any

from sqlalchemy import JSON, Index, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.core.database import Base


class WAFLog(Base):
    __tablename__ = "waf_logs"
    __table_args__ = (
        Index("ix_waf_logs_source_ip_created", "source_ip", "created_at"),
        Index("ix_waf_logs_threat_type_severity", "threat_type", "severity"),
    )

    source_ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    country_code: Mapped[str | None] = mapped_column(String(3), nullable=True)
    request_method: Mapped[str] = mapped_column(String(10), nullable=False)
    request_path: Mapped[str] = mapped_column(String(2048), nullable=False)
    request_body: Mapped[str | None] = mapped_column(Text, nullable=True)
    query_string: Mapped[str | None] = mapped_column(Text, nullable=True)
    matched_rule_id: Mapped[str | None] = mapped_column(String(50), nullable=True, index=True)
    threat_type: Mapped[str] = mapped_column(
        String(30), nullable=False, default="other", index=True
    )
    severity: Mapped[str] = mapped_column(String(20), nullable=False, default="low", index=True)
    action_taken: Mapped[str] = mapped_column(String(20), nullable=False, default="logged")
    raw_headers: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    user_agent: Mapped[str | None] = mapped_column(String(512), nullable=True)

    # Relationships
    ai_summary = relationship(
        "AIThreatSummary", back_populates="waf_log", uselist=False, lazy="selectin"
    )

    def __repr__(self) -> str:
        return f"<WAFLog {self.source_ip} {self.threat_type} {self.severity}>"
