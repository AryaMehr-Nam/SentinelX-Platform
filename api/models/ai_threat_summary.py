"""
SentinelX — AI Threat Summary Model
Stores LLM-generated analysis of detected threats.
"""

import uuid
from typing import Any

from sqlalchemy import Float, ForeignKey, String, Text, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from api.core.database import Base


class AIThreatSummary(Base):
    __tablename__ = "ai_threat_summaries"

    waf_log_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("waf_logs.id", ondelete="CASCADE"),
        unique=True,
        nullable=False,
        index=True,
    )
    threat_classification: Mapped[str] = mapped_column(
        String(50), nullable=False, index=True
    )
    human_readable_explanation: Mapped[str] = mapped_column(Text, nullable=False)
    estimated_severity: Mapped[str] = mapped_column(
        String(20), nullable=False, default="low"
    )
    estimated_impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    mitigation_strategies: Mapped[list[str] | None] = mapped_column(
        JSON, nullable=True
    )
    raw_llm_response: Mapped[dict[str, Any] | None] = mapped_column(
        JSON, nullable=True
    )
    llm_provider: Mapped[str] = mapped_column(String(30), nullable=False)
    llm_model: Mapped[str] = mapped_column(String(100), nullable=False)
    analysis_duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Relationships
    waf_log = relationship("WAFLog", back_populates="ai_summary", lazy="selectin")

    def __repr__(self) -> str:
        return f"<AIThreatSummary {self.threat_classification} severity={self.estimated_severity}>"
