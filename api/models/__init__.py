"""
SentinelX — Models Package
Import all models here so SQLAlchemy discovers them during metadata.create_all().
"""

from api.models.user import User
from api.models.audit_log import AuditLog
from api.models.waf_log import WAFLog
from api.models.blocked_ip import BlockedIP
from api.models.phishing_domain import PhishingDomain
from api.models.ai_threat_summary import AIThreatSummary
from api.models.waf_rule import WAFRule

__all__ = [
    "User",
    "AuditLog",
    "WAFLog",
    "BlockedIP",
    "PhishingDomain",
    "AIThreatSummary",
    "WAFRule",
]
