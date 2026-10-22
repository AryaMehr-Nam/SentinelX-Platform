"""
SentinelX — Celery Application Configuration
"""

from celery import Celery
from celery.schedules import crontab

from api.core.config import get_settings

settings = get_settings()

celery_app = Celery(
    "sentinelx",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=[
        "api.workers.threat_intel",
        "api.workers.ai_analysis",
    ],
)

celery_app.conf.update(
    # Serialization
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",

    # Timezone
    timezone="UTC",
    enable_utc=True,

    # Task settings
    task_track_started=True,
    task_time_limit=300,  # 5 minutes max per task
    task_soft_time_limit=240,  # Soft limit at 4 minutes
    task_acks_late=True,
    worker_prefetch_multiplier=1,

    # Result settings
    result_expires=3600,  # Results expire after 1 hour

    # Retry settings
    task_default_retry_delay=60,  # 1 minute
    task_max_retries=3,

    # Periodic tasks
    beat_schedule={
        "cleanup-expired-blocks": {
            "task": "api.workers.threat_intel.cleanup_expired_blocks",
            "schedule": crontab(minute="*/30"),  # Every 30 minutes
        },
        "refresh-threat-intel-feeds": {
            "task": "api.workers.threat_intel.refresh_threat_feeds",
            "schedule": crontab(hour="*/6"),  # Every 6 hours
        },
    },
)
