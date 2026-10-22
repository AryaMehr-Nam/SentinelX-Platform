"""
SentinelX — Elasticsearch Client
Async Elasticsearch connection for security log ingestion and search.
"""

import logging
from datetime import datetime, timezone
from typing import Any

try:
    from elasticsearch import AsyncElasticsearch
except ImportError:
    AsyncElasticsearch = None

from api.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

_es_client: Any | None = None


async def get_elasticsearch() -> Any | None:
    """Get the Elasticsearch client instance. Returns None if ES is unavailable."""
    global _es_client
    if AsyncElasticsearch is None:
        return None
    if _es_client is None:
        try:
            _es_client = AsyncElasticsearch(
                hosts=[settings.elasticsearch_url],
                request_timeout=30,
                max_retries=3,
                retry_on_timeout=True,
            )
            info = await _es_client.info()
            logger.info(f"Elasticsearch connected: {info['version']['number']}")
        except Exception as e:
            logger.warning(
                f"Elasticsearch unavailable: {e}. "
                "Log ingestion will fall back to PostgreSQL only."
            )
            _es_client = None
    return _es_client


async def init_elasticsearch() -> None:
    """Initialize Elasticsearch indices with proper mappings."""
    es = await get_elasticsearch()
    if es is None:
        return

    # WAF Logs Index
    waf_index = settings.elasticsearch_waf_index
    if not await es.indices.exists(index=waf_index):
        await es.indices.create(
            index=waf_index,
            body={
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                    "refresh_interval": "5s",
                },
                "mappings": {
                    "properties": {
                        "timestamp": {"type": "date"},
                        "source_ip": {"type": "ip"},
                        "country_code": {"type": "keyword"},
                        "request_method": {"type": "keyword"},
                        "request_path": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                        "request_body": {"type": "text"},
                        "matched_rule_id": {"type": "keyword"},
                        "threat_type": {"type": "keyword"},
                        "severity": {"type": "keyword"},
                        "action_taken": {"type": "keyword"},
                        "raw_headers": {"type": "object", "enabled": False},
                        "user_agent": {"type": "text", "fields": {"keyword": {"type": "keyword"}}},
                    }
                },
            },
        )
        logger.info(f"Created Elasticsearch index: {waf_index}")

    # Audit Logs Index
    audit_index = settings.elasticsearch_audit_index
    if not await es.indices.exists(index=audit_index):
        await es.indices.create(
            index=audit_index,
            body={
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0,
                },
                "mappings": {
                    "properties": {
                        "timestamp": {"type": "date"},
                        "user_id": {"type": "keyword"},
                        "action": {"type": "keyword"},
                        "resource": {"type": "keyword"},
                        "ip_address": {"type": "ip"},
                        "details": {"type": "object", "enabled": False},
                    }
                },
            },
        )
        logger.info(f"Created Elasticsearch index: {audit_index}")


async def index_waf_log(log_data: dict[str, Any]) -> None:
    """Index a WAF log entry into Elasticsearch."""
    es = await get_elasticsearch()
    if es is None:
        return

    log_data["timestamp"] = datetime.now(timezone.utc).isoformat()
    try:
        await es.index(
            index=settings.elasticsearch_waf_index,
            document=log_data,
        )
    except Exception as e:
        logger.error(f"Failed to index WAF log to Elasticsearch: {e}")


async def index_audit_log(log_data: dict[str, Any]) -> None:
    """Index an audit log entry into Elasticsearch."""
    es = await get_elasticsearch()
    if es is None:
        return

    log_data["timestamp"] = datetime.now(timezone.utc).isoformat()
    try:
        await es.index(
            index=settings.elasticsearch_audit_index,
            document=log_data,
        )
    except Exception as e:
        logger.error(f"Failed to index audit log to Elasticsearch: {e}")


async def search_waf_logs(
    query: dict[str, Any],
    size: int = 50,
    sort: list[dict] | None = None,
) -> dict[str, Any]:
    """Search WAF logs in Elasticsearch."""
    es = await get_elasticsearch()
    if es is None:
        return {"hits": {"total": {"value": 0}, "hits": []}}

    if sort is None:
        sort = [{"timestamp": {"order": "desc"}}]

    try:
        result = await es.search(
            index=settings.elasticsearch_waf_index,
            body={"query": query, "size": size, "sort": sort},
        )
        return result
    except Exception as e:
        logger.error(f"Elasticsearch search failed: {e}")
        return {"hits": {"total": {"value": 0}, "hits": []}}


async def close_elasticsearch() -> None:
    """Close the Elasticsearch client."""
    global _es_client
    if _es_client is not None:
        await _es_client.close()
        _es_client = None
        logger.info("Elasticsearch connection closed")
