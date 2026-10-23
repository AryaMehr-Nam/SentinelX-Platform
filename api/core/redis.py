"""
SentinelX — Redis Client & In-Memory Fallback
Async Redis connection for rate limiting, caching, and IP management with transparent in-memory fallback.
"""

import asyncio
import logging
import time
import builtins
from typing import Any, Set

from api.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()


class InMemoryPipeline:
    """Mock Redis Pipeline for in-memory operations."""

    def __init__(self, backend: "InMemoryRedisFallback"):
        self.backend = backend
        self.commands: list[tuple[str, tuple, dict]] = []

    def zremrangebyscore(self, key: str, min_score: float, max_score: float):
        self.commands.append(("zremrangebyscore", (key, min_score, max_score), {}))
        return self

    def zcard(self, key: str):
        self.commands.append(("zcard", (key,), {}))
        return self

    def zadd(self, key: str, mapping: dict[str, float]):
        self.commands.append(("zadd", (key, mapping), {}))
        return self

    def expire(self, key: str, seconds: int):
        self.commands.append(("expire", (key, seconds), {}))
        return self

    def set(self, key: str, value: Any, ex: int | None = None):
        self.commands.append(("set", (key, value), {"ex": ex}))
        return self

    def get(self, key: str):
        self.commands.append(("get", (key,), {}))
        return self

    def incr(self, key: str):
        self.commands.append(("incr", (key,), {}))
        return self

    def delete(self, *keys: str):
        self.commands.append(("delete", keys, {}))
        return self

    def sadd(self, key: str, *members: str):
        self.commands.append(("sadd", (key, *members), {}))
        return self

    def srem(self, key: str, *members: str):
        self.commands.append(("srem", (key, *members), {}))
        return self

    async def execute(self) -> list[Any]:
        results = []
        for cmd, args, kwargs in self.commands:
            fn = getattr(self.backend, cmd)
            res = await fn(*args, **kwargs)
            results.append(res)
        self.commands.clear()
        return results


class InMemoryRedisFallback:
    """
    High-performance in-memory fallback mimicking the redis.asyncio API.
    Enables rate limiting, blacklisting, and reputation scoring without an external Redis server.
    """

    def __init__(self):
        self._strings: dict[str, tuple[str, float | None]] = {}
        self._sets: dict[str, Set[str]] = {}
        self._zsets: dict[str, dict[str, float]] = {}
        self._lock = asyncio.Lock()

    async def ping(self) -> bool:
        return True

    def pipeline(self) -> InMemoryPipeline:
        return InMemoryPipeline(self)

    # ──── Strings & Key Operations ────

    async def get(self, key: str) -> str | None:
        async with self._lock:
            if key not in self._strings:
                return None
            val, exp = self._strings[key]
            if exp is not None and time.time() > exp:
                del self._strings[key]
                return None
            return val

    async def set(self, key: str, value: Any, ex: int | None = None) -> bool:
        async with self._lock:
            exp = (time.time() + ex) if ex else None
            self._strings[key] = (str(value), exp)
            return True

    async def incr(self, key: str) -> int:
        async with self._lock:
            val, exp = self._strings.get(key, ("0", None))
            try:
                new_val = int(val) + 1
            except ValueError:
                new_val = 1
            self._strings[key] = (str(new_val), exp)
            return new_val

    async def delete(self, *keys: str) -> int:
        count = 0
        async with self._lock:
            for k in keys:
                if k in self._strings:
                    del self._strings[k]
                    count += 1
                if k in self._sets:
                    del self._sets[k]
                    count += 1
                if k in self._zsets:
                    del self._zsets[k]
                    count += 1
        return count

    async def expire(self, key: str, seconds: int) -> bool:
        async with self._lock:
            exp = time.time() + seconds
            if key in self._strings:
                v, _ = self._strings[key]
                self._strings[key] = (v, exp)
                return True
            return False

    async def ttl(self, key: str) -> int:
        async with self._lock:
            if key in self._strings:
                _, exp = self._strings[key]
                if exp is None:
                    return -1
                remaining = int(exp - time.time())
                return max(0, remaining)
            return -2

    # ──── Sets ────

    async def sadd(self, key: str, *members: str) -> int:
        async with self._lock:
            s = self._sets.setdefault(key, set())
            added = 0
            for m in members:
                if m not in s:
                    s.add(m)
                    added += 1
            return added

    async def srem(self, key: str, *members: str) -> int:
        async with self._lock:
            if key not in self._sets:
                return 0
            s = self._sets[key]
            removed = 0
            for m in members:
                if m in s:
                    s.remove(m)
                    removed += 1
            return removed

    async def sismember(self, key: str, member: str) -> bool:
        async with self._lock:
            s = self._sets.get(key, builtins.set())
            return member in s

    async def smembers(self, key: str) -> Set[str]:
        async with self._lock:
            return builtins.set(self._sets.get(key, builtins.set()))

    # ──── Sorted Sets (for Sliding Window Rate Limiting) ────

    async def zadd(self, key: str, mapping: dict[str, float]) -> int:
        async with self._lock:
            zs = self._zsets.setdefault(key, {})
            added = 0
            for member, score in mapping.items():
                if member not in zs:
                    added += 1
                zs[member] = float(score)
            return added

    async def zcard(self, key: str) -> int:
        async with self._lock:
            return len(self._zsets.get(key, {}))

    async def zremrangebyscore(self, key: str, min_score: float, max_score: float) -> int:
        async with self._lock:
            if key not in self._zsets:
                return 0
            zs = self._zsets[key]
            to_remove = [m for m, score in zs.items() if min_score <= score <= max_score]
            for m in to_remove:
                del zs[m]
            return len(to_remove)

    async def close(self) -> None:
        pass


# Global Redis connection instance
_redis_instance: Any | None = None
_using_fallback: bool = False


async def get_redis() -> Any:
    """Get the Redis connection instance (or in-memory fallback)."""
    global _redis_instance, _using_fallback
    if _redis_instance is None:
        try:
            import redis.asyncio as aioredis
            client = aioredis.from_url(
                settings.redis_url,
                encoding="utf-8",
                decode_responses=True,
                max_connections=20,
                retry_on_timeout=True,
                socket_timeout=1.5,
                socket_connect_timeout=1.5,
            )
            # Test connection
            await client.ping()
            _redis_instance = client
            _using_fallback = False
            logger.info("Connected to primary Redis server.")
        except Exception as exc:
            logger.warning(
                f"Redis server unavailable ({settings.redis_url}): {exc}. "
                "Enabling transparent in-memory Redis fallback (Rate limiting & IP management active)."
            )
            _redis_instance = InMemoryRedisFallback()
            _using_fallback = True
    return _redis_instance


async def init_redis() -> Any:
    """Initialize Redis or fallback."""
    return await get_redis()


async def close_redis() -> None:
    """Close the Redis connection or cleanup fallback."""
    global _redis_instance
    if _redis_instance is not None:
        await _redis_instance.close()
        _redis_instance = None
        logger.info("Redis connection closed")


# ──── Redis Key Namespaces ────

class RedisKeys:
    """Centralized Redis key management to avoid collisions."""

    RATE_LIMIT = "sentinelx:rate_limit:{identifier}:{window}"
    IP_BLACKLIST = "sentinelx:ip:blacklist"
    IP_WHITELIST = "sentinelx:ip:whitelist"
    IP_REPUTATION = "sentinelx:ip:reputation:{ip}"
    CACHE_WAF_RULES = "sentinelx:cache:waf_rules"
    CACHE_THREAT_INTEL = "sentinelx:cache:threat_intel:{domain}"
    TOKEN_BLACKLIST = "sentinelx:tokens:blacklist"

    @staticmethod
    def rate_limit_key(identifier: str, window: str) -> str:
        return f"sentinelx:rate_limit:{identifier}:{window}"

    @staticmethod
    def ip_reputation_key(ip: str) -> str:
        return f"sentinelx:ip:reputation:{ip}"

    @staticmethod
    def threat_intel_cache_key(domain: str) -> str:
        return f"sentinelx:cache:threat_intel:{domain}"
