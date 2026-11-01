"""
SentinelX — Rate Limiter
Redis-based sliding window rate limiter for per-IP, per-endpoint, and per-user limiting.
"""

import logging
import time
from typing import Any

logger = logging.getLogger(__name__)


class SlidingWindowRateLimiter:
    """
    Sliding window rate limiter using Redis sorted sets.
    Each request is stored as a member with score = timestamp.
    Expired entries are pruned on each check.
    """

    def __init__(self, redis_client: Any):
        self.redis = redis_client

    async def is_rate_limited(
        self,
        identifier: str,
        max_requests: int,
        window_seconds: int,
    ) -> tuple[bool, int]:
        """
        Check if the identifier has exceeded the rate limit.

        Args:
            identifier: Unique key (e.g., IP address, "ip:endpoint", user_id)
            max_requests: Maximum requests allowed in the window
            window_seconds: Time window in seconds

        Returns:
            Tuple of (is_limited, remaining_requests)
        """
        try:
            key = f"sentinelx:rate_limit:{identifier}"
            now = time.time()
            window_start = now - window_seconds

            pipe = self.redis.pipeline()

            # Remove expired entries
            pipe.zremrangebyscore(key, 0, window_start)

            # Count current requests in window
            pipe.zcard(key)

            # Add current request
            pipe.zadd(key, {f"{now}:{id(now)}": now})

            # Set TTL on the key
            pipe.expire(key, window_seconds + 1)

            results = await pipe.execute()
            current_count = results[1]  # zcard result

            remaining = max(0, max_requests - current_count - 1)
            is_limited = current_count >= max_requests

            return is_limited, remaining

        except Exception as e:
            logger.error(f"Rate limiter error: {e}")
            # Fail open — don't block if Redis is down
            return False, max_requests

    async def get_limit_info(self, identifier: str, window_seconds: int) -> dict[str, Any]:
        """Get rate limit information for an identifier."""
        try:
            key = f"sentinelx:rate_limit:{identifier}"
            now = time.time()
            window_start = now - window_seconds

            # Clean and count
            await self.redis.zremrangebyscore(key, 0, window_start)
            count = await self.redis.zcard(key)

            # Get TTL
            ttl = await self.redis.ttl(key)

            return {
                "current_requests": count,
                "window_seconds": window_seconds,
                "reset_in_seconds": max(0, ttl),
            }
        except Exception as e:
            logger.error(f"Rate limiter info error: {e}")
            return {
                "current_requests": 0,
                "window_seconds": window_seconds,
                "reset_in_seconds": window_seconds,
            }

    async def reset(self, identifier: str) -> None:
        """Reset rate limit for an identifier."""
        try:
            key = f"sentinelx:rate_limit:{identifier}"
            await self.redis.delete(key)
        except Exception as e:
            logger.error(f"Rate limiter reset error: {e}")
