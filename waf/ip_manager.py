"""
SentinelX — IP Manager
Manages IP blacklists, whitelists, and GeoIP-based blocking using Redis.
"""

import logging
from typing import Any

logger = logging.getLogger(__name__)

# Country codes to block by default (configurable)
DEFAULT_BLOCKED_COUNTRIES: set[str] = set()

# Known malicious IP ranges (CIDR — stub for demonstration)
KNOWN_MALICIOUS_RANGES: list[str] = []


class IPManager:
    """Manages real-time IP blacklists, whitelists, and reputation scoring."""

    BLACKLIST_KEY = "sentinelx:ip:blacklist"
    WHITELIST_KEY = "sentinelx:ip:whitelist"
    REPUTATION_PREFIX = "sentinelx:ip:reputation:"
    BLOCKED_COUNTRIES_KEY = "sentinelx:geo:blocked_countries"

    def __init__(self, redis_client: Any):
        self.redis = redis_client

    # ──── Blacklist Operations ────

    async def is_blacklisted(self, ip: str) -> bool:
        """Check if an IP is in the blacklist."""
        try:
            return await self.redis.sismember(self.BLACKLIST_KEY, ip)
        except Exception as e:
            logger.error(f"Blacklist check error: {e}")
            return False

    async def add_to_blacklist(self, ip: str, reason: str = "", ttl: int | None = None) -> None:
        """Add an IP to the blacklist."""
        try:
            await self.redis.sadd(self.BLACKLIST_KEY, ip)
            if reason:
                await self.redis.set(f"{self.REPUTATION_PREFIX}{ip}:reason", reason, ex=ttl)
            logger.info(f"IP blacklisted: {ip} — {reason}")
        except Exception as e:
            logger.error(f"Blacklist add error: {e}")

    async def remove_from_blacklist(self, ip: str) -> None:
        """Remove an IP from the blacklist."""
        try:
            await self.redis.srem(self.BLACKLIST_KEY, ip)
            await self.redis.delete(f"{self.REPUTATION_PREFIX}{ip}:reason")
            logger.info(f"IP removed from blacklist: {ip}")
        except Exception as e:
            logger.error(f"Blacklist remove error: {e}")

    async def get_blacklist(self) -> set[str]:
        """Get all blacklisted IPs."""
        try:
            return await self.redis.smembers(self.BLACKLIST_KEY)
        except Exception as e:
            logger.error(f"Blacklist fetch error: {e}")
            return set()

    # ──── Whitelist Operations ────

    async def is_whitelisted(self, ip: str) -> bool:
        """Check if an IP is in the whitelist (bypasses all WAF checks)."""
        try:
            return await self.redis.sismember(self.WHITELIST_KEY, ip)
        except Exception as e:
            logger.error(f"Whitelist check error: {e}")
            return False

    async def add_to_whitelist(self, ip: str) -> None:
        """Add an IP to the whitelist."""
        try:
            await self.redis.sadd(self.WHITELIST_KEY, ip)
            logger.info(f"IP whitelisted: {ip}")
        except Exception as e:
            logger.error(f"Whitelist add error: {e}")

    async def remove_from_whitelist(self, ip: str) -> None:
        """Remove an IP from the whitelist."""
        try:
            await self.redis.srem(self.WHITELIST_KEY, ip)
        except Exception as e:
            logger.error(f"Whitelist remove error: {e}")

    # ──── Reputation Scoring ────

    async def increment_threat_count(self, ip: str, ttl: int = 86400) -> int:
        """Increment the threat count for an IP. Returns new count."""
        try:
            key = f"{self.REPUTATION_PREFIX}{ip}:threats"
            count = await self.redis.incr(key)
            await self.redis.expire(key, ttl)
            return count
        except Exception as e:
            logger.error(f"Threat count error: {e}")
            return 0

    async def get_threat_count(self, ip: str) -> int:
        """Get the current threat count for an IP."""
        try:
            key = f"{self.REPUTATION_PREFIX}{ip}:threats"
            count = await self.redis.get(key)
            return int(count) if count else 0
        except Exception as e:
            logger.error(f"Threat count fetch error: {e}")
            return 0

    async def auto_block_if_threshold(self, ip: str, threshold: int = 10) -> bool:
        """Auto-block an IP if it exceeds the threat threshold."""
        count = await self.get_threat_count(ip)
        if count >= threshold:
            await self.add_to_blacklist(ip, reason=f"Auto-blocked: {count} threats detected")
            return True
        return False

    # ──── GeoIP Blocking (Stub) ────

    async def get_country_code(self, ip: str) -> str | None:
        """
        Get the country code for an IP address.
        In production, this would use MaxMind GeoIP2 database.
        """
        try:
            # Stub: Try to resolve from cached reputation data
            cached = await self.redis.get(f"{self.REPUTATION_PREFIX}{ip}:country")
            if cached:
                return cached

            # In production, use geoip2:
            # import geoip2.database
            # reader = geoip2.database.Reader('GeoLite2-Country.mmdb')
            # response = reader.country(ip)
            # return response.country.iso_code

            return None
        except Exception:
            return None

    async def is_country_blocked(self, country_code: str | None) -> bool:
        """Check if a country code is in the blocked countries list."""
        if not country_code:
            return False
        try:
            return await self.redis.sismember(self.BLOCKED_COUNTRIES_KEY, country_code)
        except Exception:
            return False

    async def block_country(self, country_code: str) -> None:
        """Add a country to the blocked list."""
        try:
            await self.redis.sadd(self.BLOCKED_COUNTRIES_KEY, country_code.upper())
            logger.info(f"Country blocked: {country_code}")
        except Exception as e:
            logger.error(f"Country block error: {e}")

    async def unblock_country(self, country_code: str) -> None:
        """Remove a country from the blocked list."""
        try:
            await self.redis.srem(self.BLOCKED_COUNTRIES_KEY, country_code.upper())
        except Exception as e:
            logger.error(f"Country unblock error: {e}")
