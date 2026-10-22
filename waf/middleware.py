"""
SentinelX — WAF ASGI Middleware
Intercepts all incoming HTTP requests for threat detection.
Non-blocking, async implementation with zero-copy request inspection.
"""

import json
import logging
import time
import uuid
from typing import Any
from urllib.parse import unquote

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from api.core.config import get_settings

logger = logging.getLogger(__name__)
settings = get_settings()

# Paths that bypass WAF inspection
WAF_BYPASS_PATHS = {
    "/api/v1/health",
    "/docs",
    "/redoc",
    "/openapi.json",
    "/favicon.ico",
}


class WAFMiddleware(BaseHTTPMiddleware):
    """
    Web Application Firewall middleware.
    Inspects all incoming requests and blocks malicious traffic.

    Flow:
    1. Check IP whitelist → bypass if whitelisted
    2. Check IP blacklist → block if blacklisted
    3. Check rate limit → block if exceeded
    4. Check GeoIP → block if country is blocked
    5. Run WAF rule engine → block/log if matched
    6. Dispatch async Celery task for AI analysis (on match)
    """

    async def dispatch(self, request: Request, call_next):
        # Skip WAF for bypass paths
        if request.url.path in WAF_BYPASS_PATHS:
            return await call_next(request)

        # Skip if WAF is disabled
        if not settings.waf_enabled:
            return await call_next(request)

        start_time = time.time()
        client_ip = self._get_client_ip(request)
        request_id = str(uuid.uuid4())[:8]

        try:
            # Get Redis client (lazy import to avoid circular deps)
            from api.core.redis import get_redis
            redis = await get_redis()

            # ── Step 1: Whitelist Check ──
            from waf.ip_manager import IPManager
            ip_manager = IPManager(redis)

            if await ip_manager.is_whitelisted(client_ip):
                return await call_next(request)

            # ── Step 2: Blacklist Check ──
            if await ip_manager.is_blacklisted(client_ip):
                logger.warning(f"[WAF:{request_id}] Blocked blacklisted IP: {client_ip}")
                return self._block_response(
                    "Access denied. Your IP has been blocked.",
                    status_code=403,
                    request_id=request_id,
                )

            # ── Step 3: Rate Limiting ──
            from waf.rate_limiter import SlidingWindowRateLimiter
            rate_limiter = SlidingWindowRateLimiter(redis)

            is_limited, remaining = await rate_limiter.is_rate_limited(
                identifier=client_ip,
                max_requests=settings.rate_limit_requests,
                window_seconds=settings.rate_limit_window_seconds,
            )

            if is_limited:
                logger.warning(f"[WAF:{request_id}] Rate limited: {client_ip}")
                await self._log_waf_event(
                    request=request,
                    client_ip=client_ip,
                    threat_type="rate_limit",
                    severity="medium",
                    action="blocked",
                    matched_rule_id="RATE-LIMIT",
                )
                return self._block_response(
                    "Rate limit exceeded. Please try again later.",
                    status_code=429,
                    request_id=request_id,
                    headers={"X-RateLimit-Remaining": "0"},
                )

            # ── Step 4: GeoIP Check ──
            country_code = await ip_manager.get_country_code(client_ip)
            if await ip_manager.is_country_blocked(country_code):
                logger.warning(
                    f"[WAF:{request_id}] Blocked by GeoIP: {client_ip} ({country_code})"
                )
                return self._block_response(
                    "Access denied from your region.",
                    status_code=403,
                    request_id=request_id,
                )

            # ── Step 5: WAF Rule Engine ──
            request_data = await self._extract_request_data(request)

            from waf.engine import get_rule_engine
            engine = get_rule_engine()
            match = engine.evaluate(request_data)

            if match and match.matched:
                is_blocking = settings.waf_mode == "block" and match.action in ("block", "blocked")
                action = "blocked" if is_blocking else "logged"

                logger.warning(
                    f"[WAF:{request_id}] {action.upper()}: "
                    f"Rule {match.rule_id} ({match.category}) "
                    f"from {client_ip} — {match.matched_value[:80]}"
                )

                # Log the WAF event
                waf_log_id = await self._log_waf_event(
                    request=request,
                    client_ip=client_ip,
                    threat_type=match.category,
                    severity=match.severity,
                    action=action,
                    matched_rule_id=match.rule_id,
                    country_code=country_code,
                )

                # Increment threat count for auto-blocking
                await ip_manager.increment_threat_count(client_ip)
                await ip_manager.auto_block_if_threshold(client_ip, threshold=10)

                # Dispatch async AI analysis (never blocks the request path)
                self._dispatch_ai_analysis(waf_log_id, match, request_data)

                if action == "blocked":
                    return self._block_response(
                        f"Request blocked by WAF. Malicious payload detected by rule {match.rule_id}.",
                        status_code=403,
                        request_id=request_id,
                    )

            # ── Pass through ──
            response = await call_next(request)

            # Add security headers
            elapsed_ms = (time.time() - start_time) * 1000
            response.headers["X-Request-ID"] = request_id
            response.headers["X-RateLimit-Remaining"] = str(remaining)
            response.headers["X-WAF-Status"] = "pass"
            response.headers["X-Response-Time"] = f"{elapsed_ms:.1f}ms"

            return response

        except Exception as e:
            # WAF should never crash the application — fail open
            logger.error(f"[WAF:{request_id}] Middleware error: {e}")
            return await call_next(request)

    def _get_client_ip(self, request: Request) -> str:
        """Extract the real client IP, respecting reverse proxy headers."""
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
        real_ip = request.headers.get("x-real-ip")
        if real_ip:
            return real_ip.strip()
        return request.client.host if request.client else "0.0.0.0"

    async def _extract_request_data(self, request: Request) -> dict[str, str]:
        """Extract inspectable data from the request for rule evaluation."""
        data = {
            "path": unquote(str(request.url.path)),
            "query_params": unquote(str(request.url.query)),
            "headers": " ".join(
                f"{k}:{v}" for k, v in request.headers.items()
                if k.lower() not in ("authorization", "cookie")
            ),
            "user_agent": request.headers.get("user-agent", ""),
        }

        # Read body if present (for POST/PUT/PATCH)
        if request.method in ("POST", "PUT", "PATCH"):
            try:
                body_bytes = await request.body()
                body_text = body_bytes.decode("utf-8", errors="ignore")[:10000]
                data["body"] = body_text
            except Exception:
                data["body"] = ""
        else:
            data["body"] = ""

        return data

    def _block_response(
        self,
        message: str,
        status_code: int = 403,
        request_id: str = "",
        headers: dict[str, str] | None = None,
    ) -> JSONResponse:
        """Create a standardized WAF block response."""
        response = JSONResponse(
            status_code=status_code,
            content={
                "error": "WAF Block",
                "detail": message,
                "request_id": request_id,
                "documentation": "https://github.com/sentinelx/sentinelx",
            },
        )
        response.headers["X-WAF-Status"] = "blocked"
        if headers:
            for key, value in headers.items():
                response.headers[key] = value
        return response

    async def _log_waf_event(
        self,
        request: Request,
        client_ip: str,
        threat_type: str,
        severity: str,
        action: str,
        matched_rule_id: str,
        country_code: str | None = None,
    ) -> str | None:
        """Log a WAF event to the database and Elasticsearch."""
        try:
            from api.core.database import async_session_factory
            from api.models.waf_log import WAFLog

            waf_log = WAFLog(
                source_ip=client_ip,
                country_code=country_code,
                request_method=request.method,
                request_path=str(request.url.path)[:2048],
                query_string=str(request.url.query)[:2048] if request.url.query else None,
                matched_rule_id=matched_rule_id,
                threat_type=threat_type,
                severity=severity,
                action_taken=action,
                raw_headers=dict(request.headers),
                user_agent=request.headers.get("user-agent", "")[:512],
            )

            async with async_session_factory() as session:
                session.add(waf_log)
                await session.commit()
                log_id = str(waf_log.id)

            # Also log to Elasticsearch (async, non-blocking)
            try:
                from api.core.elasticsearch import index_waf_log
                await index_waf_log({
                    "source_ip": client_ip,
                    "country_code": country_code,
                    "request_method": request.method,
                    "request_path": str(request.url.path),
                    "matched_rule_id": matched_rule_id,
                    "threat_type": threat_type,
                    "severity": severity,
                    "action_taken": action,
                    "user_agent": request.headers.get("user-agent", ""),
                })
            except Exception:
                pass  # ES logging is best-effort

            return log_id

        except Exception as e:
            logger.error(f"Failed to log WAF event: {e}")
            return None

    def _dispatch_ai_analysis(
        self, waf_log_id: str | None, match: Any, request_data: dict[str, str]
    ) -> None:
        """Dispatch an async Celery task for AI threat analysis. Never blocks."""
        if waf_log_id is None:
            return

        try:
            from api.workers.ai_analysis import analyze_threat
            analyze_threat.delay(
                waf_log_id=waf_log_id,
                threat_type=match.category,
                severity=match.severity,
                rule_id=match.rule_id,
                matched_value=match.matched_value,
                request_path=request_data.get("path", ""),
                request_body=request_data.get("body", "")[:2000],
            )
        except Exception as e:
            # Celery may not be running — this is fine
            logger.debug(f"Could not dispatch AI analysis task: {e}")
