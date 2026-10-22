"""
SentinelX — API & WAF Engine Comprehensive Test Suite
Verifies health, authentication, WAF rule engine, ASGI middleware, rate limiter,
and IP management capabilities.
"""

import pytest
from starlette.testclient import TestClient
from api.main import create_app
from api.core.config import get_settings


@pytest.fixture(scope="module")
def client():
    """Create a test client for the FastAPI application."""
    app = create_app()
    with TestClient(app) as test_client:
        yield test_client


class TestHealthEndpoint:
    """Tests for the system health check endpoint."""

    def test_health_returns_200(self, client):
        """Health endpoint should return 200 with operational status."""
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data.get("status") == "healthy"
        assert data.get("app") == "SentinelX"
        assert "version" in data


class TestWAFEngine:
    """Unit tests for the standalone WAF rule evaluation engine."""

    def test_sqli_detection(self):
        """WAF should detect SQL injection patterns."""
        from waf.engine import RuleEngine

        engine = RuleEngine()
        engine.load_rules_from_directory()

        result = engine.evaluate({
            "query_params": "id=1 UNION SELECT * FROM users",
            "body": "",
            "path": "/api/test",
            "headers": "",
        })
        assert result is not None
        assert result.matched is True
        assert result.category == "sqli"

    def test_xss_detection(self):
        """WAF should detect XSS patterns."""
        from waf.engine import RuleEngine

        engine = RuleEngine()
        engine.load_rules_from_directory()

        result = engine.evaluate({
            "query_params": "name=<script>alert(1)</script>",
            "body": "",
            "path": "/api/test",
            "headers": "",
        })
        assert result is not None
        assert result.matched is True
        assert result.category == "xss"

    def test_path_traversal_detection(self):
        """WAF should detect path traversal patterns."""
        from waf.engine import RuleEngine

        engine = RuleEngine()
        engine.load_rules_from_directory()

        result = engine.evaluate({
            "query_params": "",
            "body": "",
            "path": "/api/../../etc/passwd",
            "headers": "",
        })
        assert result is not None
        assert result.matched is True
        assert result.category == "path_traversal"

    def test_command_injection_detection(self):
        """WAF should detect command injection patterns."""
        from waf.engine import RuleEngine

        engine = RuleEngine()
        engine.load_rules_from_directory()

        result = engine.evaluate({
            "query_params": "",
            "body": "hostname; cat /etc/passwd",
            "path": "/api/test",
            "headers": "",
        })
        assert result is not None
        assert result.matched is True
        assert result.category == "cmd_injection"

    def test_clean_request_passes(self):
        """WAF should not flag clean requests."""
        from waf.engine import RuleEngine

        engine = RuleEngine()
        engine.load_rules_from_directory()

        result = engine.evaluate({
            "query_params": "search=hello+world&page=1",
            "body": '{"username": "john", "email": "john@example.com"}',
            "path": "/api/users",
            "headers": "content-type:application/json",
        })
        assert result is None

    def test_rule_loading(self):
        """Engine should load rules from YAML files."""
        from waf.engine import RuleEngine

        engine = RuleEngine()
        count = engine.load_rules_from_directory()
        assert count > 0
        assert engine.rule_count > 0
        assert len(engine.categories) > 0


class TestWAFMiddlewareIntegration:
    """End-to-end tests for WAF ASGI middleware interception."""

    def test_health_bypasses_waf(self, client):
        """Health endpoint should bypass WAF rule blocking."""
        response = client.get("/api/v1/health?q=1%20UNION%20SELECT%20*%20FROM%20users")
        assert response.status_code == 200

    def test_sqli_blocked_live(self, client):
        """Middleware should block SQLi with HTTP 403 and X-WAF-Status: blocked."""
        response = client.get("/api/v1/users?id=1%20UNION%20SELECT%20*%20FROM%20users")
        assert response.status_code == 403
        assert response.headers.get("x-waf-status") == "blocked"
        data = response.json()
        assert data.get("error") == "WAF Block"
        assert "SQLI" in data.get("detail", "")

    def test_xss_blocked_live(self, client):
        """Middleware should block XSS with HTTP 403."""
        response = client.get("/api/v1/users?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E")
        assert response.status_code == 403
        assert response.headers.get("x-waf-status") == "blocked"

    def test_path_traversal_blocked_live(self, client):
        """Middleware should block path traversal attempts."""
        response = client.get("/api/v1/users?file=../../../../etc/passwd")
        assert response.status_code == 403
        assert response.headers.get("x-waf-status") == "blocked"

    def test_command_injection_blocked_live(self, client):
        """Middleware should block command injection attempts."""
        response = client.get("/api/v1/users?cmd=cat%20/etc/passwd;%20whoami")
        assert response.status_code == 403
        assert response.headers.get("x-waf-status") == "blocked"


class TestRateLimiterAndIPManager:
    """Unit tests for sliding window rate limiter and IP manager."""

    @pytest.mark.asyncio
    async def test_sliding_window_rate_limiter(self):
        """Rate limiter should track requests and enforce limit."""
        from api.core.redis import InMemoryRedisFallback
        from waf.rate_limiter import SlidingWindowRateLimiter

        redis = InMemoryRedisFallback()
        limiter = SlidingWindowRateLimiter(redis)

        # 3 requests allowed in 10 second window
        is_limited, rem1 = await limiter.is_rate_limited("client-1", max_requests=3, window_seconds=10)
        assert is_limited is False
        assert rem1 == 2

        is_limited, rem2 = await limiter.is_rate_limited("client-1", max_requests=3, window_seconds=10)
        assert is_limited is False
        assert rem2 == 1

        is_limited, rem3 = await limiter.is_rate_limited("client-1", max_requests=3, window_seconds=10)
        assert is_limited is False
        assert rem3 == 0

        # 4th request must be rate-limited
        is_limited, rem4 = await limiter.is_rate_limited("client-1", max_requests=3, window_seconds=10)
        assert is_limited is True
        assert rem4 == 0

    @pytest.mark.asyncio
    async def test_ip_manager_whitelist_blacklist(self):
        """IPManager should correctly track blacklisted and whitelisted IPs."""
        from api.core.redis import InMemoryRedisFallback
        from waf.ip_manager import IPManager

        redis = InMemoryRedisFallback()
        mgr = IPManager(redis)

        assert await mgr.is_blacklisted("198.51.100.1") is False
        await mgr.add_to_blacklist("198.51.100.1")
        assert await mgr.is_blacklisted("198.51.100.1") is True

        assert await mgr.is_whitelisted("198.51.100.2") is False
        await mgr.add_to_whitelist("198.51.100.2")
        assert await mgr.is_whitelisted("198.51.100.2") is True


class TestAuthenticationSecurity:
    """Tests for password hashing, JWT creation, and authentication flows."""

    def test_hash_and_verify(self):
        from api.core.security import hash_password, verify_password

        password = "test-password-123"
        hashed = hash_password(password)

        assert hashed != password
        assert verify_password(password, hashed) is True
        assert verify_password("wrong-password", hashed) is False

    def test_jwt_token_creation(self):
        from api.core.security import create_access_token, decode_token

        token = create_access_token("test-user-id", "admin")
        payload = decode_token(token)

        assert payload["sub"] == "test-user-id"
        assert payload["role"] == "admin"
        assert payload["type"] == "access"

    def test_auth_login_endpoint(self, client):
        """Login endpoint should authenticate valid credentials and reject invalid ones."""
        settings = get_settings()

        # Valid login
        response = client.post("/api/v1/auth/login", json={
            "email": settings.admin_email,
            "password": settings.admin_password,
        })
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data.get("token_type") == "bearer"

        # Invalid login
        bad_response = client.post("/api/v1/auth/login", json={
            "email": settings.admin_email,
            "password": "wrong-password",
        })
        assert bad_response.status_code == 401


class TestProtectedRoutesAndWAFAPI:
    """Tests for protected routes requiring JWT Bearer authentication."""

    def test_protected_routes_require_auth(self, client):
        """Protected endpoints must return 401 when no token is supplied."""
        assert client.get("/api/v1/users/me").status_code == 401
        assert client.get("/api/v1/waf/rules").status_code == 401
        assert client.get("/api/v1/dashboard/overview").status_code == 401

    def test_authenticated_admin_flow(self, client):
        """Admin user can log in and access profile, rules, and overview."""
        settings = get_settings()

        # 1. Login to get token
        login_res = client.post("/api/v1/auth/login", json={
            "email": settings.admin_email,
            "password": settings.admin_password,
        })
        assert login_res.status_code == 200
        token = login_res.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. Access /users/me
        me_res = client.get("/api/v1/users/me", headers=headers)
        assert me_res.status_code == 200
        assert me_res.json()["email"] == settings.admin_email
        assert me_res.json()["role"] == "admin"

        # 3. Access /waf/rules
        rules_res = client.get("/api/v1/waf/rules", headers=headers)
        assert rules_res.status_code == 200
        rules = rules_res.json()
        assert isinstance(rules, list)
        assert len(rules) >= 12
        for r in rules:
            assert "rule_id" in r
            assert "name" in r
            assert "category" in r
            assert "action" in r

        # 4. Access /dashboard/overview
        overview_res = client.get("/api/v1/dashboard/overview", headers=headers)
        assert overview_res.status_code == 200
        overview = overview_res.json()
        assert "total_requests_24h" in overview
        assert "global_risk_score" in overview

