"""
SentinelX — Comprehensive End-to-End System Test
Verifies all live services, authentication flows, API routes, WAF blocking,
and frontend proxy communication on the running local system.
"""

import sys
import time
import httpx

API_BASE = "http://127.0.0.1:8001/api/v1"
DASHBOARD_BASE = "http://localhost:5173"

def run_system_test():
    print("=" * 75)
    print("       SENTINELX LIVE END-TO-END SYSTEM VERIFICATION")
    print("=" * 75)

    passed = 0
    failed = 0

    def check(name: str, condition: bool, details: str = ""):
        nonlocal passed, failed
        if condition:
            passed += 1
            print(f"  [\033[92mPASS\033[0m] {name:<45} {details}")
        else:
            failed += 1
            print(f"  [\033[91mFAIL\033[0m] {name:<45} {details}")

    with httpx.Client(timeout=10.0) as client:
        # ── Test 1: API Health Endpoint ──
        try:
            r = client.get(f"{API_BASE}/health")
            data = r.json()
            check("1. API Health Check", r.status_code == 200 and data.get("status") == "healthy", f"HTTP {r.status_code} ({data.get('app')})")
        except Exception as e:
            check("1. API Health Check", False, str(e))

        # ── Test 2: Admin Authentication (Login) ──
        token = ""
        try:
            r = client.post(f"{API_BASE}/auth/login", json={
                "email": "admin@sentinelx.io",
                "password": "sentinelx-admin",
            })
            data = r.json()
            token = data.get("access_token", "")
            check("2. Admin Auth Login", r.status_code == 200 and bool(token), f"JWT Received (expires: {data.get('expires_in')}s)")
        except Exception as e:
            check("2. Admin Auth Login", False, str(e))

        auth_headers = {"Authorization": f"Bearer {token}"} if token else {}

        # ── Test 3: Protected User Profile (/users/me) ──
        try:
            r = client.get(f"{API_BASE}/users/me", headers=auth_headers)
            data = r.json()
            check("3. Current User Profile (/users/me)", r.status_code == 200 and data.get("role") == "admin", f"{data.get('full_name')} [{data.get('role')}]")
        except Exception as e:
            check("3. Current User Profile (/users/me)", False, str(e))

        # ── Test 4: Protected Users List (/users/) ──
        try:
            r = client.get(f"{API_BASE}/users/", headers=auth_headers)
            data = r.json()
            check("4. User Management List (/users/)", r.status_code == 200 and len(data) >= 1, f"Found {len(data)} registered users")
        except Exception as e:
            check("4. User Management List (/users/)", False, str(e))

        # ── Test 5: Dashboard Overview Stats ──
        try:
            r = client.get(f"{API_BASE}/dashboard/overview", headers=auth_headers)
            data = r.json()
            check("5. Dashboard Overview Stats", r.status_code == 200 and "total_requests_24h" in data, f"Total 24h Requests: {data.get('total_requests_24h')}")
        except Exception as e:
            check("5. Dashboard Overview Stats", False, str(e))

        # ── Test 6: WAF Rules List ──
        try:
            r = client.get(f"{API_BASE}/waf/rules", headers=auth_headers)
            data = r.json()
            check("6. WAF Rules Engine Inventory", r.status_code == 200 and len(data) >= 12, f"Loaded {len(data)} active rules")
        except Exception as e:
            check("6. WAF Rules Engine Inventory", False, str(e))

        # ── Test 7: Blocked IPs Repository ──
        try:
            r = client.get(f"{API_BASE}/waf/blocked-ips", headers=auth_headers)
            check("7. Blocked IPs Repository", r.status_code == 200, f"HTTP {r.status_code}")
        except Exception as e:
            check("7. Blocked IPs Repository", False, str(e))

        # ── Test 8: Attack Simulator Controls ──
        try:
            r_start = client.post(f"{API_BASE}/simulator/start?interval=2.0")
            r_status = client.get(f"{API_BASE}/simulator/status")
            status_data = r_status.json()
            check("8. Attack Simulator Lifecycle", r_start.status_code == 200 and status_data.get("running") is True, f"Running: {status_data.get('running')}")
        except Exception as e:
            check("8. Attack Simulator Lifecycle", False, str(e))

        # ── Test 9: WAF Exploit Block: SQL Injection ──
        try:
            r = client.get(f"{API_BASE}/dashboard/overview?id=1%20UNION%20SELECT%20*%20FROM%20users")
            waf_status = r.headers.get("x-waf-status", "")
            check("9. WAF Live Block: SQL Injection", r.status_code == 403 and waf_status == "blocked", f"HTTP {r.status_code} | X-WAF-Status: {waf_status}")
        except Exception as e:
            check("9. WAF Live Block: SQL Injection", False, str(e))

        # ── Test 10: WAF Exploit Block: Reflected XSS ──
        try:
            r = client.get(f"{API_BASE}/dashboard/overview?q=%3Cscript%3Ealert(1)%3C/script%3E")
            waf_status = r.headers.get("x-waf-status", "")
            check("10. WAF Live Block: Reflected XSS", r.status_code == 403 and waf_status == "blocked", f"HTTP {r.status_code} | X-WAF-Status: {waf_status}")
        except Exception as e:
            check("10. WAF Live Block: Reflected XSS", False, str(e))

        # ── Test 11: WAF Exploit Block: Path Traversal ──
        try:
            r = client.get(f"{API_BASE}/dashboard/overview?file=../../../../etc/passwd")
            waf_status = r.headers.get("x-waf-status", "")
            check("11. WAF Live Block: Path Traversal", r.status_code == 403 and waf_status == "blocked", f"HTTP {r.status_code} | X-WAF-Status: {waf_status}")
        except Exception as e:
            check("11. WAF Live Block: Path Traversal", False, str(e))

        # ── Test 12: WAF Exploit Block: Command Injection ──
        try:
            r = client.get(f"{API_BASE}/dashboard/overview?cmd=cat%20/etc/passwd;%20whoami")
            waf_status = r.headers.get("x-waf-status", "")
            check("12. WAF Live Block: Command Injection", r.status_code == 403 and waf_status == "blocked", f"HTTP {r.status_code} | X-WAF-Status: {waf_status}")
        except Exception as e:
            check("12. WAF Live Block: Command Injection", False, str(e))

        # ── Test 13: Frontend Vite Web Server ──
        try:
            r = client.get(f"{DASHBOARD_BASE}/")
            check("13. Frontend Dashboard Server", r.status_code == 200 and "<div id=\"root\">" in r.text, f"HTTP {r.status_code} (HTML Loaded)")
        except Exception as e:
            check("13. Frontend Dashboard Server", False, str(e))

        # ── Test 14: Frontend Login Page Route ──
        try:
            r = client.get(f"{DASHBOARD_BASE}/login")
            check("14. Frontend Login Route", r.status_code == 200, f"HTTP {r.status_code}")
        except Exception as e:
            check("14. Frontend Login Route", False, str(e))

        # ── Test 15: Frontend -> Backend API Proxy ──
        try:
            r = client.get(f"{DASHBOARD_BASE}/api/v1/health")
            data = r.json()
            check("15. Frontend Reverse Proxy", r.status_code == 200 and data.get("status") == "healthy", f"Vite -> FastAPI (Port 5173 -> 8001)")
        except Exception as e:
            check("15. Frontend Reverse Proxy", False, str(e))

    print("=" * 75)
    print(f"  TOTAL CHECKS: {passed + failed} | PASSED: \033[92m{passed}\033[0m | FAILED: \033[91m{failed}\033[0m")
    print("=" * 75)

    if failed == 0:
        print("  \033[92mALL SYSTEM CHECKS PASSED PERFECTLY!\033[0m\n")
        return 0
    else:
        print(f"  \033[91m{failed} CHECK(S) FAILED.\033[0m\n")
        return 1

if __name__ == "__main__":
    sys.exit(run_system_test())
