# 🛡️ SentinelX Threat Model (STRIDE Methodology)

This document establishes the formal threat model for the **SentinelX Web Security Platform**, evaluating all attack surfaces across the WAF engine, API gateway, real-time streaming pipeline, and browser extension.

---

## 1. System Architecture & Trust Boundaries

```
[ External Client / Attacker ]
            │ (Untrusted Boundary)
            ▼
┌──────────────────────────────────────────────┐
│ SentinelX WAF ASGI Middleware                │
│ (Zero-Copy Regex, Heuristics, Rate Limiting) │
└──────────────────────┬───────────────────────┘
                       │ (Sanitized & Inspected)
                       ▼
┌──────────────────────────────────────────────┐
│ SentinelX FastAPI Core & JWT Auth            │
│ (RBAC: Admin, Analyst, Viewer)               │
└───────────────┬──────────────────────────────┘
                │
        ┌───────┴───────────────┐
        ▼                       ▼
┌────────────────┐      ┌────────────────────────┐
│ PostgreSQL /   │      │ Redis / InMemory       │
│ SQLite ACID    │      │ Sliding Window Limiter │
└────────────────┘      └────────────────────────┘
```

---

## 2. STRIDE Analysis by Component

### 2.1 Web Application Firewall (WAF Engine)

| Threat Category | Threat Description | Severity | Mitigation in SentinelX | Status |
| :--- | :--- | :---: | :--- | :---: |
| **Spoofing** | Attacker spoofs `X-Forwarded-For` header to bypass IP blacklist. | High | WAF extracts first untrusted proxy IP or falls back to socket IP unless behind trusted reverse proxy. | ✅ Mitigated |
| **Tampering** | Attacker bypasses regex patterns using double-encoding or null-byte injection. | High | WAF pre-decodes URL query parameters and paths using `unquote()` before rule evaluation. | ✅ Mitigated |
| **Repudiation** | Attacker causes attacks without event trails. | Medium | All blocked and flagged attacks generate structured immutable audit records in `waf_logs`. | ✅ Mitigated |
| **Information Disclosure** | WAF error responses leak stack traces or internal server paths. | Medium | Standardized, sanitized JSON block responses with generic security reference IDs. | ✅ Mitigated |
| **Denial of Service** | ReDoS (Regular Expression Denial of Service) via complex payload. | High | Rules pre-compiled at startup with bounded execution and strict length limits on body inspection (10KB cap). | ✅ Mitigated |
| **Elevation of Privilege** | Attacker bypasses WAF inspection via bypass routes. | Critical | Strict bypass set limited solely to `/health` and OpenAPI docs in development. | ✅ Mitigated |

---

### 2.2 API & Authentication Service

| Threat Category | Threat Description | Severity | Mitigation in SentinelX | Status |
| :--- | :--- | :---: | :--- | :---: |
| **Spoofing** | Forged JWT access tokens. | Critical | HS256 / RS256 signature verification with secret keys and strict expiry validation. | ✅ Mitigated |
| **Tampering** | Modification of role claims in JWT payload. | Critical | Cryptographically signed token claims; role checked on every protected route via `require_role()`. | ✅ Mitigated |
| **Repudiation** | Administrative actions performed anonymously. | High | `AuditLog` records user ID, action, target resource, timestamp, and client IP. | ✅ Mitigated |
| **Information Disclosure** | Password hash leakage or database dumps. | High | Passwords hashed with bcrypt (salt cost 12); sensitive columns excluded from Pydantic response schemas. | ✅ Mitigated |
| **Denial of Service** | Credential stuffing on `/api/v1/auth/login`. | High | Dedicated per-IP and per-user sliding window rate limiting (5 req/min burst). | ✅ Mitigated |
| **Elevation of Privilege** | Viewer role accessing Admin user management endpoints. | Critical | Hierarchical RBAC (`UserRole.ADMIN > ANALYST > VIEWER`) enforced at router level. | ✅ Mitigated |

---

### 2.3 Browser Extension (SecureLens)

| Threat Category | Threat Description | Severity | Mitigation in SentinelX | Status |
| :--- | :--- | :---: | :--- | :---: |
| **Spoofing** | Malicious site mimicking extension messaging. | Medium | Manifest V3 isolated world content script communication via `chrome.runtime.sendMessage`. | ✅ Mitigated |
| **Tampering** | Host page tampering with extension DOM or findings. | Low | Extension UI renders in an isolated extension context popup (`popup.html`). | ✅ Mitigated |
| **Information Disclosure** | Extension leaking user browsing history to third parties. | High | Host permissions scoped; analysis performed locally in client service worker without transmitting full browsing history. | ✅ Mitigated |

---

## 3. Residual Risks & Future Roadmap

1. **Distributed DDoS L7**: While SentinelX provides per-node sliding-window rate limiting, volumetric network-level DDoS requires upstream CDN filtering (e.g. Cloudflare Magic Transit / AWS Shield).
2. **Machine Learning False Positives**: Heuristic confidence scores should be periodically tuned with live traffic datasets to ensure minimal disruption to production APIs.
