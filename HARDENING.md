# 🔒 SentinelX Production Security Hardening Guide

This document outlines mandatory configurations and operational hardening procedures for deploying the **SentinelX Web Security Platform** in production environments.

---

## 1. Network & TLS Gateway Hardening

### 1.1 Mandatory TLS 1.3 Enforcement
Never expose the Python ASGI server directly to the public internet. Terminate TLS at the reverse proxy (Nginx, Caddy, or Cloudflare).

```nginx
# Minimum TLS configuration (in deploy/nginx.conf)
ssl_protocols TLSv1.2 TLSv1.3;
ssl_prefer_server_ciphers on;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
ssl_session_cache shared:SSL:10m;
ssl_session_timeout 1d;
ssl_session_tickets off;
```

### 1.2 HTTP Security Headers
Ensure the following response headers are returned on all endpoints:

```http
Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
X-Content-Type-Options: nosniff
X-Frame-Options: SAMEORIGIN
Referrer-Policy: strict-origin-when-cross-origin
Permissions-Policy: camera=(), microphone=(), geolocation=()
Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; connect-src 'self' wss:;
```

---

## 2. API & Authentication Hardening

### 2.1 JWT Secret & Cryptographic Hygiene
- Generate strong cryptographic secrets (minimum 256-bit entropy):
  ```bash
  python -c "import secrets; print(secrets.token_urlsafe(64))"
  ```
- Configure short access token lifetimes (15–30 minutes) and use refresh token rotation.
- Store secrets strictly in environment variables or external vaults (AWS Secrets Manager, HashiCorp Vault), never in code or source control.

### 2.2 Rate Limiting Tiers
SentinelX enforces multi-tier sliding-window rate limiting:

| Target Endpoint | Recommended Limit | Window | Action on Breach |
| :--- | :---: | :---: | :--- |
| `/api/v1/auth/login` | 5 requests | 60 seconds | 429 Too Many Requests |
| `/api/v1/auth/register` | 3 requests | 300 seconds | 429 Too Many Requests |
| Global API (`/api/v1/*`) | 120 requests | 60 seconds | 429 + Temporary IP Score penalty |
| Public Static Assets | 300 requests | 60 seconds | Pass |

---

## 3. WAF Engine & Rule Tuning

### 3.1 Mode of Operation
- **Staging / Initial Deployment**: Set `WAF_MODE=log` to monitor false positives and profile typical client application traffic.
- **Production**: Set `WAF_MODE=block` to reject identified threats with immediate HTTP 403 status codes.

### 3.2 Request Inspection Thresholds
- **Body Buffer Limit**: Default maximum inspected request payload size is 10 KB (`10,240 bytes`). Large file uploads (`multipart/form-data`) should be routed to dedicated presigned S3/GCS URLs rather than parsed in memory.
- **Auto-Block Threshold**: By default, an IP accumulating 10 flagged threat events within 24 hours is automatically added to the global blacklist.

---

## 4. Container & Operating System Hardening

1. **Non-Root Execution**: Run all containerized processes (`api`, `celery`, `dashboard`) under dedicated non-root service accounts (`UID 10001`).
2. **Minimal Base Images**: Use `python:3.13-slim` or `alpine` to minimize installed system libraries and CVE surface area.
3. **Database Credentials**: Never use default credentials (`sentinelx-secret`). Change all passwords in `.env` before booting production containers.
