# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability within SentinelX, please report it responsibly.

### How to Report

1. **Email**: security@sentinelx.io
2. **Subject**: `[SECURITY] Brief description of the vulnerability`
3. **Include**:
   - Description of the vulnerability
   - Steps to reproduce
   - Impact assessment
   - Suggested fix (if any)

### Response Timeline

| Stage | Timeline |
|-------|----------|
| Acknowledgment | Within 24 hours |
| Initial Assessment | Within 72 hours |
| Fix Development | Within 14 days |
| Public Disclosure | After fix is released |

### What to Expect

- We will acknowledge your report within 24 hours
- We will keep you informed of the progress
- We will credit you in the security advisory (unless you prefer anonymity)
- We will NOT take legal action against good-faith security researchers

### Scope

The following are in scope:
- SentinelX API (FastAPI backend)
- WAF Engine and detection rules
- SOC Dashboard (React frontend)
- SecureLens browser extension
- Docker and deployment configurations
- Authentication and authorization mechanisms

The following are **out of scope**:
- Third-party dependencies (report to upstream)
- Social engineering attacks
- DDoS attacks against production instances
- Issues in development/testing environments

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.x     | ✅ Active |
| < 1.0   | ❌ Not supported |

## Security Best Practices

When deploying SentinelX:

1. **Always use HTTPS** in production
2. **Change default credentials** in `.env`
3. **Rotate JWT secrets** regularly
4. **Enable WAF in block mode** for production
5. **Keep dependencies updated** via `dependabot`
6. **Use the CI/CD pipeline** for automated security scanning
7. **Restrict API access** with proper CORS and rate limiting
