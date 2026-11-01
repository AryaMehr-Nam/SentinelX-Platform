"""
SentinelX — Threat Intelligence Celery Tasks
Async tasks for fetching domain/IP intelligence from external services.
Integrates with VirusTotal, AbuseIPDB, and OpenPhish (mock or real).
"""

import logging
import uuid
from datetime import UTC, datetime

import httpx

from api.core.config import get_settings
from api.workers.celery_app import celery_app

logger = logging.getLogger(__name__)
settings = get_settings()


@celery_app.task(bind=True, max_retries=3, default_retry_delay=60)
def analyze_domain(self, domain_id: str, domain: str):
    """
    Fetch threat intelligence for a reported domain.
    Queries VirusTotal, AbuseIPDB, and OpenPhish feeds.
    """
    logger.info(f"[ThreatIntel] Analyzing domain: {domain}")

    results = {
        "virustotal": None,
        "abuseipdb": None,
        "openphish": None,
        "analyzed_at": datetime.now(UTC).isoformat(),
    }

    # ──── VirusTotal Lookup ────
    try:
        results["virustotal"] = _query_virustotal(domain)
    except Exception as e:
        logger.error(f"[ThreatIntel] VirusTotal error for {domain}: {e}")

    # ──── AbuseIPDB Lookup ────
    try:
        results["abuseipdb"] = _query_abuseipdb(domain)
    except Exception as e:
        logger.error(f"[ThreatIntel] AbuseIPDB error for {domain}: {e}")

    # ──── OpenPhish Feed Check ────
    try:
        results["openphish"] = _check_openphish(domain)
    except Exception as e:
        logger.error(f"[ThreatIntel] OpenPhish error for {domain}: {e}")

    # Calculate aggregate risk score
    risk_score = _calculate_risk_score(results)
    results["aggregate_risk_score"] = risk_score

    # Update the database record
    _update_domain_record(domain_id, results, risk_score)

    logger.info(f"[ThreatIntel] Domain analysis complete: {domain} — Risk Score: {risk_score}")
    return results


def _query_virustotal(domain: str) -> dict:
    """Query VirusTotal API for domain reputation."""
    api_key = settings.virustotal_api_key
    if not api_key:
        # Return mock data when no API key is configured
        return {
            "source": "virustotal",
            "mode": "mock",
            "positives": 3,
            "total_scanners": 70,
            "categories": ["phishing", "malware"],
            "reputation_score": -15,
            "last_analysis_date": datetime.now(UTC).isoformat(),
            "community_votes": {"harmless": 2, "malicious": 8},
        }

    with httpx.Client(timeout=30) as client:
        response = client.get(
            f"https://www.virustotal.com/api/v3/domains/{domain}",
            headers={"x-apikey": api_key},
        )
        if response.status_code == 200:
            data = response.json()
            attrs = data.get("data", {}).get("attributes", {})
            last_analysis = attrs.get("last_analysis_stats", {})
            return {
                "source": "virustotal",
                "mode": "live",
                "positives": last_analysis.get("malicious", 0),
                "total_scanners": sum(last_analysis.values()),
                "categories": list(attrs.get("categories", {}).values()),
                "reputation_score": attrs.get("reputation", 0),
                "last_analysis_date": attrs.get("last_analysis_date"),
            }
        else:
            return {
                "source": "virustotal",
                "mode": "live",
                "error": f"HTTP {response.status_code}",
            }


def _query_abuseipdb(ip_or_domain: str) -> dict:
    """Query AbuseIPDB API for IP/domain reputation."""
    api_key = settings.abuseipdb_api_key
    if not api_key:
        return {
            "source": "abuseipdb",
            "mode": "mock",
            "abuse_confidence_score": 45,
            "total_reports": 12,
            "country_code": "US",
            "isp": "Example ISP",
            "domain": ip_or_domain,
            "is_tor": False,
            "is_public": True,
            "categories": [18, 14, 22],  # AbuseIPDB category codes
        }

    with httpx.Client(timeout=30) as client:
        response = client.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={
                "Key": api_key,
                "Accept": "application/json",
            },
            params={
                "ipAddress": ip_or_domain,
                "maxAgeInDays": 90,
            },
        )
        if response.status_code == 200:
            data = response.json().get("data", {})
            return {
                "source": "abuseipdb",
                "mode": "live",
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "country_code": data.get("countryCode"),
                "isp": data.get("isp"),
                "is_tor": data.get("isTor", False),
                "is_public": data.get("isPublic", True),
            }
        else:
            return {
                "source": "abuseipdb",
                "mode": "live",
                "error": f"HTTP {response.status_code}",
            }


def _check_openphish(domain: str) -> dict:
    """Check domain against OpenPhish feed (mock implementation)."""
    # In production, download and parse the OpenPhish feed
    # https://openphish.com/feed.txt
    known_phishing = [
        "evil-login.com",
        "fake-bank-secure.com",
        "paypal-verify.xyz",
        "microsoft-update.tk",
    ]

    is_phishing = domain.lower() in known_phishing

    return {
        "source": "openphish",
        "mode": "mock",
        "is_phishing": is_phishing,
        "feed_size": len(known_phishing),
        "checked_at": datetime.now(UTC).isoformat(),
    }


def _calculate_risk_score(results: dict) -> float:
    """Calculate aggregate risk score from all intel sources."""
    score = 0.0
    weights = 0

    # VirusTotal score
    vt = results.get("virustotal")
    if vt and "positives" in vt:
        total = max(vt.get("total_scanners", 70), 1)
        vt_score = (vt["positives"] / total) * 100
        score += vt_score * 0.4
        weights += 0.4

    # AbuseIPDB score
    aipdb = results.get("abuseipdb")
    if aipdb and "abuse_confidence_score" in aipdb:
        score += aipdb["abuse_confidence_score"] * 0.35
        weights += 0.35

    # OpenPhish score
    op = results.get("openphish")
    if op and op.get("is_phishing"):
        score += 100 * 0.25
        weights += 0.25
    elif op:
        weights += 0.25

    if weights > 0:
        return round(min(100.0, score / weights * (weights + 0.1)), 1)

    return 0.0


def _update_domain_record(domain_id: str, results: dict, risk_score: float):
    """Update the phishing domain record in the database."""
    try:
        from sqlalchemy.orm import Session

        from api.core.database import build_sync_engine
        from api.models.phishing_domain import PhishingDomain

        engine = build_sync_engine()

        with Session(engine) as session:
            domain = session.get(PhishingDomain, uuid.UUID(domain_id))
            if domain:
                domain.threat_intel_data = results
                domain.risk_score = risk_score
                if risk_score >= 70:
                    domain.status = "confirmed"
                session.commit()
            logger.info(f"Updated domain record {domain_id} with risk score {risk_score}")
    except Exception as e:
        logger.error(f"Failed to update domain record: {e}")


# ──── Periodic Tasks ────


@celery_app.task
def cleanup_expired_blocks():
    """Remove expired IP blocks from the database."""
    logger.info("[Maintenance] Cleaning up expired IP blocks")
    try:
        from sqlalchemy import delete
        from sqlalchemy.orm import Session

        from api.core.database import build_sync_engine
        from api.models.blocked_ip import BlockedIP

        engine = build_sync_engine()

        with Session(engine) as session:
            result = session.execute(
                delete(BlockedIP).where(
                    BlockedIP.is_permanent == False,
                    BlockedIP.blocked_until < datetime.now(UTC),
                )
            )
            session.commit()
            logger.info(f"[Maintenance] Removed {result.rowcount} expired IP blocks")
    except Exception as e:
        logger.error(f"[Maintenance] Cleanup error: {e}")


@celery_app.task
def refresh_threat_feeds():
    """Refresh external threat intelligence feeds."""
    logger.info("[ThreatIntel] Refreshing threat intelligence feeds")
    # In production, this would:
    # 1. Download OpenPhish feed
    # 2. Update local threat database
    # 3. Sync with VirusTotal
    # 4. Update IP reputation caches
    logger.info("[ThreatIntel] Feed refresh complete")
