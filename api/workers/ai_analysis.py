"""
SentinelX — AI Threat Analysis Celery Task
Connects to an LLM API (OpenAI/Anthropic/Ollama) for structured threat analysis.
This task is ALWAYS executed asynchronously via Celery — never in the HTTP hot path.
"""

import json
import logging
import time
import uuid
from typing import Any

import httpx

from api.core.config import get_settings
from api.workers.celery_app import celery_app

logger = logging.getLogger(__name__)
settings = get_settings()

# ──── Structured Prompt Template ────

THREAT_ANALYSIS_PROMPT = """You are a senior cybersecurity threat analyst. Analyze the following detected WAF attack and provide a structured analysis.

## Detected Attack Details
- **Threat Type**: {threat_type}
- **Severity**: {severity}
- **Matched Rule**: {rule_id}
- **Matched Payload**: {matched_value}
- **Request Path**: {request_path}
- **Request Body (truncated)**: {request_body}

## Required Output Format (JSON)
Respond with ONLY a valid JSON object containing these fields:
{{
    "threat_classification": "One of: Phishing, Malware, Bot Activity, Reconnaissance, Credential Theft, SQL Injection, XSS, Command Injection, Path Traversal, DDoS, Unknown",
    "human_readable_explanation": "A clear, 2-3 sentence explanation of what this attack is doing, written for a security analyst.",
    "estimated_severity": "One of: low, medium, high, critical",
    "estimated_impact": "Description of potential impact if this attack succeeded.",
    "mitigation_strategies": ["List of 3-5 specific, actionable mitigation steps"],
    "confidence_score": 0.0 to 1.0,
    "attack_vector": "Brief description of the attack vector used",
    "ioc_indicators": ["List of Indicators of Compromise found in the payload"]
}}
"""


@celery_app.task(bind=True, max_retries=2, default_retry_delay=30)
def analyze_threat(
    self,
    waf_log_id: str,
    threat_type: str,
    severity: str,
    rule_id: str,
    matched_value: str,
    request_path: str,
    request_body: str = "",
):
    """
    Perform AI-powered threat analysis using LLM.
    Results are stored in the ai_threat_summaries table.
    """
    logger.info(
        f"[AI Analysis] Starting analysis for WAF log {waf_log_id} "
        f"(Rule: {rule_id}, Type: {threat_type})"
    )

    start_time = time.time()

    # Build the prompt
    prompt = THREAT_ANALYSIS_PROMPT.format(
        threat_type=threat_type,
        severity=severity,
        rule_id=rule_id,
        matched_value=matched_value[:500],
        request_path=request_path[:200],
        request_body=request_body[:1000],
    )

    # Call the LLM
    try:
        llm_response = _call_llm(prompt)
        analysis = _parse_llm_response(llm_response)
    except Exception as e:
        logger.error(f"[AI Analysis] LLM call failed: {e}")
        # Use fallback heuristic analysis
        analysis = _fallback_analysis(threat_type, severity, matched_value)
        llm_response = {"fallback": True, "error": str(e)}

    elapsed_ms = (time.time() - start_time) * 1000

    # Store results in database
    _store_analysis(
        waf_log_id=waf_log_id,
        analysis=analysis,
        raw_response=llm_response,
        elapsed_ms=elapsed_ms,
    )

    logger.info(
        f"[AI Analysis] Complete for WAF log {waf_log_id} — "
        f"Classification: {analysis.get('threat_classification')} — "
        f"{elapsed_ms:.0f}ms"
    )

    return analysis


def _call_llm(prompt: str) -> dict[str, Any]:
    """Call the configured LLM provider."""
    provider = settings.llm_provider.lower()

    if provider == "openai":
        return _call_openai(prompt)
    elif provider == "anthropic":
        return _call_anthropic(prompt)
    elif provider == "ollama":
        return _call_ollama(prompt)
    else:
        raise ValueError(f"Unknown LLM provider: {provider}")


def _call_openai(prompt: str) -> dict[str, Any]:
    """Call OpenAI API."""
    api_key = settings.llm_api_key
    if not api_key:
        raise ValueError("OpenAI API key not configured")

    with httpx.Client(timeout=60) as client:
        response = client.post(
            f"{settings.llm_api_base or 'https://api.openai.com'}/v1/chat/completions",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "model": settings.llm_model or "gpt-4o",
                "messages": [
                    {
                        "role": "system",
                        "content": "You are a cybersecurity threat analyst. Always respond with valid JSON only.",
                    },
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.1,
                "max_tokens": 1000,
                "response_format": {"type": "json_object"},
            },
        )
        response.raise_for_status()
        data = response.json()
        content = data["choices"][0]["message"]["content"]
        return json.loads(content)


def _call_anthropic(prompt: str) -> dict[str, Any]:
    """Call Anthropic API."""
    api_key = settings.llm_api_key
    if not api_key:
        raise ValueError("Anthropic API key not configured")

    with httpx.Client(timeout=60) as client:
        response = client.post(
            f"{settings.llm_api_base or 'https://api.anthropic.com'}/v1/messages",
            headers={
                "x-api-key": api_key,
                "Content-Type": "application/json",
                "anthropic-version": "2023-06-01",
            },
            json={
                "model": settings.llm_model or "claude-sonnet-4-20250514",
                "max_tokens": 1000,
                "system": "You are a cybersecurity threat analyst. Always respond with valid JSON only.",
                "messages": [
                    {"role": "user", "content": prompt},
                ],
            },
        )
        response.raise_for_status()
        data = response.json()
        content = data["content"][0]["text"]
        return json.loads(content)


def _call_ollama(prompt: str) -> dict[str, Any]:
    """Call Ollama local API."""
    base_url = settings.llm_api_base or "http://localhost:11434"

    with httpx.Client(timeout=120) as client:
        try:
            response = client.post(
                f"{base_url}/api/generate",
                json={
                    "model": settings.llm_model or "llama3",
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                    "options": {
                        "temperature": 0.1,
                        "num_predict": 1000,
                    },
                },
            )
            response.raise_for_status()
            data = response.json()
            return json.loads(data.get("response", "{}"))
        except (httpx.ConnectError, httpx.ConnectTimeout):
            logger.warning("[AI Analysis] Ollama not available, using fallback")
            raise


def _parse_llm_response(response: dict[str, Any]) -> dict[str, Any]:
    """Parse and validate the LLM response, ensuring all required fields."""
    required_fields = {
        "threat_classification": "Unknown",
        "human_readable_explanation": "Analysis not available.",
        "estimated_severity": "medium",
        "estimated_impact": "Unknown impact.",
        "mitigation_strategies": [],
    }

    result = {}
    for field, default in required_fields.items():
        result[field] = response.get(field, default)

    # Normalize severity
    valid_severities = {"low", "medium", "high", "critical"}
    if result["estimated_severity"] not in valid_severities:
        result["estimated_severity"] = "medium"

    return result


def _fallback_analysis(threat_type: str, severity: str, matched_value: str) -> dict[str, Any]:
    """Generate a heuristic-based analysis when LLM is unavailable."""
    classifications = {
        "sqli": "SQL Injection",
        "xss": "XSS",
        "path_traversal": "Path Traversal",
        "cmd_injection": "Command Injection",
        "rate_limit": "DDoS",
    }

    explanations = {
        "sqli": f"A SQL injection attempt was detected. The attacker injected the payload '{matched_value[:100]}' attempting to manipulate database queries to extract, modify, or delete data.",
        "xss": f"A Cross-Site Scripting (XSS) attack was detected. The payload '{matched_value[:100]}' was designed to inject malicious scripts that could steal user sessions, cookies, or redirect users.",
        "path_traversal": f"A path traversal attack was detected. The attacker used '{matched_value[:100]}' to attempt accessing files outside the web root directory, potentially exposing sensitive system files.",
        "cmd_injection": f"A command injection attempt was detected. The payload '{matched_value[:100]}' was crafted to execute arbitrary system commands on the server, potentially leading to full system compromise.",
        "rate_limit": "Excessive request rate detected from this source, potentially indicating a denial-of-service attack or automated scanning activity.",
    }

    mitigations = {
        "sqli": [
            "Use parameterized queries / prepared statements",
            "Implement input validation and sanitization",
            "Apply principle of least privilege to database accounts",
            "Enable WAF SQL injection protection rules",
            "Audit and patch database access code",
        ],
        "xss": [
            "Implement Content Security Policy (CSP) headers",
            "Sanitize all user input before rendering",
            "Use HTTP-only and Secure cookie flags",
            "Encode output in appropriate context (HTML, JS, URL)",
            "Enable X-XSS-Protection header",
        ],
        "path_traversal": [
            "Validate and sanitize file path inputs",
            "Use chroot or containerized environments",
            "Implement allowlists for accessible file paths",
            "Remove unnecessary file access permissions",
            "Deploy file integrity monitoring",
        ],
        "cmd_injection": [
            "Avoid passing user input to system commands",
            "Use language-specific safe APIs instead of shell commands",
            "Implement strict input validation with allowlists",
            "Run services with minimal privileges",
            "Enable AppArmor/SELinux security policies",
        ],
        "rate_limit": [
            "Implement progressive rate limiting",
            "Deploy CAPTCHA challenges for suspicious traffic",
            "Use CDN-level DDoS protection",
            "Enable IP reputation-based blocking",
            "Monitor traffic patterns for anomalies",
        ],
    }

    return {
        "threat_classification": classifications.get(threat_type, "Unknown"),
        "human_readable_explanation": explanations.get(
            threat_type, f"A {threat_type} attack was detected with payload: {matched_value[:100]}"
        ),
        "estimated_severity": severity,
        "estimated_impact": f"If successful, this {threat_type} attack could lead to unauthorized data access, system compromise, or service disruption.",
        "mitigation_strategies": mitigations.get(
            threat_type,
            [
                "Investigate the source IP",
                "Review and strengthen WAF rules",
                "Update intrusion detection signatures",
            ],
        ),
    }


def _store_analysis(
    waf_log_id: str,
    analysis: dict[str, Any],
    raw_response: dict[str, Any],
    elapsed_ms: float,
) -> None:
    """Store the AI analysis results in the database."""
    try:
        from sqlalchemy.orm import Session

        from api.core.database import build_sync_engine
        from api.models.ai_threat_summary import AIThreatSummary

        engine = build_sync_engine()

        with Session(engine) as session:
            summary = AIThreatSummary(
                waf_log_id=uuid.UUID(waf_log_id),
                threat_classification=analysis.get("threat_classification", "Unknown"),
                human_readable_explanation=analysis.get(
                    "human_readable_explanation", "Analysis not available."
                ),
                estimated_severity=analysis.get("estimated_severity", "medium"),
                estimated_impact=analysis.get("estimated_impact"),
                mitigation_strategies=analysis.get("mitigation_strategies", []),
                raw_llm_response=raw_response,
                llm_provider=settings.llm_provider,
                llm_model=settings.llm_model,
                analysis_duration_ms=elapsed_ms,
            )
            session.add(summary)
            session.commit()
            logger.info(f"[AI Analysis] Stored analysis for WAF log {waf_log_id}")
    except Exception as e:
        logger.error(f"[AI Analysis] Failed to store analysis: {e}")
