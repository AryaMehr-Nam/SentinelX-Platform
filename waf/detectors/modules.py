"""
SentinelX — WAF Detection Modules
Individual heuristic detectors for specific attack types.
These complement the YAML rule engine with more advanced detection logic.
"""

import re
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class DetectionResult:
    """Result from a heuristic detector."""
    detected: bool
    confidence: float  # 0.0 to 1.0
    category: str
    severity: str
    description: str
    matched_payload: str = ""


class SQLiDetector:
    """Advanced SQL injection detection using heuristics beyond simple regex."""

    # SQL keywords that are suspicious in user input
    SQL_KEYWORDS = {
        "select", "insert", "update", "delete", "drop", "alter", "create",
        "truncate", "exec", "execute", "union", "join", "where", "from",
        "having", "group", "order", "into", "values", "set", "table",
        "database", "schema", "information_schema", "pg_catalog",
    }

    # SQL operators and functions
    SQL_OPERATORS = {
        "or", "and", "not", "like", "between", "in", "exists",
        "null", "true", "false", "is",
    }

    def detect(self, input_str: str) -> DetectionResult:
        """Analyze input for SQL injection patterns."""
        if not input_str:
            return DetectionResult(False, 0.0, "sqli", "low", "")

        lower = input_str.lower()
        score = 0.0
        reasons = []

        # Check for SQL keyword density
        words = set(re.findall(r'\b\w+\b', lower))
        keyword_count = len(words & self.SQL_KEYWORDS)
        if keyword_count >= 3:
            score += 0.4
            reasons.append(f"{keyword_count} SQL keywords detected")

        # Check for string termination patterns
        if re.search(r"['\"];\s*--", lower):
            score += 0.3
            reasons.append("String termination with comment")

        # Check for tautologies (1=1, 'a'='a')
        if re.search(r"(\d+)\s*=\s*\1", lower) or re.search(r"'([^']+)'\s*=\s*'\1'", lower):
            score += 0.3
            reasons.append("Tautology detected")

        # Check for UNION-based injection
        if re.search(r"union\s+(all\s+)?select", lower):
            score += 0.5
            reasons.append("UNION SELECT detected")

        # Check for stacked queries
        if re.search(r";\s*(select|drop|alter|insert|update|delete|create)\s", lower):
            score += 0.4
            reasons.append("Stacked query detected")

        # Check for comment sequences
        if "--" in lower or "/*" in lower:
            score += 0.1
            reasons.append("SQL comment sequence")

        # Check for hex encoding evasion
        if re.search(r"0x[0-9a-f]+", lower):
            score += 0.2
            reasons.append("Hex encoding detected")

        confidence = min(1.0, score)
        detected = confidence >= 0.3

        severity = "low"
        if confidence >= 0.7:
            severity = "critical"
        elif confidence >= 0.5:
            severity = "high"
        elif confidence >= 0.3:
            severity = "medium"

        return DetectionResult(
            detected=detected,
            confidence=confidence,
            category="sqli",
            severity=severity,
            description="; ".join(reasons) if reasons else "No SQLi detected",
            matched_payload=input_str[:200],
        )


class XSSDetector:
    """Advanced XSS detection using heuristics."""

    def detect(self, input_str: str) -> DetectionResult:
        """Analyze input for XSS patterns."""
        if not input_str:
            return DetectionResult(False, 0.0, "xss", "low", "")

        score = 0.0
        reasons = []

        # Check for HTML tags
        if re.search(r"<\s*\w+[^>]*>", input_str, re.IGNORECASE):
            score += 0.3
            reasons.append("HTML tag detected")

        # Check for script tags specifically
        if re.search(r"<\s*script", input_str, re.IGNORECASE):
            score += 0.5
            reasons.append("Script tag detected")

        # Check for event handlers
        if re.search(r"\bon\w+\s*=", input_str, re.IGNORECASE):
            score += 0.4
            reasons.append("Event handler attribute detected")

        # Check for javascript: protocol
        if re.search(r"javascript\s*:", input_str, re.IGNORECASE):
            score += 0.4
            reasons.append("JavaScript protocol detected")

        # Check for encoded payloads
        if re.search(r"&#x?[0-9a-f]+;", input_str, re.IGNORECASE):
            score += 0.2
            reasons.append("HTML entity encoding detected")

        # Check for SVG-based XSS
        if re.search(r"<\s*svg[^>]*on\w+\s*=", input_str, re.IGNORECASE):
            score += 0.5
            reasons.append("SVG-based XSS detected")

        # Check for data URI
        if re.search(r"data\s*:\s*text/html", input_str, re.IGNORECASE):
            score += 0.4
            reasons.append("Data URI with HTML content")

        confidence = min(1.0, score)
        detected = confidence >= 0.3

        severity = "medium"
        if confidence >= 0.7:
            severity = "high"
        elif confidence >= 0.5:
            severity = "high"

        return DetectionResult(
            detected=detected,
            confidence=confidence,
            category="xss",
            severity=severity,
            description="; ".join(reasons) if reasons else "No XSS detected",
            matched_payload=input_str[:200],
        )


class PathTraversalDetector:
    """Advanced path traversal detection."""

    SENSITIVE_PATHS = [
        "/etc/passwd", "/etc/shadow", "/etc/hosts",
        "wp-config.php", "web.config", ".env", ".git/",
        ".htaccess", ".htpasswd", "boot.ini",
        "/proc/self/", "/windows/system32/",
    ]

    def detect(self, input_str: str) -> DetectionResult:
        if not input_str:
            return DetectionResult(False, 0.0, "path_traversal", "low", "")

        lower = input_str.lower()
        score = 0.0
        reasons = []

        # Check for directory traversal sequences
        traversal_count = lower.count("../") + lower.count("..\\")
        if traversal_count >= 2:
            score += 0.5
            reasons.append(f"{traversal_count} traversal sequences")

        # Check for URL-encoded traversal
        if "%2e%2e" in lower or "%252e" in lower:
            score += 0.4
            reasons.append("URL-encoded traversal")

        # Check for sensitive file access
        for path in self.SENSITIVE_PATHS:
            if path in lower:
                score += 0.4
                reasons.append(f"Sensitive path: {path}")
                break

        # Check for null byte injection
        if "%00" in lower or "\x00" in input_str:
            score += 0.3
            reasons.append("Null byte injection")

        confidence = min(1.0, score)
        detected = confidence >= 0.3

        severity = "high" if confidence >= 0.5 else "medium"

        return DetectionResult(
            detected=detected,
            confidence=confidence,
            category="path_traversal",
            severity=severity,
            description="; ".join(reasons) if reasons else "No traversal detected",
            matched_payload=input_str[:200],
        )


class CommandInjectionDetector:
    """Advanced command injection detection."""

    DANGEROUS_COMMANDS = [
        "ls", "cat", "whoami", "id", "uname", "pwd", "wget", "curl",
        "nc", "bash", "sh", "python", "perl", "ruby", "php",
        "rm", "chmod", "chown", "kill", "nmap", "netcat",
    ]

    def detect(self, input_str: str) -> DetectionResult:
        if not input_str:
            return DetectionResult(False, 0.0, "cmd_injection", "low", "")

        lower = input_str.lower()
        score = 0.0
        reasons = []

        # Check for shell metacharacters followed by commands
        for cmd in self.DANGEROUS_COMMANDS:
            if re.search(rf"[;|&`]\s*{cmd}\b", lower):
                score += 0.5
                reasons.append(f"Shell command after metachar: {cmd}")
                break

        # Check for command substitution
        if re.search(r"\$\(.*\)", lower):
            score += 0.4
            reasons.append("Command substitution $() detected")

        if re.search(r"`[^`]+`", lower):
            score += 0.4
            reasons.append("Backtick command substitution")

        # Check for pipe chains
        if re.search(r"\|\s*\w+", lower):
            score += 0.2
            reasons.append("Pipe chain detected")

        # Check for reverse shell patterns
        if re.search(r"/dev/(tcp|udp)/", lower):
            score += 0.5
            reasons.append("Reverse shell pattern")

        confidence = min(1.0, score)
        detected = confidence >= 0.3

        severity = "critical" if confidence >= 0.5 else "high"

        return DetectionResult(
            detected=detected,
            confidence=confidence,
            category="cmd_injection",
            severity=severity,
            description="; ".join(reasons) if reasons else "No injection detected",
            matched_payload=input_str[:200],
        )
