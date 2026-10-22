/**
 * SentinelX SecureLens — Background Service Worker
 * Manifest V3 compliant background script.
 * Handles security analysis coordination, message passing, and API communication.
 */

// ──── Configuration ────
const CONFIG = {
  API_BASE_URL: "http://localhost:8000/api/v1",
  ANALYSIS_CACHE_TTL: 300000, // 5 minutes
  BADGE_COLORS: {
    SAFE: "#10B981",       // Green
    LOW: "#3B82F6",        // Blue
    MEDIUM: "#F59E0B",     // Yellow
    HIGH: "#EF4444",       // Red
    CRITICAL: "#7C3AED",   // Purple
  },
};

// In-memory cache for analysis results
const analysisCache = new Map();

// ──── Message Handler ────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === "ANALYZE_PAGE") {
    handleAnalyzePage(message.data, sender.tab)
      .then(sendResponse)
      .catch((err) => sendResponse({ error: err.message }));
    return true; // Keep message channel open for async response
  }

  if (message.type === "REPORT_THREAT") {
    handleReportThreat(message.data)
      .then(sendResponse)
      .catch((err) => sendResponse({ error: err.message }));
    return true;
  }

  if (message.type === "GET_CACHED_RESULT") {
    const cached = analysisCache.get(message.url);
    sendResponse(cached || null);
    return false;
  }
});

// ──── Tab Update Listener ────
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === "complete" && tab.url) {
    // Auto-analyze when page loads
    if (tab.url.startsWith("http")) {
      chrome.tabs.sendMessage(tabId, { type: "COLLECT_SECURITY_DATA" }).catch(() => {
        // Content script may not be ready yet
      });
    }
  }
});

// ──── Core Analysis Logic ────

async function handleAnalyzePage(data, tab) {
  const url = data.url;

  // Check cache first
  const cached = analysisCache.get(url);
  if (cached && Date.now() - cached.timestamp < CONFIG.ANALYSIS_CACHE_TTL) {
    updateBadge(tab?.id, cached.result.riskLevel);
    return cached.result;
  }

  // Perform analysis
  const result = analyzeSecurityData(data);

  // Cache the result
  analysisCache.set(url, { result, timestamp: Date.now() });

  // Prune old cache entries
  if (analysisCache.size > 100) {
    const oldest = [...analysisCache.entries()]
      .sort((a, b) => a[1].timestamp - b[1].timestamp)
      .slice(0, 50);
    oldest.forEach(([key]) => analysisCache.delete(key));
  }

  // Update badge
  if (tab?.id) {
    updateBadge(tab.id, result.riskLevel);
  }

  return result;
}

function analyzeSecurityData(data) {
  const scores = {
    ssl: analyzeSSL(data),
    headers: analyzeHeaders(data.headers || {}),
    cookies: analyzeCookies(data.cookies || []),
    urlStructure: analyzeURL(data.url),
  };

  // Calculate weighted total score (0-100)
  const totalScore = Math.round(
    scores.ssl.score * 0.30 +
    scores.headers.score * 0.35 +
    scores.cookies.score * 0.15 +
    scores.urlStructure.score * 0.20
  );

  const riskLevel = getRiskLevel(totalScore);
  const techFingerprint = data.technologies || [];

  return {
    url: data.url,
    securityScore: totalScore,
    riskLevel,
    breakdown: scores,
    technologies: techFingerprint,
    recommendations: generateRecommendations(scores),
    analyzedAt: new Date().toISOString(),
  };
}

// ──── SSL Analysis ────

function analyzeSSL(data) {
  const url = data.url || "";
  const findings = [];
  let score = 0;

  if (url.startsWith("https://")) {
    score += 60;
    findings.push({ status: "pass", message: "HTTPS enabled" });

    // Check for HSTS
    const hsts = data.headers?.["strict-transport-security"];
    if (hsts) {
      score += 20;
      findings.push({ status: "pass", message: "HSTS header present" });
      if (hsts.includes("includeSubDomains")) {
        score += 10;
        findings.push({ status: "pass", message: "HSTS includes subdomains" });
      }
      if (hsts.includes("preload")) {
        score += 10;
        findings.push({ status: "pass", message: "HSTS preload enabled" });
      }
    } else {
      findings.push({ status: "warn", message: "No HSTS header" });
    }
  } else {
    findings.push({ status: "fail", message: "No HTTPS — connection is insecure" });
  }

  return { score: Math.min(100, score), findings };
}

// ──── Security Headers Analysis ────

function analyzeHeaders(headers) {
  const findings = [];
  let score = 0;
  const maxScore = 100;

  const headerChecks = [
    {
      name: "content-security-policy",
      label: "Content Security Policy (CSP)",
      weight: 25,
    },
    {
      name: "x-frame-options",
      label: "X-Frame-Options",
      weight: 15,
    },
    {
      name: "x-content-type-options",
      label: "X-Content-Type-Options",
      weight: 15,
    },
    {
      name: "referrer-policy",
      label: "Referrer-Policy",
      weight: 10,
    },
    {
      name: "permissions-policy",
      label: "Permissions-Policy",
      weight: 10,
    },
    {
      name: "x-xss-protection",
      label: "X-XSS-Protection",
      weight: 10,
    },
    {
      name: "strict-transport-security",
      label: "Strict-Transport-Security",
      weight: 15,
    },
  ];

  for (const check of headerChecks) {
    if (headers[check.name]) {
      score += check.weight;
      findings.push({
        status: "pass",
        message: `${check.label} is set`,
        value: headers[check.name],
      });
    } else {
      findings.push({
        status: "fail",
        message: `Missing ${check.label}`,
      });
    }
  }

  return { score: Math.min(100, score), findings };
}

// ──── Cookie Analysis ────

function analyzeCookies(cookies) {
  const findings = [];
  let score = 100;

  if (cookies.length === 0) {
    return { score: 100, findings: [{ status: "info", message: "No cookies detected" }] };
  }

  let insecureCount = 0;
  let noHttpOnlyCount = 0;
  let noSameSiteCount = 0;

  for (const cookie of cookies) {
    if (!cookie.secure) insecureCount++;
    if (!cookie.httpOnly) noHttpOnlyCount++;
    if (!cookie.sameSite || cookie.sameSite === "none") noSameSiteCount++;
  }

  const total = cookies.length;

  if (insecureCount > 0) {
    score -= Math.round((insecureCount / total) * 40);
    findings.push({
      status: "fail",
      message: `${insecureCount}/${total} cookies lack Secure flag`,
    });
  } else {
    findings.push({ status: "pass", message: "All cookies have Secure flag" });
  }

  if (noHttpOnlyCount > 0) {
    score -= Math.round((noHttpOnlyCount / total) * 35);
    findings.push({
      status: "warn",
      message: `${noHttpOnlyCount}/${total} cookies lack HttpOnly flag`,
    });
  } else {
    findings.push({ status: "pass", message: "All cookies have HttpOnly flag" });
  }

  if (noSameSiteCount > 0) {
    score -= Math.round((noSameSiteCount / total) * 25);
    findings.push({
      status: "warn",
      message: `${noSameSiteCount}/${total} cookies lack SameSite attribute`,
    });
  }

  return { score: Math.max(0, score), findings };
}

// ──── URL Structure Analysis ────

function analyzeURL(url) {
  const findings = [];
  let score = 100;

  try {
    const parsed = new URL(url);

    // Check for suspicious TLDs
    const suspiciousTLDs = [".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".buzz", ".club"];
    if (suspiciousTLDs.some((tld) => parsed.hostname.endsWith(tld))) {
      score -= 30;
      findings.push({ status: "warn", message: "Suspicious top-level domain" });
    }

    // Check for IP address in hostname
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.hostname)) {
      score -= 25;
      findings.push({ status: "warn", message: "IP address used instead of domain name" });
    }

    // Check for excessive subdomains
    const subdomainCount = parsed.hostname.split(".").length - 2;
    if (subdomainCount > 3) {
      score -= 15;
      findings.push({ status: "warn", message: `Excessive subdomains (${subdomainCount})` });
    }

    // Check for suspicious characters
    if (parsed.hostname.includes("--") || parsed.hostname.includes("..")) {
      score -= 20;
      findings.push({ status: "warn", message: "Suspicious characters in hostname" });
    }

    // Check for very long URLs
    if (url.length > 200) {
      score -= 10;
      findings.push({ status: "info", message: "Unusually long URL" });
    }

    // Check for data/javascript URIs in params
    if (parsed.search.includes("javascript:") || parsed.search.includes("data:")) {
      score -= 40;
      findings.push({ status: "fail", message: "Potential XSS in URL parameters" });
    }

    // Check for common phishing patterns
    const phishingKeywords = ["login", "verify", "secure", "update", "confirm", "account", "banking"];
    const hostParts = parsed.hostname.toLowerCase().split(/[.-]/);
    const phishingMatches = phishingKeywords.filter((kw) =>
      hostParts.some((part) => part.includes(kw))
    );
    if (phishingMatches.length >= 2) {
      score -= 20;
      findings.push({
        status: "warn",
        message: `Potential phishing keywords in domain: ${phishingMatches.join(", ")}`,
      });
    }

    if (findings.length === 0) {
      findings.push({ status: "pass", message: "URL structure appears normal" });
    }
  } catch (e) {
    score = 0;
    findings.push({ status: "fail", message: "Invalid URL format" });
  }

  return { score: Math.max(0, score), findings };
}

// ──── Risk Level Classification ────

function getRiskLevel(score) {
  if (score >= 80) return "SAFE";
  if (score >= 60) return "LOW";
  if (score >= 40) return "MEDIUM";
  if (score >= 20) return "HIGH";
  return "CRITICAL";
}

// ──── Recommendations Generator ────

function generateRecommendations(scores) {
  const recommendations = [];

  for (const finding of scores.ssl.findings) {
    if (finding.status === "fail" || finding.status === "warn") {
      recommendations.push({
        category: "SSL/TLS",
        severity: finding.status === "fail" ? "high" : "medium",
        message: finding.message,
      });
    }
  }

  for (const finding of scores.headers.findings) {
    if (finding.status === "fail") {
      recommendations.push({
        category: "Security Headers",
        severity: "medium",
        message: `Add ${finding.message.replace("Missing ", "")}`,
      });
    }
  }

  for (const finding of scores.cookies.findings) {
    if (finding.status === "fail" || finding.status === "warn") {
      recommendations.push({
        category: "Cookies",
        severity: finding.status === "fail" ? "high" : "medium",
        message: finding.message,
      });
    }
  }

  for (const finding of scores.urlStructure.findings) {
    if (finding.status === "fail" || finding.status === "warn") {
      recommendations.push({
        category: "URL Analysis",
        severity: finding.status === "fail" ? "high" : "low",
        message: finding.message,
      });
    }
  }

  return recommendations;
}

// ──── Badge Update ────

function updateBadge(tabId, riskLevel) {
  if (!tabId) return;

  const text = riskLevel === "SAFE" ? "✓" : riskLevel.charAt(0);
  const color = CONFIG.BADGE_COLORS[riskLevel] || "#6B7280";

  chrome.action.setBadgeText({ text, tabId });
  chrome.action.setBadgeBackgroundColor({ color, tabId });
}

// ──── Report Threat to API ────

async function handleReportThreat(data) {
  try {
    const response = await fetch(`${CONFIG.API_BASE_URL}/threats/report`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        url: data.url,
        risk_score: data.riskScore || 50,
        threat_type: data.threatType || "unknown",
        details: data.details || {},
        source: "extension",
      }),
    });

    if (!response.ok) {
      throw new Error(`API responded with ${response.status}`);
    }

    return await response.json();
  } catch (error) {
    console.error("[SecureLens] Report threat failed:", error);
    return { error: error.message };
  }
}

console.log("[SecureLens] Service worker initialized");
