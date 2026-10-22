/**
 * SecureLens Popup — Interactive Logic
 */

document.addEventListener("DOMContentLoaded", () => {
  initTabs();
  initAnalysis();
  initReportForm();
  initRefresh();
});

// ──── Tab Navigation ────

function initTabs() {
  const tabs = document.querySelectorAll(".tab");
  const contents = document.querySelectorAll(".tab-content");

  tabs.forEach((tab) => {
    tab.addEventListener("click", () => {
      tabs.forEach((t) => t.classList.remove("active"));
      contents.forEach((c) => c.classList.remove("active"));

      tab.classList.add("active");
      document.getElementById(`tab-${tab.dataset.tab}`).classList.add("active");
    });
  });
}

// ──── Security Analysis ────

function initAnalysis() {
  // Get the active tab URL
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (!tab || !tab.url) {
      showError("Cannot analyze this page.");
      return;
    }

    document.getElementById("urlDisplay").textContent = tab.url;

    // Try to get cached result first
    chrome.storage.local.get("lastAnalysis", (data) => {
      if (data.lastAnalysis && data.lastAnalysis.url === tab.url) {
        renderResults(data.lastAnalysis);
      } else {
        // Trigger a fresh analysis
        triggerAnalysis(tab);
      }
    });
  });
}

function triggerAnalysis(tab) {
  chrome.tabs.sendMessage(
    tab.id,
    { type: "COLLECT_SECURITY_DATA" },
    (response) => {
      if (chrome.runtime.lastError) {
        // Content script may not be injected (e.g., chrome:// pages)
        showError("Cannot analyze this page type.");
        return;
      }

      // Wait for analysis result
      setTimeout(() => {
        chrome.storage.local.get("lastAnalysis", (data) => {
          if (data.lastAnalysis) {
            renderResults(data.lastAnalysis);
          }
        });
      }, 1500);
    }
  );
}

function renderResults(result) {
  if (!result) return;

  // Update score
  const scoreNum = document.getElementById("scoreNumber");
  const scoreCircle = document.getElementById("scoreCircle");
  const riskBadge = document.getElementById("riskBadge");

  const circumference = 326.73;
  const offset = circumference - (result.securityScore / 100) * circumference;

  scoreNum.textContent = result.securityScore;
  scoreCircle.style.strokeDashoffset = offset;

  // Set score ring color
  const colors = {
    SAFE: "#10B981",
    LOW: "#3B82F6",
    MEDIUM: "#F59E0B",
    HIGH: "#EF4444",
    CRITICAL: "#8B5CF6",
  };
  scoreCircle.style.stroke = colors[result.riskLevel] || "#6366F1";

  // Update risk badge
  riskBadge.textContent = result.riskLevel;
  riskBadge.className = `risk-badge ${result.riskLevel.toLowerCase()}`;

  // Render findings
  renderFindings(result);

  // Render header checks
  renderHeaders(result);

  // Render technologies
  renderTechnologies(result);
}

function renderFindings(result) {
  const container = document.getElementById("findingsList");
  const allFindings = [];

  if (result.breakdown) {
    for (const [category, data] of Object.entries(result.breakdown)) {
      if (data.findings) {
        for (const finding of data.findings) {
          allFindings.push({ ...finding, category: formatCategory(category) });
        }
      }
    }
  }

  if (allFindings.length === 0) {
    container.innerHTML = '<div class="empty-state">No findings available.</div>';
    return;
  }

  // Sort: failures first, then warnings, then passes
  const order = { fail: 0, warn: 1, info: 2, pass: 3 };
  allFindings.sort((a, b) => (order[a.status] ?? 3) - (order[b.status] ?? 3));

  container.innerHTML = allFindings
    .map(
      (f) => `
    <div class="finding-item ${f.status}">
      <div class="finding-icon ${f.status}">
        ${f.status === "pass" ? "✓" : f.status === "fail" ? "✗" : f.status === "warn" ? "!" : "i"}
      </div>
      <div>
        <div class="finding-text">${escapeHtml(f.message)}</div>
        <div class="finding-category">${escapeHtml(f.category)}</div>
      </div>
    </div>
  `
    )
    .join("");
}

function renderHeaders(result) {
  const container = document.getElementById("headerChecks");
  const headers = result.breakdown?.headers?.findings || [];

  if (headers.length === 0) {
    container.innerHTML = '<div class="empty-state">No header data available.</div>';
    return;
  }

  container.innerHTML = headers
    .map(
      (h) => `
    <div class="header-check">
      <span class="header-name">${escapeHtml(h.message.replace("Missing ", "").replace(" is set", ""))}</span>
      <span class="header-status ${h.status === "pass" ? "present" : "missing"}">
        ${h.status === "pass" ? "Present" : "Missing"}
      </span>
    </div>
  `
    )
    .join("");
}

function renderTechnologies(result) {
  const container = document.getElementById("techList");
  const techs = result.technologies || [];

  if (techs.length === 0) {
    container.innerHTML = '<div class="empty-state">No technologies detected.</div>';
    return;
  }

  container.innerHTML = techs
    .map(
      (t) => `
    <div class="tech-item">
      <div class="tech-info">
        <span class="tech-name">${escapeHtml(t.name)}</span>
        <span class="tech-category">${escapeHtml(t.category)}</span>
      </div>
      <span class="tech-confidence">${t.confidence}%</span>
    </div>
  `
    )
    .join("");
}

function showError(message) {
  document.getElementById("scoreNumber").textContent = "—";
  document.getElementById("riskBadge").textContent = "N/A";
  document.getElementById("urlDisplay").textContent = message;
  document.getElementById("findingsList").innerHTML = `
    <div class="empty-state">${escapeHtml(message)}</div>
  `;
}

// ──── Report Threat ────

function initReportForm() {
  const reportBtn = document.getElementById("reportBtn");
  const statusEl = document.getElementById("reportStatus");

  reportBtn.addEventListener("click", async () => {
    const threatType = document.getElementById("threatType").value;
    const details = document.getElementById("threatDetails").value;

    if (!threatType) {
      statusEl.textContent = "Please select a threat type.";
      statusEl.className = "report-status error";
      return;
    }

    reportBtn.disabled = true;
    reportBtn.textContent = "Submitting...";

    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const url = tabs[0]?.url;

      chrome.runtime.sendMessage(
        {
          type: "REPORT_THREAT",
          data: {
            url,
            threatType,
            riskScore: 75,
            details: { userNotes: details, reportedFrom: "extension-popup" },
          },
        },
        (response) => {
          reportBtn.disabled = false;
          reportBtn.innerHTML =
            '<svg width="14" height="14" viewBox="0 0 14 14" fill="currentColor"><path d="M1 13L14 7L1 1V5.5L10 7L1 8.5V13Z"/></svg> Submit Report';

          if (response && !response.error) {
            statusEl.textContent = "✓ Report submitted successfully!";
            statusEl.className = "report-status success";
          } else {
            statusEl.textContent = `✗ Failed: ${response?.error || "Unknown error"}`;
            statusEl.className = "report-status error";
          }
        }
      );
    });
  });
}

// ──── Refresh Button ────

function initRefresh() {
  document.getElementById("refreshBtn").addEventListener("click", () => {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs[0]) {
        // Clear cache for this URL
        chrome.storage.local.remove(`analysis_${tabs[0].url}`);
        triggerAnalysis(tabs[0]);

        // Visual feedback
        const btn = document.getElementById("refreshBtn");
        btn.style.animation = "spin 0.5s ease";
        setTimeout(() => (btn.style.animation = ""), 500);
      }
    });
  });
}

// ──── Utilities ────

function formatCategory(key) {
  const labels = {
    ssl: "SSL/TLS",
    headers: "Security Headers",
    cookies: "Cookies",
    urlStructure: "URL Analysis",
  };
  return labels[key] || key;
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}
