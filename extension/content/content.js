/**
 * SentinelX SecureLens — Content Script
 * Collects security-relevant data from the active page.
 * Runs in the page context and communicates with the service worker.
 */

(function () {
  "use strict";

  // ──── Collect Security Data ────

  function collectSecurityData() {
    return {
      url: window.location.href,
      hostname: window.location.hostname,
      protocol: window.location.protocol,
      headers: collectResponseHeaders(),
      cookies: collectCookieInfo(),
      technologies: detectTechnologies(),
      pageMetadata: collectPageMetadata(),
    };
  }

  // ──── Response Header Collection ────
  // Note: Content scripts can't directly access response headers.
  // We use meta tags and other indicators as proxies.

  function collectResponseHeaders() {
    const headers = {};

    // Check meta tags for CSP
    const cspMeta = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    if (cspMeta) {
      headers["content-security-policy"] = cspMeta.getAttribute("content");
    }

    // Check meta tags for X-Frame-Options
    const xfoMeta = document.querySelector('meta[http-equiv="X-Frame-Options"]');
    if (xfoMeta) {
      headers["x-frame-options"] = xfoMeta.getAttribute("content");
    }

    // Check meta tags for other security headers
    const xctMeta = document.querySelector('meta[http-equiv="X-Content-Type-Options"]');
    if (xctMeta) {
      headers["x-content-type-options"] = xctMeta.getAttribute("content");
    }

    // Use a fetch to the same page to get actual headers
    // This is done asynchronously and results are merged
    return headers;
  }

  // ──── Cookie Analysis ────

  function collectCookieInfo() {
    const cookies = [];
    const cookieStr = document.cookie;

    if (!cookieStr) return cookies;

    const pairs = cookieStr.split(";");
    for (const pair of pairs) {
      const [name] = pair.trim().split("=");
      if (name) {
        cookies.push({
          name: name.trim(),
          secure: window.location.protocol === "https:",
          httpOnly: false, // Can't detect from JS (if accessible, it's NOT httpOnly)
          sameSite: "unknown",
        });
      }
    }

    return cookies;
  }

  // ──── Technology Fingerprinting ────

  function detectTechnologies() {
    const techs = [];

    // React
    if (
      document.querySelector("[data-reactroot]") ||
      document.querySelector("#__next") ||
      window.__REACT_DEVTOOLS_GLOBAL_HOOK__
    ) {
      techs.push({ name: "React", category: "JavaScript Framework", confidence: 90 });
    }

    // Next.js
    if (document.querySelector("#__next") || document.querySelector('script[src*="/_next/"]')) {
      techs.push({ name: "Next.js", category: "Web Framework", confidence: 85 });
    }

    // Vue.js
    if (document.querySelector("[data-v-]") || window.__VUE__) {
      techs.push({ name: "Vue.js", category: "JavaScript Framework", confidence: 85 });
    }

    // Nuxt.js
    if (document.querySelector("#__nuxt") || document.querySelector("#__layout")) {
      techs.push({ name: "Nuxt.js", category: "Web Framework", confidence: 80 });
    }

    // Angular
    if (document.querySelector("[ng-version]") || document.querySelector("[_nghost-]")) {
      techs.push({ name: "Angular", category: "JavaScript Framework", confidence: 90 });
    }

    // WordPress
    if (
      document.querySelector('meta[name="generator"][content*="WordPress"]') ||
      document.querySelector('link[href*="wp-content"]')
    ) {
      techs.push({ name: "WordPress", category: "CMS", confidence: 95 });
    }

    // Cloudflare
    if (document.querySelector('script[src*="cloudflare"]')) {
      techs.push({ name: "Cloudflare", category: "CDN/Security", confidence: 80 });
    }

    // jQuery
    if (window.jQuery || document.querySelector('script[src*="jquery"]')) {
      techs.push({ name: "jQuery", category: "JavaScript Library", confidence: 90 });
    }

    // Google Analytics
    if (
      document.querySelector('script[src*="google-analytics"]') ||
      document.querySelector('script[src*="gtag"]') ||
      window.ga ||
      window.gtag
    ) {
      techs.push({ name: "Google Analytics", category: "Analytics", confidence: 90 });
    }

    // Tailwind CSS
    if (document.querySelector('[class*="flex"]') && document.querySelector('[class*="bg-"]')) {
      techs.push({ name: "Tailwind CSS", category: "CSS Framework", confidence: 60 });
    }

    // Bootstrap
    if (
      document.querySelector('[class*="container"]') &&
      document.querySelector('[class*="row"]') &&
      document.querySelector('link[href*="bootstrap"]')
    ) {
      techs.push({ name: "Bootstrap", category: "CSS Framework", confidence: 85 });
    }

    // Svelte / SvelteKit
    if (document.querySelector("[class*='svelte-']")) {
      techs.push({ name: "Svelte", category: "JavaScript Framework", confidence: 80 });
    }

    return techs;
  }

  // ──── Page Metadata ────

  function collectPageMetadata() {
    return {
      title: document.title,
      description:
        document.querySelector('meta[name="description"]')?.getAttribute("content") || "",
      favicon: document.querySelector('link[rel*="icon"]')?.getAttribute("href") || "",
      forms: document.querySelectorAll("form").length,
      passwordFields: document.querySelectorAll('input[type="password"]').length,
      externalLinks: [...document.querySelectorAll("a[href]")].filter((a) => {
        try {
          return new URL(a.href).hostname !== window.location.hostname;
        } catch {
          return false;
        }
      }).length,
      iframes: document.querySelectorAll("iframe").length,
    };
  }

  // ──── Fetch Real Headers ────

  async function fetchRealHeaders() {
    try {
      const response = await fetch(window.location.href, {
        method: "HEAD",
        cache: "no-cache",
      });

      const headers = {};
      const securityHeaders = [
        "content-security-policy",
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "x-xss-protection",
        "referrer-policy",
        "permissions-policy",
      ];

      for (const header of securityHeaders) {
        const value = response.headers.get(header);
        if (value) {
          headers[header] = value;
        }
      }

      return headers;
    } catch (e) {
      return {};
    }
  }

  // ──── Message Listener ────

  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "COLLECT_SECURITY_DATA") {
      // Collect basic data synchronously
      const data = collectSecurityData();

      // Then fetch real headers asynchronously
      fetchRealHeaders().then((realHeaders) => {
        // Merge real headers with meta-based headers
        data.headers = { ...data.headers, ...realHeaders };

        // Send to background for analysis
        chrome.runtime.sendMessage(
          { type: "ANALYZE_PAGE", data },
          (result) => {
            if (result) {
              // Store result for popup access
              chrome.storage.local.set({
                [`analysis_${data.url}`]: result,
                lastAnalysis: result,
              });
            }
          }
        );

        sendResponse(data);
      });

      return true; // Keep channel open for async
    }
  });

  // ──── Auto-analyze on Load ────

  function runAutoAnalysis() {
    setTimeout(() => {
      const data = collectSecurityData();
      fetchRealHeaders().then((realHeaders) => {
        data.headers = { ...data.headers, ...realHeaders };
        chrome.runtime.sendMessage({ type: "ANALYZE_PAGE", data }, (result) => {
          if (result) {
            chrome.storage.local.set({
              [`analysis_${data.url}`]: result,
              lastAnalysis: result,
            });
          }
        });
      });
    }, 1000);
  }

  if (document.readyState === "complete") {
    runAutoAnalysis();
  } else {
    window.addEventListener("load", runAutoAnalysis, { once: true });
  }
})();
