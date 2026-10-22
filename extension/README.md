# 🌐 SecureLens Browser Extension — Setup & Testing Guide

SecureLens is the browser extension component of SentinelX, built for Chrome, Edge, Brave, and other Chromium-based browsers using **Manifest V3**.

---

## 🚀 How to Install in Chrome / Edge (Unpacked)

1. Open your browser and navigate to:
   - **Chrome**: `chrome://extensions/`
   - **Edge**: `edge://extensions/`
   - **Brave**: `brave://extensions/`
2. Toggle on **Developer mode** (top-right corner).
3. Click the **Load unpacked** button (top-left).
4. Select the directory:
   ```
   C:\Users\lenovo\.gemini\antigravity\scratch\sentinelx\extension
   ```
5. SecureLens will appear in your extensions bar! Pin it for quick access.

---

## 🧪 How to Test It

### 1. Test on Real Sites
- Navigate to high-security sites like `https://github.com` or `https://cloudflare.com`.
- Click the SecureLens shield icon in your toolbar.
- You should observe high security scores (80–100), verified HTTPS/HSTS, comprehensive CSP policies, and tech fingerprinting (e.g. React, Next.js, Cloudflare).

### 2. Test with the Included Vulnerability Testbed
- In your browser, open the local testbed file:
  ```
  file:///C:/Users/lenovo/.gemini/antigravity/scratch/sentinelx/extension/test/test_target.html
  ```
- Click the button **"Inject Test Cookies"**.
- Click the SecureLens extension icon in your browser:
  - **Score**: Low / Warning score due to missing CSP, HSTS, X-Frame-Options.
  - **Findings Tab**: Flags missing headers and insecure cookie flags.
  - **Tech Tab**: Detects React and jQuery frameworks.
  - **Report Tab**: Try submitting a threat report directly to the SentinelX API!
