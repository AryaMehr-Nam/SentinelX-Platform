/** SentinelX Dashboard — WAF Rules Page */
import { useState, useEffect } from "react";
import {
  Shield,
  Search,
  ToggleLeft,
  ToggleRight,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
  Zap,
} from "lucide-react";
import { wafApi } from "../lib/api";
import type { WAFRule } from "../types";

/* ────────────────────────── Mock Data ────────────────────────── */

const MOCK_RULES: WAFRule[] = [
  {
    id: "r1", rule_id: "WAF-001", name: "SQL Injection — Classic Patterns",
    description: "Detects common SQL injection patterns including UNION SELECT, OR 1=1, comment sequences (--), and stacked queries. Covers MySQL, PostgreSQL, MSSQL, and Oracle syntax variants.",
    category: "Injection", rule_definition: {}, is_enabled: true, priority: 1, action: "block",
    created_at: "2025-03-01T00:00:00Z", updated_at: "2026-05-20T10:00:00Z",
  },
  {
    id: "r2", rule_id: "WAF-002", name: "SQL Injection — Blind & Time-based",
    description: "Detects blind SQL injection attempts using boolean-based and time-based techniques such as SLEEP(), BENCHMARK(), and conditional expressions.",
    category: "Injection", rule_definition: {}, is_enabled: true, priority: 1, action: "block",
    created_at: "2025-03-01T00:00:00Z", updated_at: "2026-05-18T14:30:00Z",
  },
  {
    id: "r3", rule_id: "WAF-012", name: "XSS — Reflected Script Injection",
    description: "Blocks reflected cross-site scripting payloads in URL parameters and form inputs. Detects <script> tags, event handlers (onerror, onload), and javascript: protocol URIs.",
    category: "XSS", rule_definition: {}, is_enabled: true, priority: 2, action: "block",
    created_at: "2025-03-15T00:00:00Z",
  },
  {
    id: "r4", rule_id: "WAF-013", name: "XSS — DOM-based Payload Detection",
    description: "Identifies DOM-based XSS attempts targeting document.cookie, innerHTML assignments, and eval() calls injected through hash fragments and query strings.",
    category: "XSS", rule_definition: {}, is_enabled: true, priority: 2, action: "block",
    created_at: "2025-03-15T00:00:00Z",
  },
  {
    id: "r5", rule_id: "WAF-034", name: "Path Traversal — Directory Escape",
    description: "Detects attempts to traverse directories using ../ sequences, URL-encoded variants (%2e%2e%2f), and double-encoding bypasses to access sensitive system files.",
    category: "File Inclusion", rule_definition: {}, is_enabled: true, priority: 2, action: "block",
    created_at: "2025-04-01T00:00:00Z",
  },
  {
    id: "r6", rule_id: "WAF-056", name: "Remote Code Execution — Command Injection",
    description: "Blocks OS command injection attempts via shell metacharacters (;, |, &&, `), common commands (whoami, cat, wget), and reverse shell patterns.",
    category: "RCE", rule_definition: {}, is_enabled: true, priority: 1, action: "block",
    created_at: "2025-04-15T00:00:00Z",
  },
  {
    id: "r7", rule_id: "WAF-078", name: "SSRF — Internal Network Access",
    description: "Prevents server-side request forgery targeting internal IPs (169.254.x.x, 10.x.x.x, 192.168.x.x), cloud metadata endpoints, and internal service discovery.",
    category: "SSRF", rule_definition: {}, is_enabled: true, priority: 1, action: "block",
    created_at: "2025-05-01T00:00:00Z",
  },
  {
    id: "r8", rule_id: "WAF-091", name: "Rate Limiting — Login Endpoint",
    description: "Enforces rate limiting on authentication endpoints. Max 10 requests per minute per IP. Triggers CAPTCHA challenge after 5 failed attempts.",
    category: "Rate Limit", rule_definition: {}, is_enabled: true, priority: 3, action: "challenge",
    created_at: "2025-05-10T00:00:00Z",
  },
  {
    id: "r9", rule_id: "WAF-092", name: "Rate Limiting — API Global",
    description: "Global API rate limiting at 1,000 requests per minute per IP. Helps prevent DDoS and aggressive scraping while allowing normal usage.",
    category: "Rate Limit", rule_definition: {}, is_enabled: true, priority: 4, action: "challenge",
    created_at: "2025-05-10T00:00:00Z",
  },
  {
    id: "r10", rule_id: "WAF-105", name: "Bot Detection — Headless Browsers",
    description: "Identifies and challenges requests from headless browsers (Puppeteer, Playwright, Selenium) by analyzing navigator properties, WebGL fingerprints, and timing anomalies.",
    category: "Bot", rule_definition: {}, is_enabled: false, priority: 5, action: "challenge",
    created_at: "2025-06-01T00:00:00Z",
  },
  {
    id: "r11", rule_id: "WAF-106", name: "Bot Detection — Known Bad User-Agents",
    description: "Blocks requests from known malicious user agents including common vulnerability scanners (Nikto, SQLMap, Nmap), and outdated crawlers.",
    category: "Bot", rule_definition: {}, is_enabled: true, priority: 4, action: "block",
    created_at: "2025-06-01T00:00:00Z",
  },
  {
    id: "r12", rule_id: "ML-AUTO", name: "AI/ML Anomaly Detection",
    description: "Machine-learning model that analyzes request patterns, payload entropy, and behavioral signals in real-time. Automatically adapts to new attack vectors without rule updates.",
    category: "AI/ML", rule_definition: {}, is_enabled: true, priority: 1, action: "block",
    created_at: "2025-06-15T00:00:00Z", updated_at: "2026-06-05T06:00:00Z",
  },
];

/* ────────────────────────── Helpers ────────────────────────── */

const CATEGORY_COLORS: Record<string, string> = {
  Injection: "bg-severity-critical/15 text-severity-critical border-severity-critical/30",
  XSS: "bg-severity-high/15 text-severity-high border-severity-high/30",
  "File Inclusion": "bg-warning/15 text-warning border-warning/30",
  RCE: "bg-severity-critical/15 text-severity-critical border-severity-critical/30",
  SSRF: "bg-accent-purple/15 text-accent-purple border-accent-purple/30",
  "Rate Limit": "bg-accent-cyan/15 text-accent-cyan border-accent-cyan/30",
  Bot: "bg-accent-blue/15 text-accent-blue border-accent-blue/30",
  "AI/ML": "bg-accent-indigo/15 text-accent-indigo border-accent-indigo/30",
};

const ACTION_STYLES: Record<string, string> = {
  block: "bg-danger/15 text-danger border-danger/30",
  challenge: "bg-warning/15 text-warning border-warning/30",
  log: "bg-info/15 text-info border-info/30",
};

function priorityIndicator(p: number) {
  const map: Record<number, { label: string; cls: string }> = {
    1: { label: "Critical", cls: "text-severity-critical" },
    2: { label: "High", cls: "text-severity-high" },
    3: { label: "Medium", cls: "text-severity-medium" },
    4: { label: "Low", cls: "text-severity-low" },
    5: { label: "Info", cls: "text-text-muted" },
  };
  const m = map[p] ?? map[5];
  return (
    <div className="flex items-center gap-1.5">
      <div className="flex gap-0.5">
        {Array.from({ length: 5 }, (_, i) => (
          <div
            key={i}
            className={`h-2 w-1 rounded-full ${
              i < (6 - p) ? m.cls.replace("text-", "bg-") : "bg-bg-elevated"
            }`}
          />
        ))}
      </div>
      <span className={`text-[10px] font-medium ${m.cls}`}>{m.label}</span>
    </div>
  );
}

/* ────────────────────────── Page ────────────────────────── */

export default function WAFRulesPage() {
  const [rules, setRules] = useState<WAFRule[]>(MOCK_RULES);
  const [search, setSearch] = useState("");
  const [categoryFilter, setCategoryFilter] = useState("all");
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [mounted, setMounted] = useState(false);

  useEffect(() => { setMounted(true); }, []);

  useEffect(() => {
    wafApi.rules().then((r) => {
      if (Array.isArray(r.data) && r.data.length) setRules(r.data);
    }).catch(() => {});
  }, []);

  const categories = ["all", ...Array.from(new Set(rules.map((r) => r.category)))];

  const filtered = rules.filter((r) => {
    if (categoryFilter !== "all" && r.category !== categoryFilter) return false;
    if (search.trim()) {
      const q = search.toLowerCase();
      return (
        r.name.toLowerCase().includes(q) ||
        r.rule_id.toLowerCase().includes(q) ||
        r.category.toLowerCase().includes(q) ||
        (r.description ?? "").toLowerCase().includes(q)
      );
    }
    return true;
  });

  const toggleRule = async (rule: WAFRule) => {
    const nextState = !rule.is_enabled;
    setRules((prev) =>
      prev.map((r) => (r.id === rule.id ? { ...r, is_enabled: nextState } : r))
    );
    try {
      await wafApi.updateRule(rule.rule_id, { is_enabled: nextState });
    } catch {
      // Keep optimistic update or offline fallback
    }
  };

  const enabledCount = rules.filter((r) => r.is_enabled).length;

  return (
    <div className={`space-y-6 p-6 transition-all duration-500 ${mounted ? "opacity-100" : "opacity-0"}`}>
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold text-text-primary tracking-tight">
            <Shield className="h-6 w-6 text-accent-indigo" />
            WAF Rules
          </h1>
          <p className="mt-1 text-sm text-text-muted">
            {enabledCount} of {rules.length} rules enabled
          </p>
        </div>
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 rounded-lg border border-success/30 bg-success/10 px-3 py-1.5">
            <Zap className="h-3.5 w-3.5 text-success" />
            <span className="text-xs font-medium text-success">{enabledCount} Active</span>
          </div>
          <div className="flex items-center gap-2 rounded-lg border border-border bg-bg-card px-3 py-1.5">
            <AlertTriangle className="h-3.5 w-3.5 text-text-muted" />
            <span className="text-xs font-medium text-text-muted">{rules.length - enabledCount} Disabled</span>
          </div>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-text-muted" />
          <input
            type="text"
            placeholder="Search rules by name, ID, or category…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full rounded-lg border border-border bg-bg-card pl-10 pr-4 py-2 text-sm text-text-primary placeholder:text-text-muted outline-none focus:border-accent-indigo/50 focus:ring-1 focus:ring-accent-indigo/30 transition-colors"
          />
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setCategoryFilter(cat)}
              className={`rounded-md border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wider transition-colors ${
                categoryFilter === cat
                  ? cat === "all"
                    ? "border-accent-indigo/30 bg-accent-indigo/15 text-accent-indigo"
                    : (CATEGORY_COLORS[cat] ?? "border-border bg-bg-elevated text-text-secondary")
                  : "border-border bg-bg-card text-text-muted hover:bg-bg-elevated"
              }`}
            >
              {cat}
            </button>
          ))}
        </div>
      </div>

      {/* Rules List */}
      <div className="space-y-3">
        {filtered.map((rule, i) => {
          const expanded = expandedId === rule.id;
          return (
            <div
              key={rule.id}
              className={`card overflow-hidden transition-all duration-200 ${
                !rule.is_enabled ? "opacity-60" : ""
              }`}
              style={{ animation: `fadeIn 0.3s ease-out ${i * 40}ms both` }}
            >
              {/* Main row */}
              <div className="flex items-center gap-4 px-5 py-4">
                {/* Toggle */}
                <button
                  onClick={() => toggleRule(rule)}
                  className="shrink-0 transition-colors cursor-pointer"
                  title={rule.is_enabled ? "Disable rule" : "Enable rule"}
                >
                  {rule.is_enabled ? (
                    <ToggleRight className="h-7 w-7 text-success" />
                  ) : (
                    <ToggleLeft className="h-7 w-7 text-text-muted" />
                  )}
                </button>

                {/* Info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-[11px] text-text-muted bg-bg-elevated rounded px-1.5 py-0.5">
                      {rule.rule_id}
                    </span>
                    <span className="text-sm font-semibold text-text-primary truncate">
                      {rule.name}
                    </span>
                  </div>
                  <div className="mt-1.5 flex items-center gap-3 flex-wrap">
                    <span
                      className={`inline-flex items-center rounded-md border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${
                        CATEGORY_COLORS[rule.category] ?? "border-border bg-bg-elevated text-text-muted"
                      }`}
                    >
                      {rule.category}
                    </span>
                    <span
                      className={`inline-flex items-center rounded-md border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${
                        ACTION_STYLES[rule.action] ?? ACTION_STYLES.log
                      }`}
                    >
                      {rule.action}
                    </span>
                    {priorityIndicator(rule.priority)}
                  </div>
                </div>

                {/* Expand */}
                <button
                  onClick={() => setExpandedId(expanded ? null : rule.id)}
                  className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md hover:bg-bg-elevated text-text-muted transition-colors"
                >
                  {expanded ? (
                    <ChevronUp className="h-4 w-4" />
                  ) : (
                    <ChevronDown className="h-4 w-4" />
                  )}
                </button>
              </div>

              {/* Expanded */}
              {expanded && (
                <div className="border-t border-border bg-bg-secondary/50 px-5 py-4 animate-fade-in">
                  <p className="text-sm text-text-secondary leading-relaxed">
                    {rule.description ?? "No description available."}
                  </p>
                  <div className="mt-3 flex flex-wrap gap-4 text-[11px] text-text-muted">
                    <span>Created: {new Date(rule.created_at).toLocaleDateString()}</span>
                    {rule.updated_at && (
                      <span>Updated: {new Date(rule.updated_at).toLocaleDateString()}</span>
                    )}
                  </div>
                </div>
              )}
            </div>
          );
        })}

        {filtered.length === 0 && (
          <div className="card p-12 text-center">
            <Shield className="mx-auto h-10 w-10 text-text-muted/40" />
            <p className="mt-3 text-sm text-text-muted">No rules match your search.</p>
          </div>
        )}
      </div>
    </div>
  );
}
