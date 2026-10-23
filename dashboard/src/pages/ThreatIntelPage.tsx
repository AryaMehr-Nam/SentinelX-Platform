/** SentinelX Dashboard — Threat Intelligence Page */
import { useState, useEffect } from "react";
import {
  Brain,
  Globe,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  Zap,
  ExternalLink,
  TrendingUp,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { threatApi } from "../lib/api";
import type { PhishingDomain, AIThreatSummary } from "../types";

/* ────────────────────────── Mock Data ────────────────────────── */

const MOCK_DOMAINS: PhishingDomain[] = [
  { id: "d1", domain: "paypa1-security-update.com", status: "confirmed", risk_score: 96, created_at: "2026-06-05T18:23:00Z", reviewed_at: "2026-06-05T19:01:00Z" },
  { id: "d2", domain: "amaz0n-prime-verify.net", status: "confirmed", risk_score: 94, created_at: "2026-06-05T16:45:00Z", reviewed_at: "2026-06-05T17:12:00Z" },
  { id: "d3", domain: "micros0ft-365-login.org", status: "pending", risk_score: 89, created_at: "2026-06-05T15:30:00Z" },
  { id: "d4", domain: "g00gle-drive-share.co", status: "confirmed", risk_score: 92, created_at: "2026-06-05T14:12:00Z", reviewed_at: "2026-06-05T14:45:00Z" },
  { id: "d5", domain: "netlfix-billing-update.com", status: "pending", risk_score: 78, created_at: "2026-06-05T12:55:00Z" },
  { id: "d6", domain: "dropb0x-file-shared.net", status: "false_positive", risk_score: 15, created_at: "2026-06-05T11:20:00Z", reviewed_at: "2026-06-05T12:00:00Z" },
  { id: "d7", domain: "app1e-id-verification.co", status: "confirmed", risk_score: 97, created_at: "2026-06-05T10:08:00Z", reviewed_at: "2026-06-05T10:30:00Z" },
  { id: "d8", domain: "slack-workspace-invite.org", status: "pending", risk_score: 64, created_at: "2026-06-05T08:41:00Z" },
  { id: "d9", domain: "linkedln-profile-view.com", status: "confirmed", risk_score: 91, created_at: "2026-06-05T07:15:00Z", reviewed_at: "2026-06-05T07:55:00Z" },
  { id: "d10", domain: "zoom-meeting-join.net", status: "false_positive", risk_score: 22, created_at: "2026-06-05T06:00:00Z", reviewed_at: "2026-06-05T06:30:00Z" },
];

const MOCK_SUMMARIES: AIThreatSummary[] = [
  {
    id: "ai1",
    waf_log_id: "log-5421",
    threat_classification: "SQL Injection — Union-based extraction",
    human_readable_explanation:
      "Attacker attempted a UNION-based SQL injection targeting the user search endpoint. The payload tried to extract database schema information by appending UNION SELECT statements with information_schema queries. The WAF's ML model detected the anomalous query structure and blocked the request before it reached the database layer.",
    estimated_severity: "critical",
    estimated_impact: "Full database compromise, potential data exfiltration of user PII",
    mitigation_strategies: [
      "Parameterize all database queries",
      "Implement input validation with strict allowlists",
      "Deploy database activity monitoring",
      "Restrict database user permissions to least-privilege",
    ],
    llm_provider: "OpenAI",
    llm_model: "gpt-4o",
    analysis_duration_ms: 1247,
    created_at: "2026-06-05T19:12:00Z",
  },
  {
    id: "ai2",
    waf_log_id: "log-5418",
    threat_classification: "Server-Side Request Forgery (SSRF)",
    human_readable_explanation:
      "A sophisticated SSRF attempt was detected targeting an internal API proxy endpoint. The attacker manipulated the URL parameter to access the AWS metadata service at 169.254.169.254, attempting to steal IAM role credentials. This is a classic cloud infrastructure attack vector.",
    estimated_severity: "critical",
    estimated_impact: "Cloud credential theft, lateral movement within AWS infrastructure",
    mitigation_strategies: [
      "Block requests to internal IP ranges (169.254.x.x, 10.x.x.x)",
      "Implement URL allowlisting for proxy endpoints",
      "Use IMDSv2 for AWS metadata service",
      "Network segmentation for internal services",
    ],
    llm_provider: "Anthropic",
    llm_model: "claude-sonnet-4-20250514",
    analysis_duration_ms: 983,
    created_at: "2026-06-05T18:45:00Z",
  },
  {
    id: "ai3",
    waf_log_id: "log-5402",
    threat_classification: "Credential Stuffing Campaign",
    human_readable_explanation:
      "Detected a coordinated credential stuffing attack from a botnet spanning 47 unique IPs across 12 countries. The attack used a rotating user-agent list and varied request timing to evade rate limiting. Over 2,400 login attempts were made in a 15-minute window using leaked credentials from a known data breach.",
    estimated_severity: "high",
    estimated_impact: "Account takeover, unauthorized access to user accounts",
    mitigation_strategies: [
      "Enforce multi-factor authentication (MFA)",
      "Implement progressive rate limiting per IP and account",
      "Deploy CAPTCHA after failed login attempts",
      "Cross-reference with HaveIBeenPwned API",
    ],
    llm_provider: "OpenAI",
    llm_model: "gpt-4o",
    analysis_duration_ms: 2134,
    created_at: "2026-06-05T17:30:00Z",
  },
  {
    id: "ai4",
    waf_log_id: "log-5389",
    threat_classification: "Cross-Site Scripting — DOM-based",
    human_readable_explanation:
      "An advanced DOM-based XSS payload was injected via the search query parameter. The payload utilized JavaScript template literals and event handler attributes to bypass the existing content security policy. The attack targeted session cookie theft via a base64-encoded exfiltration URL.",
    estimated_severity: "high",
    estimated_impact: "Session hijacking, cookie theft, potential account takeover",
    mitigation_strategies: [
      "Implement strict Content-Security-Policy headers",
      "Use HttpOnly and Secure flags on all cookies",
      "Enable output encoding for all user-supplied data",
      "Deploy subresource integrity (SRI) for third-party scripts",
    ],
    llm_provider: "Anthropic",
    llm_model: "claude-sonnet-4-20250514",
    analysis_duration_ms: 876,
    created_at: "2026-06-05T16:15:00Z",
  },
];

const TREND_DATA = [
  { date: "May 30", phishing: 12, malware: 8, botnet: 15 },
  { date: "May 31", phishing: 18, malware: 11, botnet: 22 },
  { date: "Jun 01", phishing: 14, malware: 6, botnet: 19 },
  { date: "Jun 02", phishing: 23, malware: 14, botnet: 28 },
  { date: "Jun 03", phishing: 31, malware: 19, botnet: 25 },
  { date: "Jun 04", phishing: 27, malware: 16, botnet: 32 },
  { date: "Jun 05", phishing: 35, malware: 22, botnet: 29 },
];

/* ────────────────────────── Helpers ────────────────────────── */

function statusBadge(status: PhishingDomain["status"]) {
  const map = {
    confirmed: { icon: XCircle, cls: "bg-danger/15 text-danger border-danger/30", label: "Confirmed" },
    pending: { icon: Clock, cls: "bg-warning/15 text-warning border-warning/30", label: "Pending" },
    false_positive: { icon: CheckCircle2, cls: "bg-success/15 text-success border-success/30", label: "Safe" },
  };
  const s = map[status];
  const Icon = s.icon;
  return (
    <span className={`inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${s.cls}`}>
      <Icon className="h-3 w-3" />
      {s.label}
    </span>
  );
}

function riskColor(score: number): string {
  if (score >= 80) return "text-severity-critical";
  if (score >= 60) return "text-severity-high";
  if (score >= 40) return "text-severity-medium";
  return "text-severity-low";
}

function sevBadge(sev: string) {
  const m: Record<string, string> = {
    critical: "bg-severity-critical/15 text-severity-critical border-severity-critical/30",
    high: "bg-severity-high/15 text-severity-high border-severity-high/30",
    medium: "bg-severity-medium/15 text-severity-medium border-severity-medium/30",
    low: "bg-severity-low/15 text-severity-low border-severity-low/30",
  };
  return (
    <span className={`inline-flex items-center rounded-md border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${m[sev] ?? m.medium}`}>
      {sev}
    </span>
  );
}

function fmtRelative(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  return `${Math.floor(hrs / 24)}d ago`;
}

interface ThreatChartTooltipProps {
  active?: boolean;
  payload?: Array<{ dataKey: string; value: number | string; color?: string }>;
  label?: string;
}

function ChartTooltip({ active, payload, label }: ThreatChartTooltipProps) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg bg-bg-elevated/95 border border-border px-3 py-2 shadow-xl backdrop-blur-sm">
      <p className="text-xs font-medium text-text-secondary mb-1">{label}</p>
      {payload.map((p) => (
        <p key={p.dataKey} className="text-xs" style={{ color: p.color }}>
          {p.dataKey}: {p.value}
        </p>
      ))}
    </div>
  );
}

/* ────────────────────────── Page ────────────────────────── */

export default function ThreatIntelPage() {
  const [domains, setDomains] = useState<PhishingDomain[]>(MOCK_DOMAINS);
  const [summaries, setSummaries] = useState<AIThreatSummary[]>(MOCK_SUMMARIES);
  const [mounted, setMounted] = useState(false);

  useEffect(() => { setMounted(true); }, []);

  useEffect(() => {
    threatApi.domains().then((r) => {
      const list = Array.isArray(r.data) ? r.data : r.data?.domains;
      if (Array.isArray(list) && list.length) setDomains(list);
    }).catch(() => {});

    threatApi.aiSummaries().then((r) => {
      const list = Array.isArray(r.data) ? r.data : r.data?.summaries;
      if (Array.isArray(list) && list.length) setSummaries(list);
    }).catch(() => {});
  }, []);

  return (
    <div className={`space-y-6 p-6 transition-all duration-500 ${mounted ? "opacity-100" : "opacity-0"}`}>
      {/* Header */}
      <div>
        <h1 className="flex items-center gap-2 text-2xl font-bold text-text-primary tracking-tight">
          <Brain className="h-6 w-6 text-accent-purple" />
          Threat Intelligence
        </h1>
        <p className="mt-1 text-sm text-text-muted">
          AI-powered threat analysis and phishing domain monitoring
        </p>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-4">
        {[
          { label: "Reported Domains", value: domains.length.toString(), icon: Globe, color: "text-accent-cyan" },
          { label: "Confirmed Threats", value: domains.filter(d => d.status === "confirmed").length.toString(), icon: AlertTriangle, color: "text-danger" },
          { label: "Pending Review", value: domains.filter(d => d.status === "pending").length.toString(), icon: Clock, color: "text-warning" },
          { label: "AI Analyses", value: summaries.length.toString(), icon: Zap, color: "text-accent-purple" },
        ].map((s, i) => (
          <div
            key={s.label}
            className="card p-4"
            style={{ animation: `fadeIn 0.4s ease-out ${i * 80}ms both` }}
          >
            <div className="flex items-center gap-3">
              <div className={`flex h-9 w-9 items-center justify-center rounded-lg bg-bg-elevated ${s.color}`}>
                <s.icon className="h-4.5 w-4.5" />
              </div>
              <div>
                <p className="text-xl font-bold text-text-primary">{s.value}</p>
                <p className="text-xs text-text-muted">{s.label}</p>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-3">
        {/* ── Reported Domains Table ── */}
        <div className="card overflow-hidden xl:col-span-2 animate-fade-in">
          <div className="border-b border-border px-5 py-4">
            <h2 className="flex items-center gap-2 text-sm font-semibold text-text-secondary">
              <Globe className="h-4 w-4" />
              Reported Phishing Domains
            </h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border bg-bg-elevated/50">
                  {["Domain", "Status", "Risk", "Reported", "Reviewed"].map(h => (
                    <th key={h} className="px-5 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-text-muted">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {domains.map(d => (
                  <tr key={d.id} className="hover:bg-bg-hover/50 transition-colors">
                    <td className="px-5 py-3">
                      <span className="flex items-center gap-1.5 font-mono text-xs text-text-primary">
                        {d.domain}
                        <ExternalLink className="h-3 w-3 text-text-muted" />
                      </span>
                    </td>
                    <td className="px-5 py-3">{statusBadge(d.status)}</td>
                    <td className="px-5 py-3">
                      <span className={`font-mono text-sm font-bold ${riskColor(d.risk_score ?? 0)}`}>
                        {d.risk_score ?? "—"}
                      </span>
                    </td>
                    <td className="px-5 py-3 text-xs text-text-muted">{fmtRelative(d.created_at)}</td>
                    <td className="px-5 py-3 text-xs text-text-muted">{d.reviewed_at ? fmtRelative(d.reviewed_at) : "—"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* ── Threat Trend Chart ── */}
        <div className="card p-5 animate-fade-in">
          <h2 className="mb-4 flex items-center gap-2 text-sm font-semibold text-text-secondary">
            <TrendingUp className="h-4 w-4" />
            Threat Trend (7 days)
          </h2>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={TREND_DATA}>
                <defs>
                  <linearGradient id="fillPhishing" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#EF4444" stopOpacity={0.2} />
                    <stop offset="100%" stopColor="#EF4444" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="fillMalware" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#8B5CF6" stopOpacity={0.2} />
                    <stop offset="100%" stopColor="#8B5CF6" stopOpacity={0} />
                  </linearGradient>
                  <linearGradient id="fillBotnet" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#06B6D4" stopOpacity={0.2} />
                    <stop offset="100%" stopColor="#06B6D4" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="rgba(255,255,255,0.04)" strokeDasharray="3 3" />
                <XAxis dataKey="date" tick={{ fill: "#5A6178", fontSize: 10 }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fill: "#5A6178", fontSize: 10 }} axisLine={false} tickLine={false} width={30} />
                <Tooltip content={<ChartTooltip />} />
                <Area type="monotone" dataKey="phishing" stroke="#EF4444" strokeWidth={2} fill="url(#fillPhishing)" />
                <Area type="monotone" dataKey="malware" stroke="#8B5CF6" strokeWidth={2} fill="url(#fillMalware)" />
                <Area type="monotone" dataKey="botnet" stroke="#06B6D4" strokeWidth={2} fill="url(#fillBotnet)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-3 flex items-center justify-center gap-4">
            {[
              { label: "Phishing", color: "#EF4444" },
              { label: "Malware", color: "#8B5CF6" },
              { label: "Botnet", color: "#06B6D4" },
            ].map(l => (
              <span key={l.label} className="flex items-center gap-1.5 text-[11px] text-text-muted">
                <span className="h-2 w-2 rounded-full" style={{ backgroundColor: l.color }} />
                {l.label}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* ── AI Analysis Cards ── */}
      <div>
        <h2 className="mb-4 flex items-center gap-2 text-sm font-semibold text-text-secondary">
          <Brain className="h-4 w-4 text-accent-purple" />
          AI Threat Analysis
        </h2>
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {summaries.map((s, i) => (
            <div
              key={s.id}
              className="card overflow-hidden"
              style={{ animation: `fadeIn 0.4s ease-out ${i * 100}ms both` }}
            >
              {/* Header */}
              <div className="flex items-start justify-between border-b border-border px-5 py-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    {sevBadge(s.estimated_severity)}
                    <span className="text-sm font-semibold text-text-primary truncate">
                      {s.threat_classification}
                    </span>
                  </div>
                  <p className="mt-1 flex items-center gap-3 text-[11px] text-text-muted">
                    <span>Log: {s.waf_log_id}</span>
                    <span>·</span>
                    <span>{s.llm_model}</span>
                    <span>·</span>
                    <span>{s.analysis_duration_ms}ms</span>
                    <span>·</span>
                    <span>{fmtRelative(s.created_at)}</span>
                  </p>
                </div>
              </div>

              {/* Body */}
              <div className="px-5 py-4 space-y-3">
                <p className="text-sm text-text-secondary leading-relaxed">
                  {s.human_readable_explanation}
                </p>

                {s.estimated_impact && (
                  <div className="rounded-lg bg-danger/5 border border-danger/15 px-3 py-2">
                    <p className="text-[11px] font-semibold uppercase tracking-wider text-danger mb-0.5">
                      Potential Impact
                    </p>
                    <p className="text-xs text-text-secondary">{s.estimated_impact}</p>
                  </div>
                )}

                {s.mitigation_strategies && s.mitigation_strategies.length > 0 && (
                  <div>
                    <p className="text-[11px] font-semibold uppercase tracking-wider text-text-muted mb-1.5">
                      Mitigation Strategies
                    </p>
                    <ul className="space-y-1">
                      {s.mitigation_strategies.map((m, mi) => (
                        <li key={mi} className="flex items-start gap-2 text-xs text-text-secondary">
                          <CheckCircle2 className="mt-0.5 h-3 w-3 shrink-0 text-success" />
                          {m}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
