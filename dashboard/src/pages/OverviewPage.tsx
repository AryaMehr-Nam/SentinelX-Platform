/** SentinelX Dashboard — Overview Page */
import { useState, useEffect, useMemo } from "react";
import {
  Activity,
  ShieldAlert,
  ShieldBan,
  Gauge,
  TrendingUp,
  TrendingDown,
  Globe,
} from "lucide-react";
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { dashboardApi } from "../lib/api";
import type { DashboardOverview } from "../types";

/* ────────────────────────── Mock Data ────────────────────────── */

const MOCK: DashboardOverview = {
  total_requests_24h: 2_847_312,
  blocked_threats_24h: 14_829,
  active_blocked_ips: 1_247,
  global_risk_score: 72,
  threat_trend: [
    { time: "00:00", count: 312 },
    { time: "02:00", count: 189 },
    { time: "04:00", count: 143 },
    { time: "06:00", count: 267 },
    { time: "08:00", count: 589 },
    { time: "10:00", count: 823 },
    { time: "12:00", count: 1245 },
    { time: "14:00", count: 987 },
    { time: "16:00", count: 1567 },
    { time: "18:00", count: 2103 },
    { time: "20:00", count: 1834 },
    { time: "22:00", count: 1423 },
  ],
  top_threat_types: [
    { type: "SQL Injection", count: 4832 },
    { type: "XSS", count: 3421 },
    { type: "Path Traversal", count: 2156 },
    { type: "RCE", count: 1893 },
    { type: "Bot / Scraper", count: 1247 },
    { type: "DDoS L7", count: 987 },
    { type: "SSRF", count: 293 },
  ],
  top_source_countries: [
    { country: "CN", count: 3842 },
    { country: "RU", count: 2917 },
    { country: "US", count: 1823 },
    { country: "BR", count: 1456 },
    { country: "IN", count: 1102 },
    { country: "KR", count: 874 },
    { country: "DE", count: 531 },
    { country: "VN", count: 412 },
  ],
  severity_distribution: { critical: 1247, high: 3829, medium: 6453, low: 3300 },
};

const COUNTRY_NAMES: Record<string, string> = {
  CN: "China",
  RU: "Russia",
  US: "United States",
  BR: "Brazil",
  IN: "India",
  KR: "South Korea",
  DE: "Germany",
  VN: "Vietnam",
  IR: "Iran",
  ID: "Indonesia",
};

const COUNTRY_FLAGS: Record<string, string> = {
  CN: "🇨🇳",
  RU: "🇷🇺",
  US: "🇺🇸",
  BR: "🇧🇷",
  IN: "🇮🇳",
  KR: "🇰🇷",
  DE: "🇩🇪",
  VN: "🇻🇳",
  IR: "🇮🇷",
  ID: "🇮🇩",
};

/* ────────────────────────── Helpers ────────────────────────── */

function fmt(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString();
}

function severityColor(s: string): string {
  const map: Record<string, string> = {
    critical: "bg-severity-critical/15 text-severity-critical border-severity-critical/25",
    high: "bg-severity-high/15 text-severity-high border-severity-high/25",
    medium: "bg-severity-medium/15 text-severity-medium border-severity-medium/25",
    low: "bg-severity-low/15 text-severity-low border-severity-low/25",
  };
  return map[s] ?? map.low;
}

/* ────────────────────────── Sub-components ────────────────────────── */

interface MetricCardProps {
  icon: React.ReactNode;
  label: string;
  value: string;
  trend?: number;
  delay: number;
}

function MetricCard({ icon, label, value, trend, delay }: MetricCardProps) {
  const [visible, setVisible] = useState(false);
  useEffect(() => {
    const t = setTimeout(() => setVisible(true), delay);
    return () => clearTimeout(t);
  }, [delay]);

  return (
    <div
      className={`card p-5 transition-all duration-500 ease-out ${
        visible ? "translate-y-0 opacity-100" : "translate-y-4 opacity-0"
      }`}
    >
      <div className="flex items-start justify-between">
        <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-accent-indigo/10 text-accent-indigo">
          {icon}
        </div>
        {trend !== undefined && (
          <span
            className={`flex items-center gap-0.5 text-xs font-medium ${
              trend >= 0 ? "text-danger" : "text-success"
            }`}
          >
            {trend >= 0 ? (
              <TrendingUp className="h-3 w-3" />
            ) : (
              <TrendingDown className="h-3 w-3" />
            )}
            {Math.abs(trend)}%
          </span>
        )}
      </div>
      <p className="mt-4 text-2xl font-bold text-text-primary tracking-tight">{value}</p>
      <p className="mt-1 text-sm text-text-muted">{label}</p>
    </div>
  );
}

function RiskGauge({ score }: { score: number }) {
  const [animScore, setAnimScore] = useState(0);
  useEffect(() => {
    const t = setTimeout(() => setAnimScore(score), 400);
    return () => clearTimeout(t);
  }, [score]);

  const rotation = (animScore / 100) * 180;
  const color =
    score >= 75
      ? "var(--color-severity-critical)"
      : score >= 50
        ? "var(--color-warning)"
        : "var(--color-success)";

  return (
    <div className="card p-5 flex flex-col items-center justify-center transition-all duration-500">
      {/* Gauge */}
      <div className="relative h-28 w-56 overflow-hidden">
        {/* Background arc */}
        <div
          className="absolute bottom-0 left-0 h-56 w-56 rounded-full border-[10px] border-bg-elevated"
          style={{ clipPath: "inset(0 0 50% 0)" }}
        />
        {/* Filled arc */}
        <div
          className="absolute bottom-0 left-0 h-56 w-56 rounded-full border-[10px] border-transparent transition-transform duration-1000 ease-out"
          style={{
            borderBottomColor: color,
            borderLeftColor: color,
            transform: `rotate(${rotation}deg)`,
            clipPath: "inset(0 0 50% 0)",
          }}
        />
        {/* Needle center */}
        <div className="absolute bottom-0 left-1/2 -translate-x-1/2 flex flex-col items-center">
          <span className="text-3xl font-bold text-text-primary">{animScore}</span>
          <span className="text-[10px] uppercase tracking-widest text-text-muted">/ 100</span>
        </div>
      </div>
      <div className="mt-3 flex items-center gap-2">
        <Gauge className="h-4 w-4 text-text-muted" />
        <span className="text-sm text-text-muted">Global Risk Score</span>
      </div>
    </div>
  );
}

/* ────────────────────────── Chart Tooltip ────────────────────────── */

interface ChartTooltipProps {
  active?: boolean;
  payload?: Array<{ value: number; [key: string]: unknown }>;
  label?: string;
}

function ChartTooltip({ active, payload, label }: ChartTooltipProps) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg bg-bg-elevated/95 border border-border px-3 py-2 shadow-xl backdrop-blur-sm">
      <p className="text-xs text-text-muted">{label}</p>
      <p className="text-sm font-semibold text-text-primary">
        {payload[0].value.toLocaleString()} events
      </p>
    </div>
  );
}

/* ────────────────────────── Page ────────────────────────── */

export default function OverviewPage() {
  const [data, setData] = useState<DashboardOverview>(MOCK);

  useEffect(() => {
    dashboardApi
      .overview()
      .then((r) => {
        if (r.data && typeof r.data === "object") {
          setData((prev) => ({
            ...prev,
            ...r.data,
            top_source_countries: r.data.top_source_countries?.length ? r.data.top_source_countries : prev.top_source_countries,
            threat_trend: r.data.threat_trend?.length ? r.data.threat_trend : prev.threat_trend,
            top_threat_types: r.data.top_threat_types?.length ? r.data.top_threat_types : prev.top_threat_types,
            severity_distribution: Object.keys(r.data.severity_distribution || {}).length ? r.data.severity_distribution : prev.severity_distribution,
          }));
        }
      })
      .catch(() => {
        /* keep mock data */
      });
  }, []);

  const maxCountry = useMemo(
    () => Math.max(1, ...(data.top_source_countries ?? []).map((c) => c.count)),
    [data]
  );

  return (
    <div className="space-y-6 p-6">
      {/* ── Header ── */}
      <div>
        <h1 className="text-2xl font-bold text-text-primary tracking-tight">
          Dashboard Overview
        </h1>
        <p className="mt-1 text-sm text-text-muted">
          Real-time security posture · Last 24 hours
        </p>
      </div>

      {/* ── Metric Cards ── */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <MetricCard
          icon={<Activity className="h-5 w-5" />}
          label="Total Requests (24h)"
          value={fmt(data.total_requests_24h)}
          trend={12}
          delay={0}
        />
        <MetricCard
          icon={<ShieldAlert className="h-5 w-5" />}
          label="Blocked Threats"
          value={fmt(data.blocked_threats_24h)}
          trend={8}
          delay={80}
        />
        <MetricCard
          icon={<ShieldBan className="h-5 w-5" />}
          label="Active Blocked IPs"
          value={fmt(data.active_blocked_ips)}
          trend={-3}
          delay={160}
        />
        <RiskGauge score={data.global_risk_score} />
      </div>

      {/* ── Charts Row ── */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        {/* Attack Trend */}
        <div className="card p-5 lg:col-span-2 animate-fade-in">
          <h2 className="mb-4 text-sm font-semibold text-text-secondary">
            Attack Trend (24h)
          </h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={data.threat_trend}>
                <defs>
                  <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#6366F1" stopOpacity={0.3} />
                    <stop offset="100%" stopColor="#6366F1" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="rgba(255,255,255,0.04)" strokeDasharray="3 3" />
                <XAxis
                  dataKey="time"
                  tick={{ fill: "#5A6178", fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fill: "#5A6178", fontSize: 11 }}
                  axisLine={false}
                  tickLine={false}
                  width={40}
                />
                <Tooltip content={<ChartTooltip />} />
                <Area
                  type="monotone"
                  dataKey="count"
                  stroke="#6366F1"
                  strokeWidth={2}
                  fill="url(#trendFill)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Threat Type Distribution */}
        <div className="card p-5 animate-fade-in">
          <h2 className="mb-4 text-sm font-semibold text-text-secondary">
            Threat Types
          </h2>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={data.top_threat_types} layout="vertical">
                <CartesianGrid stroke="rgba(255,255,255,0.04)" strokeDasharray="3 3" />
                <XAxis
                  type="number"
                  tick={{ fill: "#5A6178", fontSize: 10 }}
                  axisLine={false}
                  tickLine={false}
                />
                <YAxis
                  dataKey="type"
                  type="category"
                  tick={{ fill: "#8B92A8", fontSize: 10 }}
                  axisLine={false}
                  tickLine={false}
                  width={90}
                />
                <Tooltip content={<ChartTooltip />} />
                <Bar dataKey="count" fill="#8B5CF6" radius={[0, 4, 4, 0]} barSize={16} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* ── Bottom Row ── */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Top Source Countries */}
        <div className="card p-5 animate-fade-in">
          <h2 className="mb-4 flex items-center gap-2 text-sm font-semibold text-text-secondary">
            <Globe className="h-4 w-4" />
            Top Source Countries
          </h2>
          <div className="space-y-3">
            {data.top_source_countries.map((c) => (
              <div key={c.country} className="flex items-center gap-3">
                <span className="text-lg leading-none">
                  {COUNTRY_FLAGS[c.country] ?? "🏳️"}
                </span>
                <span className="w-24 text-sm text-text-secondary truncate">
                  {COUNTRY_NAMES[c.country] ?? c.country}
                </span>
                <div className="flex-1 h-2 rounded-full bg-bg-elevated overflow-hidden">
                  <div
                    className="h-full rounded-full bg-gradient-to-r from-accent-indigo to-accent-purple transition-all duration-700"
                    style={{ width: `${(c.count / maxCountry) * 100}%` }}
                  />
                </div>
                <span className="w-14 text-right text-xs font-mono text-text-muted">
                  {fmt(c.count)}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Severity Distribution */}
        <div className="card p-5 animate-fade-in">
          <h2 className="mb-4 text-sm font-semibold text-text-secondary">
            Severity Distribution
          </h2>
          <div className="grid grid-cols-2 gap-4">
            {Object.entries(data.severity_distribution).map(([sev, count]) => {
              const total = Object.values(data.severity_distribution).reduce(
                (a, b) => a + b,
                0
              );
              const pct = total > 0 ? ((count / total) * 100).toFixed(1) : "0.0";
              return (
                <div key={sev} className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span
                      className={`inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wider ${severityColor(
                        sev
                      )}`}
                    >
                      {sev}
                    </span>
                    <span className="text-xs text-text-muted">{pct}%</span>
                  </div>
                  <p className="text-xl font-bold text-text-primary">{fmt(count)}</p>
                  <div className="h-1.5 rounded-full bg-bg-elevated overflow-hidden">
                    <div
                      className="h-full rounded-full transition-all duration-700"
                      style={{
                        width: `${pct}%`,
                        backgroundColor:
                          sev === "critical"
                            ? "var(--color-severity-critical)"
                            : sev === "high"
                              ? "var(--color-severity-high)"
                              : sev === "medium"
                                ? "var(--color-severity-medium)"
                                : "var(--color-severity-low)",
                      }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
