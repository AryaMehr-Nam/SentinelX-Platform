/** SentinelX Dashboard — Attack Stream Page */
import { useState, useEffect, useCallback, useMemo } from "react";
import {
  Search,
  RefreshCw,
  ChevronLeft,
  ChevronRight,
  Radio,
  Filter,
  Clock,
  Zap,
  Square,
} from "lucide-react";
import { dashboardApi, simulatorApi } from "../lib/api";
import type { AttackStreamEntry } from "../types";

/* ────────────────────────── Mock Data ────────────────────────── */

const THREAT_TYPES = [
  "SQL Injection",
  "XSS Reflected",
  "XSS Stored",
  "Path Traversal",
  "Remote Code Exec",
  "SSRF",
  "Command Injection",
  "Bot / Scraper",
  "Credential Stuffing",
  "DDoS L7",
  "LDAP Injection",
  "XXE",
] as const;

const PATHS = [
  "/api/v1/users?id=1' OR 1=1--",
  "/search?q=<script>alert(1)</script>",
  "/admin/../../../../etc/passwd",
  "/api/v1/exec?cmd=whoami",
  "/wp-login.php",
  "/api/internal/ssrf?url=http://169.254.169.254",
  "/.env",
  "/graphql",
  "/api/v1/auth/login",
  "/actuator/health",
  "/debug/pprof",
  "/api/v1/upload",
  "/.git/config",
  "/xmlrpc.php",
  "/api/v1/tokens/refresh",
];

const IPS = [
  "185.220.101.34",
  "45.155.205.99",
  "192.241.220.183",
  "103.75.190.12",
  "5.188.206.71",
  "91.240.118.172",
  "23.129.64.210",
  "194.163.128.89",
  "162.247.74.204",
  "198.98.56.11",
  "176.111.174.26",
  "89.248.167.131",
  "167.71.13.196",
  "104.248.85.203",
  "138.68.3.71",
  "209.141.33.152",
  "77.247.181.165",
  "185.100.86.74",
  "171.25.193.77",
  "199.19.226.28",
];

const COUNTRIES = ["CN", "RU", "US", "BR", "DE", "KR", "IN", "VN", "IR", "NL", "GB", "FR"];
const SEVERITIES = ["critical", "high", "medium", "low"] as const;
const ACTIONS = ["blocked", "logged", "challenged"] as const;
const RULES = ["WAF-001", "WAF-012", "WAF-034", "WAF-056", "WAF-078", "WAF-091", "WAF-105", "ML-AUTO"];

function rand<T>(arr: readonly T[]): T {
  return arr[Math.floor(Math.random() * arr.length)];
}

function makeMockEntry(i: number): AttackStreamEntry {
  const now = Date.now();
  return {
    id: `atk-${1000 + i}`,
    timestamp: new Date(now - i * 4300 - Math.random() * 2000).toISOString(),
    source_ip: rand(IPS),
    country_code: rand(COUNTRIES),
    threat_type: rand(THREAT_TYPES),
    severity: rand(SEVERITIES),
    request_path: rand(PATHS),
    action_taken: rand(ACTIONS),
    matched_rule_id: rand(RULES),
  };
}

const MOCK_DATA: AttackStreamEntry[] = Array.from({ length: 200 }, (_, i) =>
  makeMockEntry(i)
);

/* ────────────────────────── Helpers ────────────────────────── */

const COUNTRY_FLAGS: Record<string, string> = {
  CN: "🇨🇳", RU: "🇷🇺", US: "🇺🇸", BR: "🇧🇷", DE: "🇩🇪", KR: "🇰🇷",
  IN: "🇮🇳", VN: "🇻🇳", IR: "🇮🇷", NL: "🇳🇱", GB: "🇬🇧", FR: "🇫🇷",
};

function severityBadge(s: string) {
  const styles: Record<string, string> = {
    critical: "bg-severity-critical/15 text-severity-critical border-severity-critical/30",
    high: "bg-severity-high/15 text-severity-high border-severity-high/30",
    medium: "bg-severity-medium/15 text-severity-medium border-severity-medium/30",
    low: "bg-severity-low/15 text-severity-low border-severity-low/30",
  };
  return (
    <span
      className={`inline-flex items-center rounded-md border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${
        styles[s] ?? styles.low
      }`}
    >
      {s}
    </span>
  );
}

function actionBadge(a: string) {
  const styles: Record<string, string> = {
    blocked: "bg-danger/15 text-danger border-danger/30",
    logged: "bg-accent-blue/15 text-accent-blue border-accent-blue/30",
    challenged: "bg-warning/15 text-warning border-warning/30",
  };
  return (
    <span
      className={`inline-flex items-center rounded-md border px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider ${
        styles[a] ?? styles.logged
      }`}
    >
      {a}
    </span>
  );
}

function fmtTime(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleTimeString("en-US", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });
}

/* ────────────────────────── Page ────────────────────────── */

const PAGE_SIZE = 20;
const INTERVALS = [5, 10, 30, 60];

export default function AttackStreamPage() {
  const [allData, setAllData] = useState<AttackStreamEntry[]>(MOCK_DATA);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [page, setPage] = useState(1);
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [refreshInterval, setRefreshInterval] = useState(10);
  const [lastUpdate, setLastUpdate] = useState(new Date());
  const [wsConnected, setWsConnected] = useState(false);
  const [mounted, setMounted] = useState(false);
  const [simulatorRunning, setSimulatorRunning] = useState(false);
  const [simulatorLoading, setSimulatorLoading] = useState(false);

  useEffect(() => { setMounted(true); }, []);

  useEffect(() => {
    simulatorApi.status().then((r) => {
      if (r.data?.running !== undefined) {
        setSimulatorRunning(r.data.running);
      }
    }).catch(() => {});
  }, []);

  const toggleSimulator = async () => {
    setSimulatorLoading(true);
    try {
      if (simulatorRunning) {
        await simulatorApi.stop();
        setSimulatorRunning(false);
      } else {
        await simulatorApi.start(2.0);
        setSimulatorRunning(true);
      }
    } catch {
      setSimulatorRunning((prev) => !prev);
    } finally {
      setSimulatorLoading(false);
    }
  };

  /* Real-time WebSocket connection to SentinelX live stream */
  useEffect(() => {
    const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
    const host = window.location.host;
    const wsUrl = `${protocol}//${host}/api/v1/ws/attack-stream`;

    let ws: WebSocket | null = null;
    let pingInterval: ReturnType<typeof setInterval>;
    let reconnectTimeout: ReturnType<typeof setTimeout>;

    const connect = () => {
      try {
        ws = new WebSocket(wsUrl);
        ws.onopen = () => {
          setWsConnected(true);
          pingInterval = setInterval(() => {
            if (ws && ws.readyState === WebSocket.OPEN) {
              ws.send(JSON.stringify({ action: "ping" }));
            }
          }, 30000);
        };
        ws.onmessage = (event) => {
          try {
            const payload = JSON.parse(event.data);
            if (payload.type === "ATTACK_EVENT" && payload.data) {
              setAllData((prev) => [payload.data, ...prev.slice(0, 499)]);
              setLastUpdate(new Date());
            }
          } catch {
            // non-json or ping/pong
          }
        };
        ws.onclose = () => {
          setWsConnected(false);
          clearInterval(pingInterval);
          reconnectTimeout = setTimeout(connect, 4000);
        };
        ws.onerror = () => {
          setWsConnected(false);
        };
      } catch {
        setWsConnected(false);
      }
    };

    connect();

    return () => {
      clearInterval(pingInterval);
      clearTimeout(reconnectTimeout);
      if (ws) ws.close();
    };
  }, []);

  /* Fetch from API or regenerate mock data */
  const refresh = useCallback(() => {
    dashboardApi
      .attackStream()
      .then((r) => {
        const events = r.data?.events ?? r.data;
        if (Array.isArray(events) && events.length) setAllData(events);
        else setAllData(Array.from({ length: 200 }, (_, i) => makeMockEntry(i)));
      })
      .catch(() => {
        setAllData((prev) => prev.length ? prev : Array.from({ length: 200 }, (_, i) => makeMockEntry(i)));
      });
    setLastUpdate(new Date());
  }, []);

  useEffect(() => {
    if (!autoRefresh || wsConnected) return;
    const id = setInterval(refresh, refreshInterval * 1000);
    return () => clearInterval(id);
  }, [autoRefresh, refreshInterval, refresh, wsConnected]);

  /* Filter + search */
  const filtered = useMemo(() => {
    let result = allData;
    if (severityFilter !== "all") {
      result = result.filter((e) => e.severity === severityFilter);
    }
    if (search.trim()) {
      const q = search.toLowerCase();
      result = result.filter(
        (e) =>
          e.source_ip.includes(q) ||
          e.threat_type.toLowerCase().includes(q) ||
          e.request_path.toLowerCase().includes(q) ||
          (e.country_code ?? "").toLowerCase().includes(q) ||
          (e.matched_rule_id ?? "").toLowerCase().includes(q)
      );
    }
    return result;
  }, [allData, severityFilter, search]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / PAGE_SIZE));
  const pageData = filtered.slice((page - 1) * PAGE_SIZE, page * PAGE_SIZE);

  useEffect(() => {
    setPage(1);
  }, [search, severityFilter]);

  return (
    <div
      className={`space-y-5 p-6 transition-all duration-500 ${
        mounted ? "opacity-100" : "opacity-0"
      }`}
    >
      {/* ── Header ── */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="flex items-center gap-2 text-2xl font-bold text-text-primary tracking-tight">
              <Radio className="h-5 w-5 text-danger animate-pulse" />
              Live Attack Stream
            </h1>
            {wsConnected ? (
              <span className="inline-flex items-center gap-1.5 rounded-full bg-success/15 border border-success/30 px-2.5 py-0.5 text-[11px] font-semibold text-success">
                <span className="h-1.5 w-1.5 rounded-full bg-success animate-ping" />
                Live WebSocket
              </span>
            ) : (
              <span className="inline-flex items-center gap-1.5 rounded-full bg-warning/10 border border-warning/20 px-2 py-0.5 text-[10px] font-medium text-warning">
                Polling Fallback
              </span>
            )}
          </div>
          <p className="mt-1 text-sm text-text-muted">
            Showing {filtered.length} events · Updated{" "}
            {lastUpdate.toLocaleTimeString()}
          </p>
        </div>

        {/* Auto-refresh & Simulator controls */}
        <div className="flex flex-wrap items-center gap-2.5">
          {/* Attack Simulator Live Toggle */}
          <button
            onClick={toggleSimulator}
            disabled={simulatorLoading}
            className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-semibold transition-all shadow-sm cursor-pointer ${
              simulatorRunning
                ? "border-danger/40 bg-danger/15 text-danger shadow-danger/20 hover:bg-danger/25"
                : "border-accent-purple/40 bg-accent-purple/15 text-accent-purple shadow-accent-purple/20 hover:bg-accent-purple/25"
            }`}
            title={simulatorRunning ? "Stop background attack simulation" : "Start live attack telemetry simulator"}
          >
            {simulatorRunning ? (
              <>
                <span className="relative flex h-2 w-2">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-danger opacity-75" />
                  <span className="relative inline-flex rounded-full h-2 w-2 bg-danger" />
                </span>
                <Square className="h-3 w-3 fill-current" />
                <span>Stop Attack Sim</span>
              </>
            ) : (
              <>
                <Zap className="h-3.5 w-3.5 text-accent-purple" />
                <span>Simulate Attacks</span>
              </>
            )}
          </button>

          <div className="flex items-center gap-2 rounded-lg border border-border bg-bg-card px-3 py-1.5 text-sm">
            <Clock className="h-3.5 w-3.5 text-text-muted" />
            <select
              value={refreshInterval}
              onChange={(e) => setRefreshInterval(Number(e.target.value))}
              className="bg-transparent text-text-secondary text-xs outline-none cursor-pointer"
            >
              {INTERVALS.map((s) => (
                <option key={s} value={s}>
                  {s}s
                </option>
              ))}
            </select>
          </div>
          <button
            onClick={() => setAutoRefresh(!autoRefresh)}
            className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs font-medium transition-colors cursor-pointer ${
              autoRefresh
                ? "border-success/30 bg-success/10 text-success"
                : "border-border bg-bg-card text-text-muted"
            }`}
          >
            <RefreshCw
              className={`h-3.5 w-3.5 ${autoRefresh ? "animate-spin" : ""}`}
              style={autoRefresh ? { animationDuration: "3s" } : undefined}
            />
            {autoRefresh ? "Live" : "Paused"}
          </button>
          <button
            onClick={refresh}
            className="flex items-center gap-1.5 rounded-lg border border-border bg-bg-card px-3 py-1.5 text-xs font-medium text-text-secondary hover:bg-bg-elevated transition-colors cursor-pointer"
          >
            <RefreshCw className="h-3.5 w-3.5" />
            Refresh
          </button>
        </div>
      </div>

      {/* ── Filters ── */}
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-text-muted" />
          <input
            type="text"
            placeholder="Search IPs, paths, threat types, rules…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full rounded-lg border border-border bg-bg-card pl-10 pr-4 py-2 text-sm text-text-primary placeholder:text-text-muted outline-none focus:border-accent-indigo/50 focus:ring-1 focus:ring-accent-indigo/30 transition-colors"
          />
        </div>
        <div className="flex items-center gap-2">
          <Filter className="h-4 w-4 text-text-muted" />
          {["all", ...SEVERITIES].map((s) => (
            <button
              key={s}
              onClick={() => setSeverityFilter(s)}
              className={`rounded-md border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-wider transition-colors ${
                severityFilter === s
                  ? s === "all"
                    ? "border-accent-indigo/30 bg-accent-indigo/15 text-accent-indigo"
                    : s === "critical"
                      ? "border-severity-critical/30 bg-severity-critical/15 text-severity-critical"
                      : s === "high"
                        ? "border-severity-high/30 bg-severity-high/15 text-severity-high"
                        : s === "medium"
                          ? "border-severity-medium/30 bg-severity-medium/15 text-severity-medium"
                          : "border-severity-low/30 bg-severity-low/15 text-severity-low"
                  : "border-border bg-bg-card text-text-muted hover:bg-bg-elevated"
              }`}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      {/* ── Table ── */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-bg-elevated/50">
                {[
                  "Time",
                  "Source IP",
                  "Country",
                  "Threat Type",
                  "Severity",
                  "Path",
                  "Action",
                  "Rule",
                ].map((h) => (
                  <th
                    key={h}
                    className="px-4 py-3 text-left text-[11px] font-semibold uppercase tracking-wider text-text-muted"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {pageData.map((entry, idx) => (
                <tr
                  key={entry.id}
                  className="hover:bg-bg-hover/50 transition-colors"
                  style={{
                    animation: `fadeIn 0.3s ease-out ${idx * 20}ms both`,
                  }}
                >
                  <td className="px-4 py-2.5 font-mono text-xs text-text-muted whitespace-nowrap">
                    {fmtTime(entry.timestamp)}
                  </td>
                  <td className="px-4 py-2.5 font-mono text-xs text-text-primary whitespace-nowrap">
                    {entry.source_ip}
                  </td>
                  <td className="px-4 py-2.5 whitespace-nowrap">
                    <span className="flex items-center gap-1.5 text-xs text-text-secondary">
                      <span>{COUNTRY_FLAGS[entry.country_code ?? ""] ?? "🏳️"}</span>
                      {entry.country_code}
                    </span>
                  </td>
                  <td className="px-4 py-2.5 text-xs text-text-secondary whitespace-nowrap">
                    {entry.threat_type}
                  </td>
                  <td className="px-4 py-2.5 whitespace-nowrap">
                    {severityBadge(entry.severity)}
                  </td>
                  <td className="px-4 py-2.5 max-w-[260px] truncate font-mono text-[11px] text-text-muted">
                    {entry.request_path}
                  </td>
                  <td className="px-4 py-2.5 whitespace-nowrap">
                    {actionBadge(entry.action_taken)}
                  </td>
                  <td className="px-4 py-2.5 font-mono text-[11px] text-text-muted whitespace-nowrap">
                    {entry.matched_rule_id}
                  </td>
                </tr>
              ))}
              {pageData.length === 0 && (
                <tr>
                  <td
                    colSpan={8}
                    className="px-4 py-12 text-center text-sm text-text-muted"
                  >
                    No events match your filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Pagination ── */}
      <div className="flex items-center justify-between">
        <p className="text-xs text-text-muted">
          {filtered.length === 0
            ? "Showing 0 of 0 events"
            : `Showing ${(page - 1) * PAGE_SIZE + 1}–${Math.min(page * PAGE_SIZE, filtered.length)} of ${filtered.length} events`}
        </p>
        <div className="flex items-center gap-1">
          <button
            onClick={() => setPage((p) => Math.max(1, p - 1))}
            disabled={page === 1}
            className="flex h-8 w-8 items-center justify-center rounded-md border border-border bg-bg-card text-text-muted hover:bg-bg-elevated disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
          >
            <ChevronLeft className="h-4 w-4" />
          </button>
          {Array.from({ length: Math.min(totalPages, 7) }, (_, i) => {
            let p: number;
            if (totalPages <= 7) {
              p = i + 1;
            } else if (page <= 4) {
              p = i + 1;
            } else if (page >= totalPages - 3) {
              p = totalPages - 6 + i;
            } else {
              p = page - 3 + i;
            }
            return (
              <button
                key={p}
                onClick={() => setPage(p)}
                className={`flex h-8 w-8 items-center justify-center rounded-md border text-xs font-medium transition-colors ${
                  page === p
                    ? "border-accent-indigo/40 bg-accent-indigo/15 text-accent-indigo"
                    : "border-border bg-bg-card text-text-muted hover:bg-bg-elevated"
                }`}
              >
                {p}
              </button>
            );
          })}
          <button
            onClick={() => setPage((p) => Math.min(totalPages, p + 1))}
            disabled={page === totalPages}
            className="flex h-8 w-8 items-center justify-center rounded-md border border-border bg-bg-card text-text-muted hover:bg-bg-elevated disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
          >
            <ChevronRight className="h-4 w-4" />
          </button>
        </div>
      </div>
    </div>
  );
}
