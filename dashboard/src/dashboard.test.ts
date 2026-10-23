/** SentinelX Dashboard — Unit & Component Tests */
import { describe, it, expect, beforeEach } from "vitest";
import { useAuthStore } from "./stores/authStore";

describe("Dashboard AuthStore", () => {
  beforeEach(() => {
    localStorage.clear();
    useAuthStore.getState().logout();
  });

  it("initializes with unauthenticated state when storage is empty", () => {
    const state = useAuthStore.getState();
    expect(state.user).toBeNull();
    expect(state.isAuthenticated).toBe(false);
  });

  it("authenticates and saves tokens on login", () => {
    const mockUser = {
      id: "u-123",
      email: "secops@sentinelx.io",
      full_name: "SecOps Lead",
      role: "admin" as const,
      is_active: true,
      created_at: new Date().toISOString(),
    };

    useAuthStore.getState().login("access-token-123", "refresh-token-456", mockUser);

    const state = useAuthStore.getState();
    expect(state.isAuthenticated).toBe(true);
    expect(state.user?.email).toBe("secops@sentinelx.io");
    expect(state.user?.role).toBe("admin");
    expect(localStorage.getItem("sentinelx_access_token")).toBe("access-token-123");
    expect(localStorage.getItem("sentinelx_refresh_token")).toBe("refresh-token-456");
  });

  it("clears storage and user state on logout", () => {
    const mockUser = {
      id: "u-123",
      email: "secops@sentinelx.io",
      full_name: "SecOps Lead",
      role: "admin" as const,
      is_active: true,
      created_at: new Date().toISOString(),
    };

    useAuthStore.getState().login("token", "refresh", mockUser);
    expect(useAuthStore.getState().isAuthenticated).toBe(true);

    useAuthStore.getState().logout();

    expect(useAuthStore.getState().isAuthenticated).toBe(false);
    expect(useAuthStore.getState().user).toBeNull();
    expect(localStorage.getItem("sentinelx_access_token")).toBeNull();
  });
});

describe("Threat Intelligence Response Normalization", () => {
  function extractThreatDomains(data: unknown): unknown[] {
    if (Array.isArray(data)) return data;
    if (typeof data === "object" && data !== null && "domains" in data) {
      const d = (data as { domains: unknown }).domains;
      if (Array.isArray(d)) return d;
    }
    return [];
  }

  function extractThreatSummaries(data: unknown): unknown[] {
    if (Array.isArray(data)) return data;
    if (typeof data === "object" && data !== null && "summaries" in data) {
      const s = (data as { summaries: unknown }).summaries;
      if (Array.isArray(s)) return s;
    }
    return [];
  }

  function riskColor(score: number): string {
    if (score >= 80) return "text-severity-critical";
    if (score >= 60) return "text-severity-high";
    if (score >= 40) return "text-severity-medium";
    return "text-severity-low";
  }

  it("extracts domains when API returns a raw array", () => {
    const raw = [{ id: "1", domain: "test1.com" }, { id: "2", domain: "test2.com" }];
    const extracted = extractThreatDomains(raw);
    expect(extracted).toEqual(raw);
    expect(extracted.length).toBe(2);
  });

  it("extracts domains when API returns { domains: [...] } envelope", () => {
    const enveloped = {
      domains: [{ id: "1", domain: "test1.com" }],
      total: 1,
      page: 1,
      per_page: 20,
    };
    const extracted = extractThreatDomains(enveloped);
    expect(extracted.length).toBe(1);
    expect((extracted[0] as { domain: string }).domain).toBe("test1.com");
  });

  it("returns empty array for invalid domain payload structures", () => {
    expect(extractThreatDomains(null)).toEqual([]);
    expect(extractThreatDomains(undefined)).toEqual([]);
    expect(extractThreatDomains({ unexpectedKey: 123 })).toEqual([]);
    expect(extractThreatDomains("string-response")).toEqual([]);
  });

  it("extracts summaries when API returns { summaries: [...] } envelope", () => {
    const enveloped = {
      summaries: [{ id: "s1", threat_classification: "SQLi" }],
    };
    const extracted = extractThreatSummaries(enveloped);
    expect(extracted.length).toBe(1);
  });

  it("calculates correct risk color class based on score threshold", () => {
    expect(riskColor(95)).toBe("text-severity-critical");
    expect(riskColor(80)).toBe("text-severity-critical");
    expect(riskColor(75)).toBe("text-severity-high");
    expect(riskColor(60)).toBe("text-severity-high");
    expect(riskColor(50)).toBe("text-severity-medium");
    expect(riskColor(40)).toBe("text-severity-medium");
    expect(riskColor(35)).toBe("text-severity-low");
    expect(riskColor(0)).toBe("text-severity-low");
  });
});

