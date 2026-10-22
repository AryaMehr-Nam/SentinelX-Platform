/** SentinelX Dashboard — API Client */
import axios from "axios";

const API_BASE = "/api/v1";

const api = axios.create({
  baseURL: API_BASE,
  headers: { "Content-Type": "application/json" },
});

// Attach auth token to every request
api.interceptors.request.use((config) => {
  const token = localStorage.getItem("sentinelx_access_token");
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

// Handle 401 → redirect to login
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    const url = error.config?.url || "";
    if (url.includes("/auth/login") || url.includes("/auth/register")) {
      return Promise.reject(error);
    }

    if (error.response?.status === 401) {
      // Try refresh
      const refreshToken = localStorage.getItem("sentinelx_refresh_token");
      if (refreshToken && !error.config._retry) {
        error.config._retry = true;
        try {
          const res = await axios.post(`${API_BASE}/auth/refresh`, {
            refresh_token: refreshToken,
          });
          localStorage.setItem("sentinelx_access_token", res.data.access_token);
          localStorage.setItem("sentinelx_refresh_token", res.data.refresh_token);
          error.config.headers.Authorization = `Bearer ${res.data.access_token}`;
          return api(error.config);
        } catch {
          localStorage.removeItem("sentinelx_access_token");
          localStorage.removeItem("sentinelx_refresh_token");
          window.location.href = "/login";
        }
      } else {
        localStorage.removeItem("sentinelx_access_token");
        localStorage.removeItem("sentinelx_refresh_token");
        window.location.href = "/login";
      }
    }
    return Promise.reject(error);
  }
);

export default api;

// ──── Auth API ────
export const authApi = {
  login: (email: string, password: string) =>
    api.post("/auth/login", { email, password }),
  refresh: (refresh_token: string) =>
    api.post("/auth/refresh", { refresh_token }),
  register: (data: { email: string; password: string; full_name: string }) =>
    api.post("/auth/register", data),
};

// ──── User API ────
export const userApi = {
  me: () => api.get("/users/me"),
  list: (page = 1, per_page = 20) =>
    api.get("/users", { params: { page, per_page } }),
};

// ──── Dashboard API ────
export const dashboardApi = {
  overview: () => api.get("/dashboard/overview"),
  attackStream: () => api.get("/dashboard/attack-stream"),
};

// ──── WAF API ────
export const wafApi = {
  logs: (params: Record<string, unknown> = {}) =>
    api.get("/waf/logs", { params }),
  rules: (enabled_only = false) =>
    api.get("/waf/rules", { params: { enabled_only } }),
  updateRule: (ruleId: string, updates: Partial<{ is_enabled: boolean; action: string; priority: number }>) =>
    api.patch(`/waf/rules/${ruleId}`, updates),
  blockedIps: () => api.get("/waf/blocked-ips"),
};

// ──── Threats API ────
export const threatApi = {
  domains: (params: Record<string, unknown> = {}) =>
    api.get("/threats/domains", { params }),
  aiSummaries: (limit = 20) =>
    api.get("/threats/ai-summaries", { params: { limit } }),
};

// ──── Simulator API ────
export const simulatorApi = {
  start: (interval = 2.0) => api.post(`/simulator/start?interval=${interval}`),
  stop: () => api.post("/simulator/stop"),
  status: () => api.get("/simulator/status"),
};

