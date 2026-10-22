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
