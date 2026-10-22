/** SentinelX Dashboard — Auth Store (Zustand) */
import { create } from "zustand";
import type { User } from "../types";

interface AuthState {
  user: User | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (accessToken: string, refreshToken: string, user: User) => void;
  logout: () => void;
  setUser: (user: User) => void;
  setLoading: (loading: boolean) => void;
}

const getStoredToken = () => {
  if (typeof window !== "undefined" && typeof localStorage !== "undefined") {
    return localStorage.getItem("sentinelx_access_token");
  }
  return null;
};

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  isAuthenticated: !!getStoredToken(),
  isLoading: true,

  login: (accessToken, refreshToken, user) => {
    if (typeof localStorage !== "undefined") {
      localStorage.setItem("sentinelx_access_token", accessToken);
      localStorage.setItem("sentinelx_refresh_token", refreshToken);
    }
    set({ user, isAuthenticated: true, isLoading: false });
  },

  logout: () => {
    if (typeof localStorage !== "undefined") {
      localStorage.removeItem("sentinelx_access_token");
      localStorage.removeItem("sentinelx_refresh_token");
    }
    set({ user: null, isAuthenticated: false, isLoading: false });
  },

  setUser: (user) => set({ user, isAuthenticated: true, isLoading: false }),
  setLoading: (isLoading) => set({ isLoading }),
}));
