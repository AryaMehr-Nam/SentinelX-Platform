/** SentinelX Dashboard — Sidebar Navigation */
import { useState } from "react";
import { NavLink } from "react-router-dom";
import {
  LayoutDashboard,
  Radio,
  ShieldAlert,
  ScrollText,
  Settings,
  ChevronLeft,
  ChevronRight,
  LogOut,
  Shield,
} from "lucide-react";
import { useAuthStore } from "../stores/authStore";

interface NavItem {
  label: string;
  path: string;
  icon: React.ReactNode;
}

const navItems: NavItem[] = [
  { label: "Overview", path: "/", icon: <LayoutDashboard size={20} /> },
  { label: "Attack Stream", path: "/attacks", icon: <Radio size={20} /> },
  { label: "Threat Intel", path: "/threats", icon: <ShieldAlert size={20} /> },
  { label: "WAF Rules", path: "/rules", icon: <ScrollText size={20} /> },
  { label: "Settings", path: "/settings", icon: <Settings size={20} /> },
];

export default function Sidebar() {
  const [collapsed, setCollapsed] = useState(false);
  const { user, logout } = useAuthStore();

  return (
    <aside
      className={`
        flex flex-col h-screen sticky top-0
        bg-bg-secondary border-r border-border
        transition-all duration-300 ease-in-out
        ${collapsed ? "w-[72px]" : "w-[260px]"}
      `}
    >
      {/* ── Logo ── */}
      <div className="flex items-center gap-3 px-5 h-16 shrink-0 border-b border-border">
        <div className="relative shrink-0">
          <Shield
            size={28}
            className="text-accent-indigo drop-shadow-[0_0_8px_rgba(99,102,241,0.5)]"
          />
          <span className="absolute -top-0.5 -right-0.5 w-2 h-2 rounded-full bg-success animate-pulse" />
        </div>
        {!collapsed && (
          <span className="text-lg font-bold tracking-tight gradient-text whitespace-nowrap animate-fade-in">
            SentinelX
          </span>
        )}
      </div>

      {/* ── Navigation ── */}
      <nav className="flex-1 flex flex-col gap-1 px-3 py-4 overflow-y-auto">
        {navItems.map((item) => (
          <NavLink
            key={item.path}
            to={item.path}
            end={item.path === "/"}
            className={({ isActive }) =>
              `group flex items-center gap-3 rounded-lg transition-all duration-200 relative
              ${collapsed ? "justify-center px-0 py-3" : "px-3 py-2.5"}
              ${
                isActive
                  ? "bg-accent-indigo/10 text-accent-indigo font-medium"
                  : "text-text-secondary hover:text-text-primary hover:bg-bg-hover"
              }`
            }
          >
            {({ isActive }) => (
              <>
                {/* Active indicator bar */}
                {isActive && (
                  <span className="absolute left-0 top-1/2 -translate-y-1/2 w-[3px] h-5 rounded-r-full bg-accent-indigo animate-fade-in" />
                )}

                <span
                  className={`shrink-0 transition-colors duration-200 ${
                    isActive
                      ? "text-accent-indigo drop-shadow-[0_0_6px_rgba(99,102,241,0.4)]"
                      : "text-text-muted group-hover:text-text-secondary"
                  }`}
                >
                  {item.icon}
                </span>

                {!collapsed && (
                  <span className="text-sm whitespace-nowrap animate-fade-in">
                    {item.label}
                  </span>
                )}

                {/* Tooltip on collapsed */}
                {collapsed && (
                  <span
                    className="
                      absolute left-full ml-2 px-2.5 py-1 rounded-md text-xs font-medium
                      bg-bg-elevated text-text-primary border border-border
                      opacity-0 pointer-events-none group-hover:opacity-100
                      transition-opacity duration-150 whitespace-nowrap z-50
                      shadow-lg shadow-black/30
                    "
                  >
                    {item.label}
                  </span>
                )}
              </>
            )}
          </NavLink>
        ))}
      </nav>

      {/* ── Collapse Toggle ── */}
      <div className="px-3 pb-2">
        <button
          onClick={() => setCollapsed((prev) => !prev)}
          className="
            w-full flex items-center justify-center gap-2 py-2 rounded-lg
            text-text-muted hover:text-text-secondary hover:bg-bg-hover
            transition-all duration-200 text-xs
          "
          aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
        >
          {collapsed ? <ChevronRight size={16} /> : <ChevronLeft size={16} />}
          {!collapsed && <span>Collapse</span>}
        </button>
      </div>

      {/* ── User Info ── */}
      <div className="border-t border-border px-3 py-3 shrink-0">
        <div
          className={`flex items-center gap-3 ${collapsed ? "justify-center" : ""}`}
        >
          {/* Avatar */}
          <div
            className="
              relative shrink-0 w-9 h-9 rounded-full
              bg-gradient-to-br from-accent-indigo to-accent-purple
              flex items-center justify-center text-sm font-semibold text-white
              ring-2 ring-accent-indigo/20
            "
          >
            {user?.full_name
              ? user.full_name
                  .split(" ")
                  .map((n) => n[0])
                  .join("")
                  .slice(0, 2)
                  .toUpperCase()
              : "SX"}
          </div>

          {!collapsed && (
            <div className="flex-1 min-w-0 animate-fade-in">
              <p className="text-sm font-medium text-text-primary truncate">
                {user?.full_name ?? "Operator"}
              </p>
              <span
                className="
                  inline-block mt-0.5 px-1.5 py-px rounded text-[10px] font-semibold uppercase tracking-wider
                  bg-accent-indigo/15 text-accent-indigo
                "
              >
                {user?.role ?? "analyst"}
              </span>
            </div>
          )}

          {!collapsed && (
            <button
              onClick={logout}
              className="
                p-1.5 rounded-md text-text-muted hover:text-danger
                hover:bg-danger/10 transition-colors duration-200
              "
              aria-label="Logout"
              title="Logout"
            >
              <LogOut size={16} />
            </button>
          )}
        </div>
      </div>
    </aside>
  );
}
