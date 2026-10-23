/** SentinelX Dashboard — Header Bar */
import { useState, useRef, useEffect } from "react";
import { Search, Bell, ChevronDown, LogOut, User, Settings } from "lucide-react";
import { useNavigate } from "react-router-dom";
import { useAuthStore } from "../stores/authStore";

interface HeaderProps {
  title: string;
  subtitle?: string;
}

export default function Header({ title, subtitle }: HeaderProps) {
  const { user, logout } = useAuthStore();
  const navigate = useNavigate();

  const [searchFocused, setSearchFocused] = useState(false);
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const searchInputRef = useRef<HTMLInputElement>(null);

  // Close dropdown on outside click & handle Cmd+K / Ctrl+K shortcut
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setDropdownOpen(false);
      }
    }

    function handleKeyDown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        searchInputRef.current?.focus();
      }
    }

    document.addEventListener("mousedown", handleClick);
    document.addEventListener("keydown", handleKeyDown);
    return () => {
      document.removeEventListener("mousedown", handleClick);
      document.removeEventListener("keydown", handleKeyDown);
    };
  }, []);

  const notificationCount = 5; // Will be replaced by real data

  return (
    <header className="sticky top-0 z-30 flex items-center justify-between gap-4 px-6 h-16 bg-bg-secondary/80 backdrop-blur-xl border-b border-border">
      {/* ── Left: Title ── */}
      <div className="flex items-center gap-3 min-w-0">
        <div>
          <h1 className="text-lg font-semibold text-text-primary leading-tight truncate">
            {title}
          </h1>
          {subtitle && (
            <p className="text-xs text-text-muted mt-0.5">{subtitle}</p>
          )}
        </div>

        {/* Live indicator */}
        <div className="flex items-center gap-1.5 ml-3 px-2.5 py-1 rounded-full bg-success/10 border border-success/20">
          <span className="relative flex h-2 w-2">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-success opacity-75" />
            <span className="relative inline-flex rounded-full h-2 w-2 bg-success" />
          </span>
          <span className="text-[11px] font-medium text-success tracking-wide">
            LIVE
          </span>
        </div>
      </div>

      {/* ── Right: Controls ── */}
      <div className="flex items-center gap-3">
        {/* Search */}
        <div
          className={`
            flex items-center gap-2 rounded-lg border transition-all duration-200
            ${
              searchFocused
                ? "w-72 border-accent-indigo/40 bg-bg-primary shadow-[0_0_0_3px_rgba(99,102,241,0.1)]"
                : "w-56 border-border bg-bg-primary/60 hover:border-border-light"
            }
          `}
        >
          <Search size={15} className="ml-3 text-text-muted shrink-0" />
          <input
            ref={searchInputRef}
            type="text"
            placeholder="Search threats, IPs, rules…"
            onFocus={() => setSearchFocused(true)}
            onBlur={() => setSearchFocused(false)}
            className="
              flex-1 bg-transparent text-sm text-text-primary placeholder:text-text-muted
              py-2 pr-3 outline-none
            "
          />
          <kbd className="hidden sm:inline-flex items-center mr-2 px-1.5 py-0.5 rounded text-[10px] font-mono text-text-muted bg-bg-tertiary border border-border">
            ⌘K
          </kbd>
        </div>

        {/* Notifications */}
        <button
          className="
            relative p-2 rounded-lg text-text-secondary
            hover:text-text-primary hover:bg-bg-hover
            transition-colors duration-200
          "
          aria-label="Notifications"
        >
          <Bell size={19} />
          {notificationCount > 0 && (
            <span
              className="
                absolute -top-0.5 -right-0.5 flex items-center justify-center
                min-w-[18px] h-[18px] px-1 rounded-full text-[10px] font-bold
                bg-danger text-white shadow-lg shadow-danger/30
                animate-pulse
              "
            >
              {notificationCount > 9 ? "9+" : notificationCount}
            </span>
          )}
        </button>

        {/* Divider */}
        <div className="w-px h-8 bg-border" />

        {/* User Avatar + Dropdown */}
        <div className="relative" ref={dropdownRef}>
          <button
            onClick={() => setDropdownOpen((prev) => !prev)}
            className="
              flex items-center gap-2.5 pl-1 pr-2 py-1 rounded-lg
              hover:bg-bg-hover transition-colors duration-200
            "
          >
            <div
              className="
                w-8 h-8 rounded-full
                bg-gradient-to-br from-accent-indigo to-accent-purple
                flex items-center justify-center text-xs font-semibold text-white
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
            <div className="hidden md:block text-left">
              <p className="text-sm font-medium text-text-primary leading-tight">
                {user?.full_name ?? "Operator"}
              </p>
              <p className="text-[11px] text-text-muted leading-tight">
                {user?.email ?? "operator@sentinelx.io"}
              </p>
            </div>
            <ChevronDown
              size={14}
              className={`text-text-muted transition-transform duration-200 ${
                dropdownOpen ? "rotate-180" : ""
              }`}
            />
          </button>

          {/* Dropdown Menu */}
          {dropdownOpen && (
            <div
              className="
                absolute right-0 mt-2 w-52 py-1.5 rounded-xl
                bg-bg-elevated border border-border shadow-2xl shadow-black/40
                animate-fade-in z-50
              "
            >
              <button
                onClick={() => {
                  setDropdownOpen(false);
                  navigate("/settings");
                }}
                className="
                  w-full flex items-center gap-2.5 px-3.5 py-2 text-sm text-text-secondary
                  hover:text-text-primary hover:bg-bg-hover transition-colors duration-150
                "
              >
                <User size={15} />
                Profile
              </button>
              <button
                onClick={() => {
                  setDropdownOpen(false);
                  navigate("/settings");
                }}
                className="
                  w-full flex items-center gap-2.5 px-3.5 py-2 text-sm text-text-secondary
                  hover:text-text-primary hover:bg-bg-hover transition-colors duration-150
                "
              >
                <Settings size={15} />
                Settings
              </button>
              <div className="my-1 mx-3 h-px bg-border" />
              <button
                onClick={() => {
                  setDropdownOpen(false);
                  logout();
                  navigate("/login");
                }}
                className="
                  w-full flex items-center gap-2.5 px-3.5 py-2 text-sm text-danger
                  hover:bg-danger/10 transition-colors duration-150
                "
              >
                <LogOut size={15} />
                Sign out
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  );
}
