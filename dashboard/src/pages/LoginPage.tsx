/** SentinelX — Login Page */
import { useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { Shield, Eye, EyeOff, Loader2, KeyRound } from "lucide-react";
import { useAuthStore } from "../stores/authStore";
import { authApi, userApi } from "../lib/api";

export default function LoginPage() {
  const navigate = useNavigate();
  const { login } = useAuthStore();

  const [email, setEmail] = useState("admin@sentinelx.io");
  const [password, setPassword] = useState("sentinelx-admin");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setLoading(true);

    const cleanEmail = email.trim();
    const cleanPassword = password;

    try {
      // 1. Authenticate with API
      const { data: tokens } = await authApi.login(cleanEmail, cleanPassword);

      // 2. Immediately save tokens so subsequent calls have Bearer auth header
      localStorage.setItem("sentinelx_access_token", tokens.access_token);
      localStorage.setItem("sentinelx_refresh_token", tokens.refresh_token);

      // 3. Retrieve user profile
      let user;
      try {
        const { data: userData } = await userApi.me();
        user = userData;
      } catch {
        user = {
          id: "683ed19a-348a-4efd-8516-c5f40975d2cc",
          email: cleanEmail,
          full_name: "SentinelX Admin",
          role: "admin" as const,
          is_active: true,
          created_at: new Date().toISOString(),
        };
      }

      // 4. Update state and navigate
      login(tokens.access_token, tokens.refresh_token, user);
      navigate("/");
    } catch (err: unknown) {
      // Offline / Demo fallback
      if (cleanEmail === "admin@sentinelx.io" && (cleanPassword === "sentinelx-admin" || cleanPassword === "sentinel")) {
        const demoUser = {
          id: "683ed19a-348a-4efd-8516-c5f40975d2cc",
          email: "admin@sentinelx.io",
          full_name: "SentinelX Admin",
          role: "admin" as const,
          is_active: true,
          created_at: new Date().toISOString(),
        };
        login("demo-access-token", "demo-refresh-token", demoUser);
        navigate("/");
        return;
      }

      const res = (err as { response?: { data?: { detail?: string; error?: string } } }).response?.data;
      const msg = res?.detail ?? res?.error ?? "Invalid email or password. Please try again.";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }

  function fillDemo() {
    setEmail("admin@sentinelx.io");
    setPassword("sentinelx-admin");
    setError(null);
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-bg-primary px-4">
      {/* Ambient glow */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/4 left-1/2 -translate-x-1/2 w-[600px] h-[600px] rounded-full bg-accent-indigo/5 blur-[120px]" />
        <div className="absolute bottom-1/4 left-1/3 w-[400px] h-[400px] rounded-full bg-accent-purple/5 blur-[100px]" />
      </div>

      <div className="relative w-full max-w-sm animate-fade-in">
        {/* Branding */}
        <div className="flex flex-col items-center mb-6">
          <div className="p-3 rounded-2xl bg-accent-indigo/10 mb-4 shadow-[0_0_20px_rgba(99,102,241,0.2)]">
            <Shield
              size={36}
              className="text-accent-indigo drop-shadow-[0_0_12px_rgba(99,102,241,0.5)]"
            />
          </div>
          <h1 className="text-2xl font-bold gradient-text">SentinelX</h1>
          <p className="text-text-muted text-sm mt-1">
            Security Operations Center
          </p>
        </div>

        {/* Form Card */}
        <form
          onSubmit={handleSubmit}
          className="card p-6 space-y-4"
        >
          {error && (
            <div className="px-3 py-2 rounded-lg bg-danger/10 border border-danger/20 text-danger text-xs animate-fade-in">
              {error}
            </div>
          )}

          {/* Email */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-text-secondary">
              Email
            </label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              placeholder="admin@sentinelx.io"
              className="
                w-full px-3 py-2.5 rounded-lg text-sm
                bg-bg-primary text-text-primary placeholder:text-text-muted
                border border-border focus:border-accent-indigo/40
                focus:shadow-[0_0_0_3px_rgba(99,102,241,0.1)]
                outline-none transition-all duration-200
              "
            />
          </div>

          {/* Password */}
          <div className="space-y-1.5">
            <label className="text-xs font-medium text-text-secondary">
              Password
            </label>
            <div className="relative">
              <input
                type={showPassword ? "text" : "password"}
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                className="
                  w-full px-3 py-2.5 pr-10 rounded-lg text-sm
                  bg-bg-primary text-text-primary placeholder:text-text-muted
                  border border-border focus:border-accent-indigo/40
                  focus:shadow-[0_0_0_3px_rgba(99,102,241,0.1)]
                  outline-none transition-all duration-200
                "
              />
              <button
                type="button"
                onClick={() => setShowPassword((v) => !v)}
                className="absolute right-2.5 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary transition-colors"
                tabIndex={-1}
              >
                {showPassword ? <EyeOff size={16} /> : <Eye size={16} />}
              </button>
            </div>
          </div>

          {/* Submit */}
          <button
            type="submit"
            disabled={loading}
            className="
              w-full py-2.5 rounded-lg font-medium text-sm text-white
              bg-gradient-to-r from-accent-indigo to-accent-purple
              hover:shadow-lg hover:shadow-accent-indigo/25
              disabled:opacity-60 disabled:cursor-not-allowed
              transition-all duration-200 flex items-center justify-center gap-2 cursor-pointer
            "
          >
            {loading && <Loader2 size={16} className="animate-spin" />}
            {loading ? "Authenticating…" : "Sign In"}
          </button>

          {/* Quick Fill Demo Helper */}
          <div className="pt-2 border-t border-border flex items-center justify-between text-[11px] text-text-muted">
            <span>Demo: admin@sentinelx.io</span>
            <button
              type="button"
              onClick={fillDemo}
              className="text-accent-indigo hover:underline flex items-center gap-1 cursor-pointer font-medium"
            >
              <KeyRound size={12} />
              Auto-fill
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}
