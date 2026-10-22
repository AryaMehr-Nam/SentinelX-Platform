/** SentinelX Dashboard — 404 Not Found Page */
import { ShieldAlert, ArrowLeft, Home } from "lucide-react";
import { Link, useNavigate } from "react-router-dom";

export default function NotFoundPage() {
  const navigate = useNavigate();

  return (
    <div className="min-h-screen flex items-center justify-center bg-bg-primary px-4">
      {/* Background glow */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute top-1/3 left-1/2 -translate-x-1/2 w-[500px] h-[500px] rounded-full bg-danger/5 blur-[120px]" />
      </div>

      <div className="relative text-center max-w-md animate-fade-in">
        <div className="mx-auto w-16 h-16 rounded-2xl bg-danger/10 border border-danger/20 flex items-center justify-center text-danger mb-6 shadow-[0_0_30px_rgba(239,68,68,0.2)]">
          <ShieldAlert size={36} />
        </div>

        <span className="font-mono text-xs uppercase tracking-widest text-danger font-semibold bg-danger/10 px-3 py-1 rounded-full border border-danger/20">
          HTTP 404 // Target Not Found
        </span>

        <h1 className="text-3xl font-bold text-text-primary mt-4 tracking-tight">
          Page Not Found
        </h1>

        <p className="text-sm text-text-muted mt-2 leading-relaxed">
          The requested endpoint does not exist or has been restricted by WAF security policies.
        </p>

        <div className="mt-8 flex items-center justify-center gap-3">
          <button
            onClick={() => navigate(-1)}
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg border border-border bg-bg-card text-text-secondary hover:text-text-primary hover:bg-bg-elevated transition-colors text-sm font-medium cursor-pointer"
          >
            <ArrowLeft size={16} />
            Go Back
          </button>
          <Link
            to="/"
            className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-gradient-to-r from-accent-indigo to-accent-purple text-white shadow-lg shadow-accent-indigo/25 hover:shadow-xl hover:brightness-110 transition-all text-sm font-medium"
          >
            <Home size={16} />
            SOC Overview
          </Link>
        </div>
      </div>
    </div>
  );
}
