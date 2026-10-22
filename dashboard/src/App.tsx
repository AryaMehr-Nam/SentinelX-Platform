/** SentinelX Dashboard — Root App Router */
import { lazy, Suspense } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Layout from "./components/Layout";
import { Shield } from "lucide-react";

// Lazy-loaded route components for optimized code splitting
const LoginPage = lazy(() => import("./pages/LoginPage"));
const OverviewPage = lazy(() => import("./pages/OverviewPage"));
const AttackStreamPage = lazy(() => import("./pages/AttackStreamPage"));
const ThreatIntelPage = lazy(() => import("./pages/ThreatIntelPage"));
const WAFRulesPage = lazy(() => import("./pages/WAFRulesPage"));
const SettingsPage = lazy(() => import("./pages/SettingsPage"));
const NotFoundPage = lazy(() => import("./pages/NotFoundPage"));

function PageLoadingFallback() {
  return (
    <div className="flex h-[calc(100vh-8rem)] w-full items-center justify-center">
      <div className="flex flex-col items-center gap-3 animate-fade-in">
        <div className="relative">
          <Shield className="h-10 w-10 text-accent-indigo animate-pulse" />
          <span className="absolute -top-1 -right-1 h-3 w-3 rounded-full bg-success animate-ping" />
        </div>
        <p className="text-xs font-mono tracking-wider uppercase text-text-muted">
          Loading Security Telemetry...
        </p>
      </div>
    </div>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <Suspense fallback={<PageLoadingFallback />}>
        <Routes>
          {/* Public login route */}
          <Route path="/login" element={<LoginPage />} />

          {/* Authenticated dashboard shell */}
          <Route path="/" element={<Layout />}>
            <Route index element={<OverviewPage />} />
            <Route path="attacks" element={<AttackStreamPage />} />
            <Route path="threats" element={<ThreatIntelPage />} />
            <Route path="rules" element={<WAFRulesPage />} />
            <Route path="settings" element={<SettingsPage />} />
          </Route>

          {/* 404 handler */}
          <Route path="/404" element={<NotFoundPage />} />
          <Route path="*" element={<Navigate to="/404" replace />} />
        </Routes>
      </Suspense>
    </BrowserRouter>
  );
}
