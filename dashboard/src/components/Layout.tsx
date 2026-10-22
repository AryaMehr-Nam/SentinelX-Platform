/** SentinelX Dashboard — Main Layout Shell */
import { Outlet, useLocation } from "react-router-dom";
import Sidebar from "./Sidebar";
import Header from "./Header";

/** Map route paths → readable page titles */
const pageMeta: Record<string, { title: string; subtitle?: string }> = {
  "/":        { title: "Overview",       subtitle: "Real-time security posture" },
  "/attacks": { title: "Attack Stream",  subtitle: "Live threat event feed" },
  "/threats": { title: "Threat Intel",   subtitle: "Intelligence & analysis" },
  "/rules":   { title: "WAF Rules",      subtitle: "Firewall rule management" },
  "/settings":{ title: "Settings",       subtitle: "Dashboard configuration" },
};

export default function Layout() {
  const { pathname } = useLocation();
  const meta = pageMeta[pathname] ?? { title: "SentinelX" };

  return (
    <div className="flex h-screen overflow-hidden bg-bg-primary">
      {/* Sidebar */}
      <Sidebar />

      {/* Main Area */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        <Header title={meta.title} subtitle={meta.subtitle} />

        <main className="flex-1 overflow-y-auto px-6 py-6">
          <div className="animate-fade-in">
            <Outlet />
          </div>
        </main>
      </div>
    </div>
  );
}
