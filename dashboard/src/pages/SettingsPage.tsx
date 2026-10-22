/** SentinelX Dashboard — Settings Page */
import { useState, useEffect } from "react";
import {
  Settings,
  User,
  Key,
  Shield,
  Save,
  CheckCircle2,
  Eye,
  EyeOff,
  Bell,
  Globe,
  Clock,
  Mail,
} from "lucide-react";
import { useAuthStore } from "../stores/authStore";

/* ────────────────────────── Mock Settings ────────────────────────── */

interface SettingsState {
  profile: {
    fullName: string;
    email: string;
    role: string;
    timezone: string;
  };
  api: {
    baseUrl: string;
    apiKey: string;
    timeout: number;
    retryAttempts: number;
  };
  waf: {
    globalEnabled: boolean;
    mlDetection: boolean;
    blockMode: string;
    logRetentionDays: number;
    rateLimitPerMinute: number;
    challengeMode: string;
  };
  notifications: {
    emailAlerts: boolean;
    criticalOnly: boolean;
    dailyDigest: boolean;
    slackWebhook: string;
  };
}

const DEFAULT_SETTINGS: SettingsState = {
  profile: {
    fullName: "Alex Morgan",
    email: "admin@sentinelx.io",
    role: "admin",
    timezone: "UTC",
  },
  api: {
    baseUrl: "https://api.sentinelx.io/v1",
    apiKey: "sx_live_k8f2m9d4n7p1q3r6t0w5x8y2z",
    timeout: 30,
    retryAttempts: 3,
  },
  waf: {
    globalEnabled: true,
    mlDetection: true,
    blockMode: "block",
    logRetentionDays: 90,
    rateLimitPerMinute: 1000,
    challengeMode: "captcha",
  },
  notifications: {
    emailAlerts: true,
    criticalOnly: false,
    dailyDigest: true,
    slackWebhook: "https://hooks.slack.com/services/T0XXX/B0XXX/xxxx",
  },
};

/* ────────────────────────── Sub-components ────────────────────────── */

function SectionCard({
  icon: Icon,
  title,
  description,
  children,
  delay = 0,
}: {
  icon: typeof Settings;
  title: string;
  description: string;
  children: React.ReactNode;
  delay?: number;
}) {
  return (
    <div
      className="card overflow-hidden"
      style={{ animation: `fadeIn 0.4s ease-out ${delay}ms both` }}
    >
      <div className="border-b border-border px-6 py-4">
        <div className="flex items-center gap-3">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-accent-indigo/10 text-accent-indigo">
            <Icon className="h-4.5 w-4.5" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-text-primary">{title}</h2>
            <p className="text-xs text-text-muted">{description}</p>
          </div>
        </div>
      </div>
      <div className="px-6 py-5 space-y-5">{children}</div>
    </div>
  );
}

function Field({
  label,
  children,
  hint,
}: {
  label: string;
  children: React.ReactNode;
  hint?: string;
}) {
  return (
    <div>
      <label className="mb-1.5 block text-sm font-medium text-text-secondary">
        {label}
      </label>
      {children}
      {hint && <p className="mt-1 text-[11px] text-text-muted">{hint}</p>}
    </div>
  );
}

function TextInput({
  value,
  onChange,
  type = "text",
  placeholder,
  readOnly = false,
  mono = false,
}: {
  value: string;
  onChange: (v: string) => void;
  type?: string;
  placeholder?: string;
  readOnly?: boolean;
  mono?: boolean;
}) {
  return (
    <input
      type={type}
      value={value}
      onChange={(e) => onChange(e.target.value)}
      placeholder={placeholder}
      readOnly={readOnly}
      className={`w-full rounded-lg border border-border bg-bg-elevated/60 px-4 py-2 text-sm text-text-primary placeholder:text-text-muted outline-none transition-colors focus:border-accent-indigo/50 focus:ring-1 focus:ring-accent-indigo/30 ${
        readOnly ? "opacity-60 cursor-not-allowed" : ""
      } ${mono ? "font-mono text-xs" : ""}`}
    />
  );
}

function NumberInput({
  value,
  onChange,
  min,
  max,
}: {
  value: number;
  onChange: (v: number) => void;
  min?: number;
  max?: number;
}) {
  return (
    <input
      type="number"
      value={value}
      onChange={(e) => onChange(Number(e.target.value))}
      min={min}
      max={max}
      className="w-full rounded-lg border border-border bg-bg-elevated/60 px-4 py-2 text-sm text-text-primary outline-none transition-colors focus:border-accent-indigo/50 focus:ring-1 focus:ring-accent-indigo/30 font-mono"
    />
  );
}

function Toggle({
  checked,
  onChange,
  label,
}: {
  checked: boolean;
  onChange: (v: boolean) => void;
  label: string;
}) {
  return (
    <button
      type="button"
      onClick={() => onChange(!checked)}
      className="flex items-center justify-between w-full group"
    >
      <span className="text-sm text-text-secondary group-hover:text-text-primary transition-colors">
        {label}
      </span>
      <div
        className={`relative h-6 w-11 rounded-full transition-colors ${
          checked ? "bg-success" : "bg-bg-elevated"
        }`}
      >
        <div
          className={`absolute top-0.5 h-5 w-5 rounded-full bg-white shadow transition-transform ${
            checked ? "translate-x-5.5" : "translate-x-0.5"
          }`}
        />
      </div>
    </button>
  );
}

function SelectInput({
  value,
  onChange,
  options,
}: {
  value: string;
  onChange: (v: string) => void;
  options: { value: string; label: string }[];
}) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="w-full rounded-lg border border-border bg-bg-elevated/60 px-4 py-2 text-sm text-text-primary outline-none transition-colors focus:border-accent-indigo/50 focus:ring-1 focus:ring-accent-indigo/30 cursor-pointer"
    >
      {options.map((o) => (
        <option key={o.value} value={o.value}>
          {o.label}
        </option>
      ))}
    </select>
  );
}

/* ────────────────────────── Page ────────────────────────── */

export default function SettingsPage() {
  const { user } = useAuthStore();
  const [settings, setSettings] = useState<SettingsState>(() => ({
    ...DEFAULT_SETTINGS,
    profile: {
      ...DEFAULT_SETTINGS.profile,
      fullName: user?.full_name ?? DEFAULT_SETTINGS.profile.fullName,
      email: user?.email ?? DEFAULT_SETTINGS.profile.email,
      role: user?.role ?? DEFAULT_SETTINGS.profile.role,
    },
  }));
  const [showApiKey, setShowApiKey] = useState(false);
  const [saved, setSaved] = useState(false);
  const [mounted, setMounted] = useState(false);

  useEffect(() => {
    setMounted(true);
  }, []);

  const update = <K extends keyof SettingsState>(
    section: K,
    field: keyof SettingsState[K],
    value: SettingsState[K][keyof SettingsState[K]]
  ) => {
    setSettings((prev) => ({
      ...prev,
      [section]: { ...prev[section], [field]: value },
    }));
    setSaved(false);
  };

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 3000);
  };

  return (
    <div
      className={`space-y-6 p-6 transition-all duration-500 ${
        mounted ? "opacity-100" : "opacity-0"
      }`}
    >
      {/* Header */}
      <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h1 className="flex items-center gap-2 text-2xl font-bold text-text-primary tracking-tight">
            <Settings className="h-6 w-6 text-text-muted" />
            Settings
          </h1>
          <p className="mt-1 text-sm text-text-muted">
            Manage your profile, API configuration, and WAF settings
          </p>
        </div>
        <button
          onClick={handleSave}
          className={`flex items-center gap-2 rounded-lg px-5 py-2 text-sm font-semibold text-white shadow-lg transition-all duration-200 ${
            saved
              ? "bg-success shadow-success/25"
              : "bg-gradient-to-r from-accent-indigo to-accent-purple shadow-accent-indigo/25 hover:shadow-xl hover:brightness-110"
          }`}
        >
          {saved ? (
            <>
              <CheckCircle2 className="h-4 w-4" />
              Saved!
            </>
          ) : (
            <>
              <Save className="h-4 w-4" />
              Save Changes
            </>
          )}
        </button>
      </div>

      <div className="grid grid-cols-1 gap-6 xl:grid-cols-2">
        {/* ── User Profile ── */}
        <SectionCard
          icon={User}
          title="User Profile"
          description="Your account information"
          delay={0}
        >
          <Field label="Full Name">
            <TextInput
              value={settings.profile.fullName}
              onChange={(v) => update("profile", "fullName", v)}
            />
          </Field>
          <Field label="Email Address">
            <TextInput
              value={settings.profile.email}
              onChange={(v) => update("profile", "email", v)}
              type="email"
            />
          </Field>
          <div className="grid grid-cols-2 gap-4">
            <Field label="Role">
              <SelectInput
                value={settings.profile.role}
                onChange={(v) => update("profile", "role", v)}
                options={[
                  { value: "admin", label: "Administrator" },
                  { value: "analyst", label: "SOC Analyst" },
                  { value: "viewer", label: "Viewer" },
                ]}
              />
            </Field>
            <Field label="Timezone">
              <SelectInput
                value={settings.profile.timezone}
                onChange={(v) => update("profile", "timezone", v)}
                options={[
                  { value: "UTC", label: "UTC" },
                  { value: "America/New_York", label: "US Eastern" },
                  { value: "America/Los_Angeles", label: "US Pacific" },
                  { value: "Europe/London", label: "UK / London" },
                  { value: "Europe/Berlin", label: "Central Europe" },
                  { value: "Asia/Tokyo", label: "Japan" },
                  { value: "Asia/Tehran", label: "Iran" },
                ]}
              />
            </Field>
          </div>
        </SectionCard>

        {/* ── API Configuration ── */}
        <SectionCard
          icon={Key}
          title="API Configuration"
          description="API endpoint and authentication settings"
          delay={80}
        >
          <Field label="API Base URL" hint="The root URL for all API requests">
            <TextInput
              value={settings.api.baseUrl}
              onChange={(v) => update("api", "baseUrl", v)}
              mono
            />
          </Field>
          <Field label="API Key" hint="Used for authenticating external integrations">
            <div className="relative">
              <input
                type={showApiKey ? "text" : "password"}
                value={settings.api.apiKey}
                onChange={(e) => update("api", "apiKey", e.target.value)}
                className="w-full rounded-lg border border-border bg-bg-elevated/60 px-4 py-2 pr-11 text-xs font-mono text-text-primary outline-none transition-colors focus:border-accent-indigo/50 focus:ring-1 focus:ring-accent-indigo/30"
              />
              <button
                type="button"
                onClick={() => setShowApiKey(!showApiKey)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-text-muted hover:text-text-secondary transition-colors"
              >
                {showApiKey ? (
                  <EyeOff className="h-4 w-4" />
                ) : (
                  <Eye className="h-4 w-4" />
                )}
              </button>
            </div>
          </Field>
          <div className="grid grid-cols-2 gap-4">
            <Field label="Request Timeout (s)">
              <NumberInput
                value={settings.api.timeout}
                onChange={(v) => update("api", "timeout", v)}
                min={5}
                max={120}
              />
            </Field>
            <Field label="Retry Attempts">
              <NumberInput
                value={settings.api.retryAttempts}
                onChange={(v) => update("api", "retryAttempts", v)}
                min={0}
                max={10}
              />
            </Field>
          </div>
        </SectionCard>

        {/* ── WAF Settings ── */}
        <SectionCard
          icon={Shield}
          title="WAF Settings"
          description="Web Application Firewall configuration"
          delay={160}
        >
          <div className="space-y-4">
            <Toggle
              checked={settings.waf.globalEnabled}
              onChange={(v) => update("waf", "globalEnabled", v)}
              label="Global WAF Protection"
            />
            <Toggle
              checked={settings.waf.mlDetection}
              onChange={(v) => update("waf", "mlDetection", v)}
              label="AI/ML Anomaly Detection"
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <Field label="Default Block Mode">
              <SelectInput
                value={settings.waf.blockMode}
                onChange={(v) => update("waf", "blockMode", v)}
                options={[
                  { value: "block", label: "Block Request" },
                  { value: "challenge", label: "Challenge (CAPTCHA)" },
                  { value: "log", label: "Log Only" },
                ]}
              />
            </Field>
            <Field label="Challenge Mode">
              <SelectInput
                value={settings.waf.challengeMode}
                onChange={(v) => update("waf", "challengeMode", v)}
                options={[
                  { value: "captcha", label: "CAPTCHA" },
                  { value: "js_challenge", label: "JS Challenge" },
                  { value: "managed", label: "Managed Challenge" },
                ]}
              />
            </Field>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <Field label="Log Retention (days)">
              <NumberInput
                value={settings.waf.logRetentionDays}
                onChange={(v) => update("waf", "logRetentionDays", v)}
                min={7}
                max={365}
              />
            </Field>
            <Field label="Rate Limit (req/min)">
              <NumberInput
                value={settings.waf.rateLimitPerMinute}
                onChange={(v) => update("waf", "rateLimitPerMinute", v)}
                min={10}
                max={10000}
              />
            </Field>
          </div>
        </SectionCard>

        {/* ── Notifications ── */}
        <SectionCard
          icon={Bell}
          title="Notifications"
          description="Alert and notification preferences"
          delay={240}
        >
          <div className="space-y-4">
            <Toggle
              checked={settings.notifications.emailAlerts}
              onChange={(v) => update("notifications", "emailAlerts", v)}
              label="Email Alerts"
            />
            <Toggle
              checked={settings.notifications.criticalOnly}
              onChange={(v) => update("notifications", "criticalOnly", v)}
              label="Critical Severity Only"
            />
            <Toggle
              checked={settings.notifications.dailyDigest}
              onChange={(v) => update("notifications", "dailyDigest", v)}
              label="Daily Digest Email"
            />
          </div>
          <Field label="Slack Webhook URL" hint="Receive real-time alerts in your Slack channel">
            <TextInput
              value={settings.notifications.slackWebhook}
              onChange={(v) => update("notifications", "slackWebhook", v)}
              mono
              placeholder="https://hooks.slack.com/services/..."
            />
          </Field>
        </SectionCard>
      </div>

      {/* Footer info */}
      <div className="flex items-center justify-between rounded-lg border border-border bg-bg-card/50 px-5 py-3">
        <div className="flex items-center gap-4 text-xs text-text-muted">
          <span className="flex items-center gap-1.5">
            <Globe className="h-3.5 w-3.5" />
            SentinelX v1.0.0
          </span>
          <span className="flex items-center gap-1.5">
            <Clock className="h-3.5 w-3.5" />
            Uptime: 47d 12h 33m
          </span>
          <span className="flex items-center gap-1.5">
            <Mail className="h-3.5 w-3.5" />
            support@sentinelx.io
          </span>
        </div>
        <span className="text-[11px] text-text-muted/50">
          © 2026 SentinelX · All rights reserved
        </span>
      </div>
    </div>
  );
}
