/** SentinelX Dashboard — Type Definitions */

export interface User {
  id: string;
  email: string;
  full_name: string;
  role: "admin" | "analyst" | "viewer";
  is_active: boolean;
  created_at: string;
  updated_at?: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
  expires_in: number;
}

export interface WAFLog {
  id: string;
  source_ip: string;
  country_code?: string;
  request_method: string;
  request_path: string;
  matched_rule_id?: string;
  threat_type: string;
  severity: "low" | "medium" | "high" | "critical";
  action_taken: "blocked" | "logged" | "challenged";
  user_agent?: string;
  created_at: string;
}

export interface WAFRule {
  id: string;
  rule_id: string;
  name: string;
  description?: string;
  category: string;
  rule_definition: Record<string, unknown>;
  is_enabled: boolean;
  priority: number;
  action: string;
  created_at: string;
  updated_at?: string;
}

export interface BlockedIP {
  id: string;
  ip_address: string;
  reason: string;
  block_type: string;
  country_code?: string;
  blocked_until?: string;
  is_permanent: boolean;
  created_at: string;
}

export interface PhishingDomain {
  id: string;
  domain: string;
  status: "pending" | "confirmed" | "false_positive";
  risk_score?: number;
  threat_intel_data?: Record<string, unknown>;
  created_at: string;
  reviewed_at?: string;
}

export interface AIThreatSummary {
  id: string;
  waf_log_id: string;
  threat_classification: string;
  human_readable_explanation: string;
  estimated_severity: string;
  estimated_impact?: string;
  mitigation_strategies?: string[];
  llm_provider: string;
  llm_model: string;
  analysis_duration_ms?: number;
  created_at: string;
}

export interface DashboardOverview {
  total_requests_24h: number;
  blocked_threats_24h: number;
  active_blocked_ips: number;
  global_risk_score: number;
  threat_trend: { time: string; count: number }[];
  top_threat_types: { type: string; count: number }[];
  top_source_countries: { country: string; count: number }[];
  severity_distribution: Record<string, number>;
}

export interface AttackStreamEntry {
  id: string;
  timestamp: string;
  source_ip: string;
  country_code?: string;
  threat_type: string;
  severity: string;
  request_path: string;
  action_taken: string;
  matched_rule_id?: string;
}
