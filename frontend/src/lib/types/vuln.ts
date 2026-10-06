export interface Scanner {
  id: string;
  name: string;
  url: string;
  edition: string | null;
  status: string;
  connection_mode?: "gmp" | "edge_agent" | string;
  scanner_role?: "persistent_edge" | "portable" | "remote_vpn" | "central" | string;
  online?: boolean | null;
  openvas_ready?: boolean | null;
  agent_status_detail?: string | null;
  openvas_ready_at?: string | null;
  agent_token_hint?: string | null;
  last_heartbeat_at?: string | null;
  plugin_feed_updated_at: string | null;
  created_at: string;
  /** Present only once on create / rotate — copy immediately. */
  agent_token?: string;
  agent_token_once?: boolean;
  agent_recovery_token?: string;
  agent_recovery_token_once?: boolean;
  previous_token_grace_hours?: number;
}

export interface ScannerCreate {
  name: string;
  url?: string;
  edition?: string | null;
  api_key_ref?: string | null;
  connection_mode?: "gmp" | "edge_agent";
  scanner_role?: "persistent_edge" | "portable" | "remote_vpn" | "central";
}

export interface ScannerUpdate {
  name?: string | null;
  url?: string | null;
  edition?: string | null;
  api_key_ref?: string | null;
  status?: "active" | "disabled";
  connection_mode?: "gmp" | "edge_agent";
  scanner_role?: "persistent_edge" | "portable" | "remote_vpn" | "central";
}

export interface ScanPolicy {
  id: string;
  case_id: string | null;
  name: string;
  policy_type: string;
  scanner_id: string | null;
  settings_json: Record<string, unknown> | null;
  compliance_framework: string | null;
  created_by: string | null;
  created_at: string;
}

export interface ScanPolicyCreate {
  name: string;
  policy_type: string;
  case_id?: string | null;
  scanner_id?: string | null;
  settings_json?: Record<string, unknown> | null;
  compliance_framework?: string | null;
}

export interface ScanPolicyUpdate {
  name?: string | null;
  policy_type?: string | null;
  scanner_id?: string | null;
  settings_json?: Record<string, unknown> | null;
  compliance_framework?: string | null;
}

export interface ScanTarget {
  target: string;
  target_type?: string;
  credential_ref?: string | null;
  excluded?: boolean;
}

export interface ScanJob {
  id: string;
  case_id: string;
  policy_id: string | null;
  status: string;
  progress_pct?: number;
  progress_label?: string;
  error?: string | null;
  scheduled_at: string | null;
  started_at: string | null;
  completed_at: string | null;
  source: string;
  authorization_ref: string | null;
  scan_window_start: string | null;
  scan_window_end: string | null;
  external_scan_id: string | null;
  created_at: string;
  targets: ScanTarget[];
}

export interface ScanJobCreate {
  policy_id?: string | null;
  scanner_id?: string | null;
  scheduled_at?: string | null;
  authorization_ref?: string | null;
  scan_window_start?: string | null;
  scan_window_end?: string | null;
  targets?: ScanTarget[];
  orchestration_enabled?: boolean | null;
  network_token_id?: string | null;
}

export interface NetworkToken {
  id: string;
  name: string;
  cidr: string;
  note?: string | null;
  authorization_ref?: string | null;
  token_hint?: string | null;
  status: "issued" | "connected" | "revoked" | string;
  connected_public_ip?: string | null;
  connected_at?: string | null;
  connected_by?: string | null;
  created_by?: string | null;
  expires_at?: string | null;
  created_at?: string | null;
  token?: string;
  token_once?: boolean;
}

export interface NetworkTokenCreate {
  name: string;
  cidr: string;
  note?: string;
  authorization_ref?: string;
}

export interface ScanJobUpdate {
  status?: "pending" | "queued" | "running" | "completed" | "failed" | "cancelled";
  external_scan_id?: string | null;
}

export interface ScanJobSeverityBucket {
  severity: string;
  count: number;
  pct: number;
  hosts: string[];
}

export interface ScanJobTargetProgress {
  ip: string;
  status: string;
  activity: string;
  progress_pct?: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  engines?: Record<string, string>;
  excluded?: boolean;
}

export interface ScanJobSeveritySummary {
  job_id: string;
  status: string;
  progress_pct: number;
  progress_label?: string | null;
  error?: string | null;
  total: number;
  all_hosts: string[];
  severities: ScanJobSeverityBucket[];
  targets?: ScanJobTargetProgress[];
  service_coverage?: Record<string, {
    policy_version: string;
    coverage_complete: boolean;
    limitation: string;
    counts: Record<string, number>;
    services: { service_id: string; name: string; status: string; reason: string;
      endpoint_count: number; source_result_ids: string[]; credentialed_checks: string }[];
    ip_forwarding: { status: string; reason: string };
  }>;
  policy_snapshots?: Record<string, { port_range?: string; snapshot_status: string;
    configuration_sha256?: string; feed_versions?: Record<string, string>;
    credential_status?: Record<string, string> }>;
  accel?: { gpu_present: boolean; used_for_scan: boolean; detail: string };
  assessment?: {
    assessed: number;
    target_count: number;
    skipped: number;
    verified: boolean;
    label: string;
    clean_eligible: boolean;
    plugin_error_count?: number;
  };
}

export interface Vulnerability {
  id: string;
  case_id: string;
  scan_job_id: string | null;
  asset_id: string | null;
  plugin_id: string | null;
  plugin_family: string | null;
  cve: string | null;
  cvss: number | null;
  score_available?: boolean;
  severity: string;
  port: number | null;
  protocol: string | null;
  service: string | null;
  synopsis: string | null;
  remediation: string | null;
  status: string;
  created_at: string;
}

export interface VulnerabilityList {
  items: Vulnerability[];
  total: number;
  page: number;
  page_size: number;
}

export interface Asset {
  id: string;
  case_id: string;
  hostname: string | null;
  primary_ip: string | null;
  mac: string | null;
  os: string | null;
  asset_type: string | null;
  risk_score: number | null;
  created_at: string;
  identifiers: AssetIdentifier[];
}

export interface AssetIdentifier {
  id: string;
  id_type: string;
  value: string;
  source: string | null;
}

export interface AssetList {
  items: Asset[];
  total: number;
  page: number;
  page_size: number;
}

export interface AssetRisk {
  asset_id: string;
  risk_score: number | null;
  finding_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  top_cves: string[];
}

export interface RemediationTask {
  id: string;
  finding_id: string;
  owner_id: string | null;
  sla_due: string | null;
  status: string;
  resolution: string | null;
  rescan_job_id: string | null;
  accepted_risk_ref: string | null;
  escalation_level: number;
  created_at: string;
}

export interface RemediationTaskList {
  items: RemediationTask[];
  total: number;
  page: number;
  page_size: number;
}

export interface RemediationTaskCreate {
  finding_id: string;
  owner_id?: string | null;
  sla_due?: string | null;
  status?: "open" | "in_progress" | "resolved" | "accepted_risk";
}

export interface RemediationTaskUpdate {
  owner_id?: string | null;
  sla_due?: string | null;
  status?: "open" | "in_progress" | "resolved" | "accepted_risk";
  resolution?: string | null;
  rescan_job_id?: string | null;
  accepted_risk_ref?: string | null;
  escalation_level?: number;
}

export interface TimelineEvent {
  id: string;
  case_id: string;
  source_type: string;
  source_id: string | null;
  timestamp_utc: string;
  event_type: string;
  actor: string | null;
  asset_id: string | null;
  summary: string | null;
}

export interface Timeline {
  case_id: string;
  events: TimelineEvent[];
  total: number;
}

export interface CorrelationEdge {
  id: string;
  case_id: string;
  source_type: string;
  source_id: string;
  target_type: string;
  target_id: string;
  relation: string;
  confidence: number | null;
  explanation: string | null;
  created_at: string;
}

export interface ReportExportCreate {
  format?: "pdf" | "docx" | "html" | "json";
  template?: string | null;
  case_id?: string | null;
}
