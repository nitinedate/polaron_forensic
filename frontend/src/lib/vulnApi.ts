import { api } from "./api";
import type {
  Asset,
  AssetList,
  AssetRisk,
  RemediationTask,
  RemediationTaskCreate,
  RemediationTaskList,
  RemediationTaskUpdate,
  ScanJob,
  ScanJobCreate,
  ScanJobUpdate,
  ScanJobSeveritySummary,
  ScanPolicy,
  ScanPolicyCreate,
  ScanPolicyUpdate,
  NetworkToken,
  NetworkTokenCreate,
  Scanner,
  ScannerCreate,
  ScannerUpdate,
  Timeline,
  VulnerabilityList,
  ReportExportCreate,
} from "./types/vuln";
import type { Case, CaseCreate, CaseList, CaseUpdate, GapMergeCandidate, ReportExport } from "./types/forensic";

export type VulnOverview = {
  dashboards: {
    enterprise_risk_score: number;
    kev_open: number;
    sla_overdue_pct: number;
    coverage_pct: number;
    critical_open?: number;
    open_findings?: number;
  };
  functionality: {
    scans_running: number;
    failed_24h: number;
    open_remediation: number;
    exceptions_pending: number;
    scanners_active?: number;
  };
  freshness?: { last_ingestion_at: string; stale: boolean };
};

export type VulnDashboardLayer = {
  layer: string;
  filters: Record<string, unknown>;
  widgets: Record<string, unknown>;
  freshness: { last_ingestion_at: string; stale: boolean };
  metric_dictionary: Record<string, string>;
  export?: Record<string, unknown>;
};

export const vulnApi = {
  getOverview: () => api.get<VulnOverview>("/api/vuln/overview"),

  getDashboard: (layer: string) => api.get<VulnDashboardLayer>(`/api/vuln/dashboards/${layer}`),

  exportDashboard: (layer: string, format = "json") =>
    api.get<VulnDashboardLayer>(`/api/vuln/dashboards/${layer}/export`, { format }),

  listExceptions: (status?: string) =>
    api.get<Array<Record<string, unknown>>>("/api/vuln/exceptions", status ? { status } : undefined),

  createException: (payload: {
    finding_id: string;
    reason: string;
    compensating_controls?: string;
    expires_at?: string;
    residual_risk?: string;
  }) => api.post<{ id: string; status: string }>("/api/vuln/exceptions", payload),

  decideException: (exceptionId: string, payload: { status: string; residual_risk?: string }) =>
    api.post<{ id: string; status: string }>(`/api/vuln/exceptions/${exceptionId}/decide`, payload),

  listEvidence: () => api.get<Array<Record<string, unknown>>>("/api/vuln/evidence"),

  createEvidence: (payload: Record<string, unknown>) =>
    api.post<{ id: string; integrity_hash: string }>("/api/vuln/evidence", payload),

  listScanners: () => api.get<Scanner[]>("/api/scanners"),

  getScanner: (scannerId: string) => api.get<Scanner>(`/api/scanners/${scannerId}`),

  createScanner: (payload: ScannerCreate) => api.post<Scanner>("/api/scanners", payload),

  updateScanner: (scannerId: string, payload: ScannerUpdate) =>
    api.patch<Scanner>(`/api/scanners/${scannerId}`, payload),

  rotateScannerAgentToken: (scannerId: string) =>
    api.post<Scanner>(`/api/scanners/${scannerId}/rotate-agent-token`),

  ensureScannerAgentRecoveryToken: (scannerId: string) =>
    api.post<Scanner>(`/api/scanners/${scannerId}/ensure-agent-recovery-token`),

  listScanPolicies: (caseId?: string) =>
    api.get<ScanPolicy[]>("/api/scan-policies", caseId ? { case_id: caseId } : undefined),

  getScanPolicy: (policyId: string) => api.get<ScanPolicy>(`/api/scan-policies/${policyId}`),

  createScanPolicy: (payload: ScanPolicyCreate) => api.post<ScanPolicy>("/api/scan-policies", payload),

  updateScanPolicy: (policyId: string, payload: ScanPolicyUpdate) =>
    api.patch<ScanPolicy>(`/api/scan-policies/${policyId}`, payload),

  listScanJobs: (caseId: string) => api.get<ScanJob[]>(`/api/cases/${caseId}/scan-jobs`),

  createScanJob: (
    caseId: string,
    payload: ScanJobCreate & { preflight_confirmed?: boolean; scanner_id?: string | null }
  ) => api.post<ScanJob>(`/api/cases/${caseId}/scan-jobs`, payload),

  listNetworkTokens: () => api.get<NetworkToken[]>("/api/scanners/network-tokens"),

  getNetworkTokenSession: () => api.get<NetworkToken | null>("/api/scanners/network-tokens/session"),

  createNetworkToken: (payload: NetworkTokenCreate) =>
    api.post<NetworkToken>("/api/scanners/network-tokens", payload),

  activateNetworkToken: (token: string) =>
    api.post<NetworkToken>("/api/scanners/network-tokens/activate", { token }),

  revokeNetworkToken: (tokenId: string) =>
    api.post<NetworkToken>(`/api/scanners/network-tokens/${tokenId}/revoke`),

  getScanJob: (jobId: string) => api.get<ScanJob>(`/api/scan-jobs/${jobId}`),

  getScanJobSeveritySummary: (jobId: string) =>
    api.get<ScanJobSeveritySummary>(`/api/scan-jobs/${jobId}/severity-summary`),

  updateScanJob: (jobId: string, payload: ScanJobUpdate) =>
    api.patch<ScanJob>(`/api/scan-jobs/${jobId}`, payload),

  deleteScanJob: (jobId: string) =>
    api.del<{ ok: boolean; id: string; status: string }>(`/api/scan-jobs/${jobId}`),

  retryScanJob: (jobId: string) => api.post<ScanJob>(`/api/scan-jobs/${jobId}/retry`),

  retryFailedScanJobs: (caseId: string) =>
    api.post<{ count: number; retried: Array<{ id: string; status: string; target_count: number }> }>(
      `/api/cases/${caseId}/scan-jobs/retry-failed`,
    ),

  listVulnerabilities: (
    caseId: string,
    query?: { page?: number; page_size?: number; severity?: string }
  ) => api.get<VulnerabilityList>(`/api/cases/${caseId}/vulnerabilities`, query),

  listAssets: (query?: { case_id?: string; page?: number; page_size?: number }) =>
    api.get<AssetList>("/api/assets", query),

  getAsset: (assetId: string) => api.get<Asset>(`/api/assets/${assetId}`),

  getAssetRisk: (assetId: string) => api.get<AssetRisk>(`/api/assets/${assetId}/risk`),

  listRemediationTasks: (query?: {
    page?: number;
    page_size?: number;
    status?: string;
    finding_id?: string;
  }) => api.get<RemediationTaskList>("/api/remediation-tasks", query),

  createRemediationTask: (payload: RemediationTaskCreate) =>
    api.post<RemediationTask>("/api/remediation-tasks", payload),

  updateRemediationTask: (taskId: string, payload: RemediationTaskUpdate) =>
    api.patch<RemediationTask>(`/api/remediation-tasks/${taskId}`, payload),

  deleteRemediationTask: (taskId: string) => api.del(`/api/remediation-tasks/${taskId}`),

  createFindingRemediation: (
    findingId: string,
    payload: { owner_id?: string; sla_due?: string; notes?: string }
  ) => api.post<RemediationTask>(`/api/findings/${findingId}/remediation`, payload),

  getTimeline: (caseId: string, limit?: number) =>
    api.get<Timeline>("/api/timeline", { case_id: caseId, limit }),

  exportReport: (jobId: string, payload: ReportExportCreate) =>
    api.post<ReportExport>(`/api/reports/${jobId}/export`, payload),

  // BRD completion — agents / credentials / snapshots (additive)
  listAgents: (lifecycle_state?: string) =>
    api.get<Array<Record<string, unknown>>>(
      "/api/vuln/agents",
      lifecycle_state ? { lifecycle_state } : undefined
    ),

  createAgent: (payload: Record<string, unknown>) =>
    api.post<Record<string, unknown>>("/api/vuln/agents", payload),

  transitionAgent: (agentId: string, payload: { lifecycle_state: string; evidence_note?: string }) =>
    api.post<Record<string, unknown>>(`/api/vuln/agents/${agentId}/transition`, payload),

  markAgentsStale: (stale_hours = 72) =>
    api.post<{ stale_count: number; stale_hours: number }>(
      `/api/vuln/agents/mark-stale?stale_hours=${stale_hours}`,
      {}
    ),

  listCredentials: () => api.get<Array<Record<string, unknown>>>("/api/vuln/credentials"),

  createCredential: (payload: { name: string; vault_ref: string; credential_type?: string }) =>
    api.post<Record<string, unknown>>("/api/vuln/credentials", payload),

  snapshotDashboard: (layer: string) =>
    api.post<Record<string, unknown>>(`/api/vuln/dashboards/${layer}/snapshot`, {}),

  listNotifications: (acknowledged?: boolean) =>
    api.get<Array<Record<string, unknown>>>(
      "/api/vuln/notifications",
      acknowledged === undefined ? undefined : { acknowledged }
    ),

  getScannerStatus: (scannerId?: string) =>
    api.get<Record<string, unknown>>(
      "/api/vuln/scanner/status",
      scannerId ? { scanner_id: scannerId } : undefined
    ),

  listCustomChecks: () => api.get<Array<Record<string, unknown>>>("/api/vuln/custom-checks"),

  createCustomCheck: (payload: Record<string, unknown>) =>
    api.post<Record<string, unknown>>("/api/vuln/custom-checks", payload),

  updateCustomCheck: (checkId: string, payload: Record<string, unknown>) =>
    api.patch<Record<string, unknown>>(`/api/vuln/custom-checks/${checkId}`, payload),

  validateFinding: (findingId: string, payload: { authorization_ref: string }) =>
    api.post<Record<string, unknown>>(`/api/vuln/findings/${findingId}/validate`, payload),

  createPciReadinessPackage: (
    caseId: string,
    payload?: { period_start?: string; period_end?: string }
  ) => api.post<Record<string, unknown>>(`/api/cases/${caseId}/pci-readiness`, payload ?? {}),

  ingestAgentFindings: (
    agentId: string,
    payload: { case_id: string; findings: Array<Record<string, unknown>> }
  ) => api.post<Record<string, unknown>>(`/api/vuln/agents/${agentId}/findings`, payload),

  // ASV external attestation workflow
  listAsvProviders: () => api.get<Array<Record<string, unknown>>>("/api/vuln/asv/providers"),

  createAsvProvider: (payload: { name: string; accreditation_id?: string; contact_email?: string }) =>
    api.post<Record<string, unknown>>("/api/vuln/asv/providers", payload),

  createAsvSubmission: (caseId: string, payload: { provider_id?: string; target_scope: string }) =>
    api.post<Record<string, unknown>>(`/api/cases/${caseId}/asv/submission`, payload),

  recordAsvAttestation: (
    submissionId: string,
    payload: {
      attestation_ref: string;
      attestation_date?: string;
      result_status?: string;
      attestation_document_ref?: string;
      notes?: string;
    }
  ) => api.post<Record<string, unknown>>(`/api/vuln/asv/submissions/${submissionId}/attestation`, payload),

  getAsvDisclaimer: () => api.get<{ disclaimer: string }>("/api/vuln/asv/disclaimer"),

  // Bounded pentest
  listPentestPlaybooks: () => api.get<Record<string, unknown>>("/api/vuln/pentest/playbooks"),

  createPentestJob: (
    caseId: string,
    payload: { authorization_ref: string; targets: string[]; playbook?: string }
  ) => api.post<Record<string, unknown>>(`/api/cases/${caseId}/pentest-jobs`, payload),

  getPentestJob: (jobId: string) => api.get<Record<string, unknown>>(`/api/vuln/pentest-jobs/${jobId}`),

  submitAgentInventory: (
    agentId: string,
    payload: { case_id: string; hostname?: string; inventory: Record<string, unknown> }
  ) => api.post<Record<string, unknown>>(`/api/vuln/agents/${agentId}/inventory`, payload),

  getOrchestratorPipeline: () =>
    api.get<{ pipeline: Array<{ engine: string; role: string }>; orchestration_enabled: boolean }>(
      "/api/vuln/orchestrator/pipeline"
    ),

  exportVulnReportCsv: (caseId: string) =>
    api.download(`/api/cases/${caseId}/vuln-report.csv`, `vuln-report-${caseId.slice(0, 8)}.csv`),

  exportVulnReportXlsx: (caseId: string) =>
    api.download(`/api/cases/${caseId}/vuln-report.xlsx`, `Solution Set-${caseId.slice(0, 8)}.xlsx`),

  getGapIntake: (caseId: string) => api.get<Record<string, unknown>>(`/api/cases/${caseId}/gap-intake`),

  saveGapIntake: (caseId: string, payload: Record<string, unknown>) =>
    api.put<Record<string, unknown>>(`/api/cases/${caseId}/gap-intake`, payload),

  exportGapReportPdf: (caseId: string, query?: { llm?: boolean }) =>
    api.download(
      `/api/cases/${caseId}/gap-report.pdf`,
      `gap-assessment-${caseId.slice(0, 8)}.pdf`,
      query?.llm ? { llm: "1" } : undefined,
      180_000,
    ),

  exportGapReportDocx: (caseId: string, query?: { llm?: boolean }) =>
    api.download(
      `/api/cases/${caseId}/gap-report.docx`,
      `gap-assessment-${caseId.slice(0, 8)}.docx`,
      query?.llm ? { llm: "1" } : undefined,
      180_000,
    ),

  /** Merge 2+ case gap reports: identical findings append IPs; different findings stay separate. */
  exportMergedGapReportPdf: (caseIds: string[], query?: { llm?: boolean }) =>
    api.download(
      `/api/cases/gap-report/merged.pdf`,
      `gap-assessment-merged-${caseIds.map((id) => id.slice(0, 8)).join("-").slice(0, 40)}.pdf`,
      {
        case_ids: caseIds.join(","),
        ...(query?.llm ? { llm: "1" } : {}),
      },
      240_000,
    ),

  getVulnReportSummary: (caseId: string) =>
    api.get<Record<string, unknown>>(`/api/cases/${caseId}/vuln-report/summary`),

  exportServiceCoverageCsv: (caseId: string) =>
    api.download(`/api/cases/${caseId}/service-coverage.csv`, `service-coverage-${caseId.slice(0, 8)}.csv`),

  importVulnReportCsv: (caseId: string, csvText: string) =>
    api.post<{ imported: number; case_id: string }>(`/api/cases/${caseId}/vuln-report/import`, {
      csv_text: csvText,
    }),

  listEngineRuns: (jobId: string) =>
    api.get<{ items: Array<Record<string, unknown>> }>(`/api/vuln/scan-jobs/${jobId}/engine-runs`),

  /** Cases for scan jobs — always the vuln API (isolated from forensic cases). */
  listCases: (query?: { page?: number; page_size?: number; status?: string }) =>
    api.get<CaseList>("/api/cases", query, { service: "vuln" }),

  createCase: (payload: CaseCreate) => api.post<Case>("/api/cases", payload, { service: "vuln" }),

  updateCase: (caseId: string, payload: CaseUpdate) =>
    api.patch<Case>(`/api/cases/${caseId}`, payload, { service: "vuln" }),

  deleteCase: (caseId: string) =>
    api.del<{ ok: boolean; id: string; deleted_scan_jobs: number }>(`/api/cases/${caseId}`, {
      service: "vuln",
    }),

  getCase: (caseId: string) => api.get<Case>(`/api/cases/${caseId}`, undefined, { service: "vuln" }),

  listGapMergeCandidates: (query?: { from_date?: string }) =>
    api.get<{ items: GapMergeCandidate[]; total: number; from_date?: string; to_date?: string }>(
      "/api/cases/gap-merge-candidates",
      query,
      { service: "vuln" },
    ),
};
