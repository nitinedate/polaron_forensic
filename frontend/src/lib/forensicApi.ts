import {
  ApiError,
  api,
  ensureFreshAccessToken,
  refreshAccessToken,
  resolveApiUrl,
  sleep,
  tokenStore,
  type ApiService,
} from "./api";
import {
  isJobGone,
  markJobGone,
  rememberJobService,
  lookupJobService,
  serviceForJobCreate,
  serviceHeaders,
  clearJobGone,
} from "./apiRouting";
import type {
  Artifact,
  ArtifactList,
  ArtifactMediaProperties,
  ArtifactReview,
  ArtifactReviewSummary,
  ArtifactUpdate,
  Case,
  CaseCreate,
  CaseList,
  CaseMember,
  CaseUpdate,
  GapMergeCandidate,
  CategoryTree,
  ChainOfCustodyEntry,
  Checkpoint,
  PipelineHealEvent,
  AuditList,
  HumanFeedback,
  Intake,
  IntakePatch,
  Job,
  JobCreate,
  JobInventory,
  JobList,
  LogList,
  CaptureLogList,
  UnifiedLogList,
  UnifiedLogSource,
  EvidenceSearchResult,
  ProcessResult,
  ReportExport,
  ReportCatalogList,
  ReportGate,
  ReportObjectiveOption,
  ReportSection,
  ReportSectionPatch,
  ReportStartPayload,
  ReportStartResult,
  ReportTypeOption,
  ReportArtifactMappingResponse,
  AxiomArtifactsByGroupResponse,
  CaseTypeOption,
  UploadResult,
  ArtifactPreview,
  ArtifactGraph,
  JobFileTree,
  ArtifactCatalog,
  ArtifactScope,
  ArtifactScopeUpdate,
  ObjectiveProcedureScope,
  ObjectiveProcedureScopeUpdate,
  AgentDefinition,
  AgentInvokeResult,
  AgentRunList,
  AcquisitionAdapterList,
  AcquisitionPreview,
  AcquisitionStartPayload,
  AcquisitionVerification,
  AcquisitionRunDetail,
  AcquisitionRunList,
  AcquisitionRunSummary,
  DetectedDeviceList,
  MethodCoverage,
} from "./types/forensic";

function authHeaders(path?: string): Record<string, string> {
  const slug = (tokenStore.tenant() || "acme").trim().toLowerCase();
  const headers: Record<string, string> = { "X-Tenant": slug || "acme" };
  const token = tokenStore.access();
  if (token) headers["Authorization"] = `Bearer ${token}`;
  if (path) Object.assign(headers, serviceHeaders(path));
  return headers;
}

async function authFetch(path: string, init: RequestInit = {}): Promise<Response> {
  const headers: Record<string, string> = {
    ...authHeaders(path),
    ...(init.headers as Record<string, string>),
  };

  const res = await fetch(resolveApiUrl(path), { ...init, headers });
  if (!res.ok) {
    const text = await res.text();
    let data: { error?: { code?: string; message?: string } } | null = null;
    try {
      data = JSON.parse(text);
    } catch {
      /* ignore */
    }
    throw new ApiError(
      res.status,
      data?.error?.code || "error",
      data?.error?.message || res.statusText
    );
  }
  return res;
}

function parseUploadResponse(xhr: XMLHttpRequest): UploadResult {
  const text = xhr.responseText;
  if (xhr.status < 200 || xhr.status >= 300) {
    let data: { error?: { code?: string; message?: string } } | null = null;
    try {
      data = JSON.parse(text);
    } catch {
      /* ignore */
    }
    throw new ApiError(
      xhr.status,
      data?.error?.code || "error",
      data?.error?.message || xhr.statusText || "upload failed"
    );
  }
  return JSON.parse(text) as UploadResult;
}

function uploadMultipartOnce(
  path: string,
  form: FormData,
  onProgress?: (pct: number) => void
): Promise<UploadResult> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", resolveApiUrl(path));
    for (const [k, v] of Object.entries(authHeaders(path))) {
      xhr.setRequestHeader(k, v);
    }
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable && onProgress) {
        onProgress(Math.round((100 * e.loaded) / e.total));
      }
    };
    xhr.onload = () => {
      try {
        resolve(parseUploadResponse(xhr));
      } catch (err) {
        reject(err);
      }
    };
    xhr.onerror = () =>
      reject(
        new ApiError(0, "network_error", "Upload failed — check your connection and try again.")
      );
    xhr.ontimeout = () =>
      reject(new ApiError(0, "timeout", "Upload timed out — the file may be too large or the server is busy."));
    xhr.timeout = 0;
    xhr.send(form);
  });
}

async function uploadMultipart(
  path: string,
  form: FormData,
  onProgress?: (pct: number) => void
): Promise<UploadResult> {
  await ensureFreshAccessToken();

  let authRetries = 1;
  for (let attempt = 0; attempt < 6; attempt++) {
    try {
      return await uploadMultipartOnce(path, form, onProgress);
    } catch (err) {
      if (err instanceof ApiError && err.status === 401 && authRetries > 0) {
        const refreshed = await refreshAccessToken();
        authRetries -= 1;
        if (refreshed) {
          await ensureFreshAccessToken();
          continue;
        }
      }
      if (err instanceof ApiError && err.status === 429 && attempt < 5) {
        await sleep(Math.min(2000 * 2 ** attempt, 30_000));
        await ensureFreshAccessToken();
        continue;
      }
      throw err;
    }
  }
  throw new ApiError(429, "rate_limited", "too many requests");
}


// ---------------------------------------------------------------------------
// Live mobile acquisition — UFED 4PC reference architecture
// ---------------------------------------------------------------------------
//
// A collection is queued, not awaited. Holding an HTTP request open for the
// hours a full-filesystem collection can take means a dropped connection
// orphans the run and the examiner never sees the outcome — even though the
// server completed it and sealed the evidence correctly. `startAcquisition`
// therefore returns a run id, and progress arrives over SSE (acquisitionSse.ts).

export const acquisitionApi = {
  /** Which device-access technologies this workstation can actually use. */
  listAdapters: () =>
    api.get<AcquisitionAdapterList>("/api/acquisition/adapters", undefined, {
      timeoutMs: 20_000,
    }),

  /** Architecture section 6 method reference, including per-method coverage caveats. */
  listMethods: () =>
    api.get<{ methods: (MethodCoverage & { intrusiveness_rank: number })[]; selection_principle: string }>(
      "/api/acquisition/methods",
      undefined,
      { timeoutMs: 20_000 },
    ),

  /** Architecture section 7 step 1 — scan for connected devices. */
  detectDevices: () =>
    api.get<DetectedDeviceList>("/api/acquisition/devices", undefined, {
      timeoutMs: 60_000,
    }),

  /**
   * Architecture section 7 steps 2-4 — identify the device, resolve capability and
   * return preparation instructions. Separate from `startAcquisition` on purpose:
   * the examiner must see what each method does NOT cover before authorising one.
   */
  previewDevice: (adapter: string, deviceId: string) =>
    api.post<AcquisitionPreview>(
      "/api/acquisition/preview",
      { adapter, device_id: deviceId },
      { timeoutMs: 120_000 },
    ),

  /**
   * Architecture section 7 steps 5-10 — queue the collection.
   *
   * Returns as soon as the run is accepted, not when it finishes. Progress is
   * streamed separately, so a dropped connection cannot orphan a multi-hour
   * collection. A 409 means the device is already being acquired.
   */
  startAcquisition: (payload: AcquisitionStartPayload) =>
    api.post<AcquisitionRunSummary>("/api/acquisition/start", payload, {
      timeoutMs: 60_000,
    }),

  /** Runs this workstation has started. */
  listRuns: (activeOnly = false) =>
    api.get<AcquisitionRunList>("/api/acquisition/runs", { active_only: activeOnly }, {
      timeoutMs: 20_000,
    }),

  /** Full state of one run, including the result once complete. */
  getRun: (runId: string) =>
    api.get<AcquisitionRunDetail>(`/api/acquisition/runs/${runId}`, undefined, {
      timeoutMs: 20_000,
    }),

  /** Rebuild run history from the case folder after an API restart. */
  recoverRuns: (caseRoot: string, caseId: string) =>
    api.get<{ runs: AcquisitionRunSummary[] }>(
      "/api/acquisition/runs/recover",
      { case_root: caseRoot, case_id: caseId },
      { timeoutMs: 30_000 },
    ),

  /** Rehydrate the newest sealed collection when the in-memory run was lost. */
  recoverRecentRuns: (caseRoot = "/evidence/cases") =>
    api.get<{ runs: AcquisitionRunSummary[] }>(
      "/api/acquisition/runs/recover-recent",
      { case_root: caseRoot },
      { timeoutMs: 60_000 },
    ),

  /** Stop the host collection immediately and keep files already written. */
  cancelRun: (runId: string) =>
    api.post<{ accepted: boolean; status: string; message: string }>(
      `/api/acquisition/runs/${runId}/cancel`,
      {},
      { timeoutMs: 8_000 },
    ),

  /** Stop the collection and permanently delete this run's extracted files. */
  removeRun: (
    runId: string,
    body?: {
      run_name?: string;
      case_id?: string;
      progress_file?: string;
      paths?: Record<string, string>;
    },
  ) =>
    api.post<{ accepted: boolean; status: string; message: string; removed?: string[] }>(
      `/api/acquisition/runs/${runId}/remove`,
      body || {},
      { timeoutMs: 60_000 },
    ),

  /** Architecture section 12 — re-verify a stored extraction against its manifest. */
  verifyExtraction: (extractionPath: string, manifestPath: string) =>
    api.post<AcquisitionVerification & { run_name: string; interpretation: string }>(
      "/api/acquisition/verify",
      { extraction_path: extractionPath, manifest_path: manifestPath },
      { timeoutMs: 30 * 60 * 1000 },
    ),
};

export type HostFolderListing = {
  status?: "idle" | "running" | "done";
  path?: string;
  count: number;
  entries: { name: string; kind: string; size_bytes: number | null }[];
  segment_count: number;
  segments: string[];
  elapsed_sec?: number;
};

export const forensicApi = {
  // Jobs
  listJobs: (
    query?: { page?: number; page_size?: number; status?: string; type?: string; case_id?: string },
    extra?: { service?: ApiService },
  ) => {
    const service =
      extra?.service ??
      (query?.type === "android_mobile" || query?.type === "android_backup"
        ? "mobile-android"
        : query?.type === "ios_mobile" || query?.type === "ios_backup"
          ? "mobile-ios"
          : query?.type === "mobile_extraction"
            ? "mobile-extract"
            : undefined);
    return api.get<JobList>("/api/jobs", query, { timeoutMs: 8_000, ...extra, service }).then((result) => {
      if (service && service !== "vuln") {
        for (const job of result.items ?? []) rememberJobService(job.id, service);
      }
      return result;
    });
  },

  getJob: async (jobId: string, extra?: { service?: ApiService }) => {
    const service = extra?.service || lookupJobService(jobId);
    try {
      const job = await api.get<Job>(`/api/jobs/${jobId}`, undefined, { timeoutMs: 8_000, service });
      if (service) rememberJobService(jobId, service);
      clearJobGone(jobId);
      return job;
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) markJobGone(jobId);
      throw e;
    }
  },

  getJobInventory: (jobId: string) =>
    api.get<JobInventory>(`/api/jobs/${jobId}/inventory`, undefined, { timeoutMs: 60_000 }),

  createJob: async (payload: JobCreate) => {
    const service = serviceForJobCreate(payload.type, payload.source_type, payload.mobile_os);
    const job = await api.post<Job>("/api/jobs", payload, { timeoutMs: 20_000, service });
    if (job?.id) rememberJobService(job.id, service);
    return job;
  },

  deleteJob: async (jobId: string, extra?: { service?: ApiService }) => {
    const pinned = extra?.service || lookupJobService(jobId);
    const service = pinned || "forensic";
    const result = await api.del<{ ok: boolean; deleted: boolean; job_id: string; hard: boolean }>(
      `/api/jobs/${jobId}`,
      { timeoutMs: 120_000, service }
    );
    markJobGone(jobId);
    return result;
  },

  processJob: (jobId: string) => api.post<ProcessResult>(`/api/jobs/${jobId}/process`, undefined, { timeoutMs: 120_000 }),

  stopJob: (jobId: string) => api.post<ProcessResult>(`/api/jobs/${jobId}/stop`, undefined, { timeoutMs: 30_000 }),

  resumeJob: (jobId: string) => api.post<ProcessResult>(`/api/jobs/${jobId}/resume`),

  enrichJob: (jobId: string) => api.post<ProcessResult>(`/api/jobs/${jobId}/enrich`),

  retrieve: (jobId: string, body: { query: string; filters?: Record<string, unknown>; top_k?: number; include_answer?: boolean }) =>
    api.post<{
      items: Array<Record<string, unknown>>;
      total: number;
      answer?: string | null;
      confidence?: string | null;
      grounded?: boolean;
      facts?: Record<string, unknown>;
      citations?: Array<Record<string, unknown>>;
    }>(`/api/jobs/${jobId}/retrieve`, body, { timeoutMs: 300_000 }),

  queryUnderstand: (jobId: string, query: string) =>
    api.post<{
      dimensions?: string[];
      operating_systems?: string[];
      categories?: string[];
      artifact_ids?: string[];
      intent?: string;
    }>(`/api/jobs/${jobId}/query/understand`, { query }, { timeoutMs: 30_000 }),

  continueExtract: (jobId: string) =>
    api.post<ProcessResult>(`/api/jobs/${jobId}/extract/continue`, undefined, { timeoutMs: 30_000 }),

  continuePipelineBatches: (
    jobId: string,
    opts?: { parallel_extract?: number; index_workers?: number }
  ) =>
    api.post<ProcessResult>(`/api/jobs/${jobId}/pipeline/continue-batches`, opts, { timeoutMs: 30_000 }),

  resumeRag: (jobId: string) =>
    api.post<ProcessResult>(`/api/jobs/${jobId}/pipeline/resume-rag`, undefined, { timeoutMs: 30_000 }),

  listProgressEvents: (jobId: string) =>
    api.get<{ job_id: string; events: Array<{ id: number; stage?: string; decision: string; reason: string; created_at: string }> }>(`/api/jobs/${jobId}/pipeline/progress-events`),

  listPipelineHealEvents: (jobId: string, query?: { limit?: number }) =>
    api.get<{ job_id: string; count: number; events: PipelineHealEvent[] }>(
      `/api/jobs/${jobId}/pipeline/heal-events`,
      query,
      { timeoutMs: 20_000 }
    ),

  listCheckpoints: (jobId: string) => api.get<Checkpoint[]>(`/api/jobs/${jobId}/checkpoints`),

  listLogs: (jobId: string, query?: { from?: string; to?: string; limit?: number }) => {
    if (isJobGone(jobId)) {
      throw new ApiError(404, "not_found", "Job not found");
    }
    const pinned = lookupJobService(jobId);
    return api.get<LogList>(`/api/jobs/${jobId}/logs`, query, {
      timeoutMs: 30_000,
      service: pinned,
    });
  },

  listUnifiedLogs: (query?: {
    source_type?: string;
    origin?: string;
    level?: string;
    job_id?: string;
    from?: string;
    to?: string;
    q?: string;
    page?: number;
    page_size?: number;
  }) => api.get<UnifiedLogList>("/api/logs", query, { timeoutMs: 8_000 }),

  listLogSources: (query?: { source_type?: string; origin?: string }) =>
    api.get<{ items: UnifiedLogSource[]; total: number }>("/api/logs/sources", query, { timeoutMs: 20_000 }),

  listCaptureLogs: (jobId: string, query?: { from?: string; to?: string; limit?: number }) =>
    api.get<CaptureLogList>(`/api/jobs/${jobId}/capture-logs`, query),
  downloadEvidenceLog: (jobId: string, fmt: "csv" | "txt" = "csv") =>
    api.download(`/api/jobs/${jobId}/evidence-log`, `evidence_log.${fmt}`, { fmt }),
  downloadSuspiciousLog: (jobId: string, fmt: "csv" | "jsonl" = "csv") =>
    api.download(`/api/jobs/${jobId}/suspicious-log`, `suspicious_findings.${fmt}`, { fmt }),

  // Evidence upload (multipart) — one file at a time with byte progress
  uploadEvidenceFile: (
    jobId: string,
    file: File,
    onProgress?: (pct: number) => void,
    opts?: { register?: boolean; auto_process?: boolean; expected_total?: number }
  ): Promise<UploadResult> => {
    const form = new FormData();
    form.append("files", file);
    form.append("register_now", opts?.register === false ? "false" : "true");
    form.append("auto_process", opts?.auto_process ? "true" : "false");
    if (opts?.expected_total && opts.expected_total > 0) {
      form.append("expected_total", String(opts.expected_total));
    }
    return uploadMultipart(`/api/jobs/${jobId}/evidence`, form, onProgress);
  },

  uploadDirectoryFile: (
    jobId: string,
    file: File,
    relativePath: string,
    onProgress?: (pct: number) => void,
    opts?: { register?: boolean; auto_process?: boolean; expected_total?: number }
  ): Promise<UploadResult> => {
    const form = new FormData();
    form.append("files", file);
    form.append("paths", relativePath);
    form.append("register_now", opts?.register === false ? "false" : "true");
    form.append("auto_process", opts?.auto_process ? "true" : "false");
    if (opts?.expected_total && opts.expected_total > 0) {
      form.append("expected_total", String(opts.expected_total));
    }
    return uploadMultipart(`/api/jobs/${jobId}/evidence/directory`, form, onProgress);
  },

  uploadEvidence: async (jobId: string, files: File[]): Promise<UploadResult> => {
    const form = new FormData();
    for (const f of files) form.append("files", f);
    const res = await authFetch(`/api/jobs/${jobId}/evidence`, { method: "POST", body: form });
    return res.json();
  },

  uploadDirectory: async (jobId: string, files: File[], paths: string[]): Promise<UploadResult> => {
    const form = new FormData();
    files.forEach((f, i) => {
      form.append("files", f);
      form.append("paths", paths[i] ?? f.name);
    });
    const res = await authFetch(`/api/jobs/${jobId}/evidence/directory`, {
      method: "POST",
      body: form,
    });
    return res.json();
  },

  registerSegmentUpload: (
    jobId: string,
    files: File[],
    onProgress?: (pct: number) => void
  ) => {
    const form = new FormData();
    for (const f of files) form.append("files", f, f.name);
    return uploadMultipart(`/api/jobs/${jobId}/evidence/register-segments`, form, onProgress);
  },

  beginClientUpload: (jobId: string, expectedFiles: number) =>
    api.post<{
      job_id: string;
      status: string;
      download_agent: string;
      expected_files: number;
      received_files: number;
      parallelism: number;
      message: string;
    }>(
      `/api/jobs/${jobId}/evidence/begin-client-upload`,
      undefined,
      { timeoutMs: 30_000, query: { expected_files: expectedFiles } }
    ),

  completeClientUpload: (jobId: string, autoProcess = false): Promise<UploadResult> =>
    api.post<UploadResult>(
      `/api/jobs/${jobId}/evidence/complete-upload`,
      undefined,
      { timeoutMs: 600_000, query: { auto_process: autoProcess } }
    ),

  listHostFolder: (
    jobId: string,
    payload: { path?: string; drive?: string; browse_path?: string }
  ) =>
    api.post<HostFolderListing>(`/api/jobs/${jobId}/evidence/list-folder`, payload, {
      timeoutMs: 120_000,
    }),

  /** Poll a background List folder run (status: idle | running | done). */
  listHostFolderStatus: (jobId: string) =>
    api.get<HostFolderListing>(`/api/jobs/${jobId}/evidence/list-folder/status`, undefined, {
      timeoutMs: 30_000,
    }),

  ingestHostPath: (
    jobId: string,
    payload: {
      path?: string;
      source_type?: string;
      recursive?: boolean;
      selected_names?: string[];
      auto_process?: boolean;
      drive?: string;
      browse_path?: string;
      skip_folder_list?: boolean;
    }
  ) =>
    api.post<{
      job_id: string;
      status: string;
      message: string;
      processing_queued: boolean;
      accepted: UploadResult["accepted"];
      skipped: string[];
    }>(
      `/api/jobs/${jobId}/evidence/ingest-path`,
      payload,
      { timeoutMs: 300_000 }
    ),

  previewHostEvidence: (
    jobId: string,
    params?: { path?: string; source_type?: string }
  ) =>
    api.get<{
      configured: boolean;
      container_mount: string | null;
      host_evidence_path: string;
      expected_job_folder: string;
      resolved_folder: string | null;
      source_type: string;
      items: { name: string; size_bytes: number | null }[];
      item_count: number;
      error: string | null;
      ready_to_register: boolean;
    }>(`/api/jobs/${jobId}/evidence/host-preview`, params, { timeoutMs: 60_000 }),

  browseHostEvidence: (
    jobId: string,
    params?: { path?: string; drive?: string; host_path?: string; source_type?: string },
    opts?: { timeoutMs?: number }
  ) =>
    api.get<{
      configured: boolean;
      host_evidence_path: string;
      host_root: string;
      drive_root: string;
      current_path: string;
      display_path: string;
      parent_path: string | null;
      entries: {
        name: string;
        kind: string;
        size_bytes: number | null;
        selectable: boolean;
        ios_backup: boolean;
        android_backup: boolean;
        segment_base: string | null;
        segment_part: number | null;
        segment_set: string[];
        segment_count: number;
        drive_key: string | null;
        mounted?: boolean;
      }[];
      folder_segment_count: number;
      folder_segments: string[];
      drives: { key: string; label: string; host_path: string; container_path: string }[];
      error: string | null;
      mount_hint: string | null;
    }>(`/api/jobs/${jobId}/evidence/host-browse`, params, {
      timeoutMs: opts?.timeoutMs ?? 120_000,
    }),

  resolveHostFolder: (
    jobId: string,
    body: {
      filenames: string[];
      folder_hint?: string;
      relative_paths?: string[];
      file_sizes?: Record<string, number>;
    }
  ) =>
    api.post<{
      path: string | null;
      segment_count: number;
      error: string | null;
      source_residency?: "server_local";
      verified_by?: "filename" | "filename_size";
    }>(
      `/api/jobs/${jobId}/evidence/resolve-folder`,
      body,
      { timeoutMs: 120_000 }
    ),

  getHostMountInfo: (jobId: string) =>
    api.get<{
      configured: boolean;
      host_root: string;
      container_mount: string | null;
      drives: { key: string; label: string; host_path: string; container_path: string }[];
      hint: string;
    }>(`/api/jobs/${jobId}/evidence/host-mount`),

  // Artifacts
  listArtifacts: (
    jobId: string,
    query?: {
      page?: number;
      page_size?: number;
      category?: string;
      sub_category?: string;
      catalog_key?: string;
      catalog_section?: string;
      /** Mobile board family — returns all matching files for left/right browse. */
      family?: string;
      scope?: "all" | "unclassified" | "extensionless" | "tiny";
      /** person | conversation | album | flat — person/group identity (default for chats). */
      group_by?: "person" | "conversation" | "album" | "flat" | string;
      /** person_id, conversation_id, or album_id — full thread / files inside that group. */
      group_id?: string;
      /** Thread tabs: all | current | deleted | media | calls */
      message_filter?: "all" | "current" | "deleted" | "media" | "calls" | string;
      /** File forensics tabs: all | deleted | photos | videos | documents | extensionless | anomalous | modified | with_dates */
      file_filter?: string;
      type?: string;
      from?: string;
      to?: string;
      q?: string;
    }
  ) => {
    const family = String(query?.family || "");
    const heavy =
      family.includes("deleted") ||
      Boolean(query?.group_id) ||
      family === "whatsapp_messages" ||
      family === "whatsapp_deleted_messages";
    return api.get<ArtifactList>(`/api/jobs/${jobId}/artifacts`, query, {
      timeoutMs: heavy ? 300_000 : 120_000,
    });
  },

  getEvidenceCoverage: (jobId: string) =>
    api.get<{
      job_id: string;
      total_files: number;
      total_bytes: number;
      extensionless_count: number;
      extensionless_tiny_le_1kb: number;
      unclassified_count: number;
      tiny_le_1kb_count: number;
      by_extension: { extension: string; count: number; bytes: number; tiny_le_1kb: number }[];
      notes: string[];
    }>(`/api/jobs/${jobId}/artifacts/evidence-coverage`, undefined, { timeoutMs: 60_000 }),

  getArtifactCategories: (jobId: string) =>
    api.get<CategoryTree>(`/api/jobs/${jobId}/artifacts/categories`, undefined, { timeoutMs: 60_000 }),

  getArtifact: (jobId: string, artifactId: string) =>
    api.get<Artifact>(`/api/jobs/${jobId}/artifacts/${artifactId}`, undefined, { timeoutMs: 30_000 }),

  getArtifactProperties: (jobId: string, artifactId: string) =>
    api.get<ArtifactMediaProperties>(`/api/jobs/${jobId}/artifacts/${artifactId}/properties`, undefined, {
      timeoutMs: 180_000,
    }),

  getArtifactReview: (jobId: string, artifactId: string) =>
    api.get<ArtifactReview>(`/api/jobs/${jobId}/artifacts/${artifactId}/review`, undefined, { timeoutMs: 60_000 }),

  getArtifactReviewSummary: (jobId: string, limit = 120) =>
    api.get<ArtifactReviewSummary>(`/api/jobs/${jobId}/artifact-review`, { limit }, { timeoutMs: 120_000 }),

  getPriorityEvidence: (jobId: string, family: string, page = 1) =>
    api.get<import("./types/forensic").PriorityEvidencePage>(`/api/jobs/${jobId}/priority-evidence`, { family, page, page_size: 50 }, { timeoutMs: 60_000 }),

  getSuspiciousActivity: (jobId: string, page = 1) =>
    api.get<import("./types/forensic").SuspiciousActivityPage>(`/api/jobs/${jobId}/suspicious-activity`, { page, page_size: 50 }),

  getMediaObservations: (jobId: string, page = 1, flagged_only = true) =>
    api.get<import("./types/forensic").MediaObservationsPage>(`/api/jobs/${jobId}/media-observations`, { page, flagged_only, page_size: 50 }, { timeoutMs: 60_000 }),

  getMediaObservationFrame: (jobId: string, artifactId: string, frame: number) =>
    api.get<{ data_url: string; sha256: string; timestamp_seconds: number | null }>(`/api/jobs/${jobId}/media-observations/${artifactId}/frames/${frame}`, undefined, { timeoutMs: 60_000 }),

  downloadMediaObservations: (jobId: string) =>
    api.download(`/api/jobs/${jobId}/media-observations/report`, "suspicious-activity-observations.md"),

  updateArtifact: (jobId: string, artifactId: string, payload: ArtifactUpdate) =>
    api.patch<Artifact>(`/api/jobs/${jobId}/artifacts/${artifactId}`, payload),

  getArtifactPreview: (jobId: string, artifactId: string) =>
    api.get<ArtifactPreview>(`/api/jobs/${jobId}/artifacts/${artifactId}/preview`, undefined, {
      timeoutMs: 120_000,
    }),

  /** Resolve a board/sample path to an openable artifact row. */
  resolveArtifactByPath: (jobId: string, path: string) =>
    api.get<Artifact>(`/api/jobs/${jobId}/artifacts/resolve-path`, { path }, { timeoutMs: 60_000 }),

  /** Fetch raw artifact bytes (authenticated) for inline preview or new-tab viewing. */
  fetchArtifactContent: async (
    jobId: string,
    artifactId: string,
    opts?: { download?: boolean }
  ): Promise<Blob> => {
    const qs = opts?.download ? "?download=1" : "";
    const res = await authFetch(`/api/jobs/${jobId}/artifacts/${artifactId}/content${qs}`);
    return res.blob();
  },

  /**
   * Open artifact content in a new browser tab — size-independent.
   * Prefer response Content-Type over any preview hint (preview may wrongly be text/plain).
   * Non-inlineable types download as a named file — never open binary as text.
   */
  openArtifactContent: async (jobId: string, artifactId: string, contentType?: string) => {
    const res = await authFetch(`/api/jobs/${jobId}/artifacts/${artifactId}/content`);
    const cd = res.headers.get("Content-Disposition") || "";
    const match = /filename\*?=(?:UTF-8''|")?([^\";]+)/i.exec(cd);
    const filename = match
      ? decodeURIComponent(match[1].replace(/"/g, "").trim())
      : `artifact-${artifactId.slice(0, 8)}.bin`;
    const blob = await res.blob();
    const responseType = (res.headers.get("Content-Type") || blob.type || "").split(";")[0].trim();
    // Never let a stale preview MIME (e.g. text/plain hex) override a binary response.
    let type = responseType || "application/octet-stream";
    if (contentType) {
      const hint = contentType.split(";")[0].trim();
      const responseIsBinary =
        !responseType ||
        /^(application\/octet-stream|application\/zip|application\/msword|application\/vnd\.|image\/|audio\/|video\/|application\/pdf)/i.test(
          responseType
        );
      const hintIsTextPlain = /^text\/plain$/i.test(hint);
      if (!(hintIsTextPlain && responseIsBinary)) {
        // Allow hint only when it upgrades a generic type in the same family (e.g. HEIC→JPEG).
        if (!responseType || responseType === "application/octet-stream" || hint.startsWith(responseType.split("/")[0])) {
          if (!hintIsTextPlain || /^text\//i.test(responseType)) {
            type = hint || type;
          }
        }
      }
    }
    const url = URL.createObjectURL(new Blob([await blob.arrayBuffer()], { type }));
    const inlineable = /^(image\/|audio\/|video\/|text\/|application\/pdf)/i.test(type);
    if (!inlineable) {
      const a = document.createElement("a");
      a.href = url;
      a.download = filename || `artifact-${artifactId.slice(0, 8)}.bin`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 120_000);
      return;
    }
    const opened = window.open(url, "_blank", "noopener,noreferrer");
    if (!opened) {
      const a = document.createElement("a");
      a.href = url;
      a.download = filename || `artifact-${artifactId.slice(0, 8)}.bin`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 120_000);
      return;
    }
    window.setTimeout(() => URL.revokeObjectURL(url), 300_000);
  },

  /** Always save the original file (photos, audio, video, documents). */
  downloadArtifactContent: async (jobId: string, artifactId: string, filenameHint?: string) => {
    const res = await authFetch(`/api/jobs/${jobId}/artifacts/${artifactId}/content?download=1`);
    const cd = res.headers.get("Content-Disposition") || "";
    const match = /filename\*?=(?:UTF-8''|")?([^\";]+)/i.exec(cd);
    const filename = match
      ? decodeURIComponent(match[1].replace(/"/g, "").trim())
      : filenameHint || `artifact-${artifactId.slice(0, 8)}.bin`;
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 60_000);
  },

  fetchEmailAttachmentContent: async (jobId: string, artifactId: string, partIndex: number): Promise<Blob> => {
    const res = await authFetch(
      `/api/jobs/${jobId}/artifacts/${artifactId}/email-attachments/${partIndex}/content`
    );
    return res.blob();
  },

  openEmailAttachmentContent: async (
    jobId: string,
    artifactId: string,
    partIndex: number,
    contentType?: string
  ) => {
    const res = await authFetch(
      `/api/jobs/${jobId}/artifacts/${artifactId}/email-attachments/${partIndex}/content`
    );
    const cd = res.headers.get("Content-Disposition") || "";
    const match = /filename\*?=(?:UTF-8''|")?([^\";]+)/i.exec(cd);
    const filename = match
      ? decodeURIComponent(match[1].replace(/"/g, "").trim())
      : `attachment-${partIndex}`;
    const blob = await res.blob();
    const responseType = (res.headers.get("Content-Type") || blob.type || "").split(";")[0].trim();
    let type = responseType || contentType || "application/octet-stream";
    if (contentType) {
      const hint = contentType.split(";")[0].trim();
      if (!/^text\/plain$/i.test(hint) || /^text\//i.test(responseType)) {
        if (!responseType || responseType === "application/octet-stream") {
          type = hint;
        }
      }
    }
    const url = URL.createObjectURL(new Blob([await blob.arrayBuffer()], { type }));
    const inlineable = /^(image\/|audio\/|video\/|text\/|application\/pdf)/i.test(type);
    if (!inlineable) {
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 120_000);
      return;
    }
    const opened = window.open(url, "_blank", "noopener,noreferrer");
    if (!opened) {
      const a = document.createElement("a");
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.setTimeout(() => URL.revokeObjectURL(url), 120_000);
      return;
    }
    window.setTimeout(() => URL.revokeObjectURL(url), 120_000);
  },

  downloadEmailAttachmentContent: async (
    jobId: string,
    artifactId: string,
    partIndex: number,
    filenameHint?: string
  ) => {
    const res = await authFetch(
      `/api/jobs/${jobId}/artifacts/${artifactId}/email-attachments/${partIndex}/content`
    );
    const cd = res.headers.get("Content-Disposition") || "";
    const match = /filename\*?=(?:UTF-8''|")?([^";]+)/i.exec(cd);
    const filename = match
      ? decodeURIComponent(match[1].replace(/"/g, "").trim())
      : filenameHint || `attachment-${partIndex}`;
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 120_000);
  },

  getArtifactGraph: (jobId: string, artifactId: string) =>
    api.get<ArtifactGraph>(`/api/jobs/${jobId}/artifacts/${artifactId}/graph`),

  getJobFileTree: (jobId: string) => api.get<JobFileTree>(`/api/jobs/${jobId}/file-tree`),

  // Intake (job-scoped)
  getIntake: (jobId: string) => api.get<Intake>(`/api/jobs/${jobId}/intake`),

  patchIntake: (jobId: string, payload: IntakePatch) =>
    api.patch<Intake>(`/api/jobs/${jobId}/intake`, payload),

  captureWhatsAppKey: (jobId: string) =>
    api.post<import("./types/forensic").WhatsAppKeyCaptureResult>(`/api/jobs/${jobId}/intake/whatsapp-key/capture`, {}, { timeoutMs: 60_000 }),

  uploadWhatsAppKey: (jobId: string, file: File) => {
    const body = new FormData();
    body.append("file", file);
    return api.post<import("./types/forensic").WhatsAppKeyCaptureResult>(`/api/jobs/${jobId}/intake/whatsapp-key/file`, body);
  },

  // Report (jobs service start + reporting service sections)
  listReportTypes: () => api.get<{ items: ReportTypeOption[] }>("/api/jobs/report/types"),

  listCaseTypes: () => api.get<{ items: CaseTypeOption[] }>("/api/jobs/report/case-types"),

  listReportObjectives: (reportType?: string) =>
    api.get<{ items: ReportObjectiveOption[]; report_type?: string; recommended_ids?: string[] }>(
      "/api/jobs/report/objectives",
      reportType ? { report_type: reportType } : undefined
    ),

  listReportArtifactMapping: (reportType?: string, platform = "Windows") =>
    api.get<ReportArtifactMappingResponse>(
      "/api/jobs/report/artifact-mapping",
      { report_type: reportType, platform }
    ),

  listCatalogArtifactsByGroup: (platform = "Windows", category?: string) =>
    api.get<AxiomArtifactsByGroupResponse>(
      "/api/jobs/report/catalog-artifacts-by-group",
      { platform, category }
    ),
  listAxiomArtifactsByGroup: (platform = "Windows", category?: string) =>
    api.get<AxiomArtifactsByGroupResponse>(
      "/api/jobs/report/catalog-artifacts-by-group",
      { platform, category }
    ),

  listArtifactCatalog: () => api.get<ArtifactCatalog>("/api/jobs/report/artifact-catalog"),

  getArtifactScope: (jobId: string) =>
    api.get<ArtifactScope>(`/api/jobs/${jobId}/artifact-scope`, undefined, { timeoutMs: 60_000 }),

  refreshArtifactScope: (jobId: string) =>
    api.post<ArtifactScope>(`/api/jobs/${jobId}/artifact-scope/refresh`, {}, { timeoutMs: 300_000 }),

  getMobileArtifactBoard: (jobId: string, opts?: { refresh?: boolean }) =>
    api.get<{
      job_id: string;
      total_files: number;
      families_available: number;
      families_total: number;
      acquisition_methods?: string[];
      mtp_only?: boolean;
      note?: string;
      packages_scanned?: number;
      rows: Array<{
        key: string;
        label: string;
        category: string;
        count: number;
        description: string;
        available: boolean;
        sample_paths?: string[];
        primary_path?: string | null;
        artifact_ids?: string[];
        primary_artifact_id?: string | null;
        catalog_key?: string | null;
        browse_query?: string | null;
        limitation?: string | null;
      }>;
    }>(
      `/api/jobs/${jobId}/mobile/artifact-board`,
      opts?.refresh ? { refresh: true } : undefined,
      { timeoutMs: 120_000 }
    ),

  getMobileNormalizedArtifacts: (
    jobId: string,
    opts?: { filter?: string; domain?: string; state?: string; limit?: number; offset?: number }
  ) =>
    api.get<{
      job_id: string;
      filter?: string | null;
      counts?: { total_artifacts?: number; inventory_total?: number; by_domain?: Record<string, Record<string, number>> };
      total: number;
      artifacts: Array<{
        artifact_id: string;
        artifact_type: string;
        source_domain: string;
        timestamp_utc?: string | null;
        state?: string;
        ui_label?: string;
        data?: Record<string, unknown>;
        forensic?: Record<string, unknown>;
        examiner_status?: string;
      }>;
    }>(`/api/jobs/${jobId}/mobile/normalized-artifacts`, opts, { timeoutMs: 60_000 }),

  getMobileTimeline: (jobId: string, opts?: { limit?: number }) =>
    api.get<{
      job_id: string;
      total: number;
      events: Array<{
        artifact_id: string;
        artifact_type: string;
        source_domain: string;
        timestamp_utc?: string | null;
        state?: string;
        ui_label?: string;
        data?: Record<string, unknown>;
        forensic?: Record<string, unknown>;
      }>;
    }>(`/api/jobs/${jobId}/mobile/timeline`, opts),

  reviewMobileArtifact: (
    jobId: string,
    artifactId: string,
    body: { decision: string; note?: string; examiner?: string }
  ) => api.post<{ job_id: string; artifact_id: string; decision: string }>(
    `/api/jobs/${jobId}/mobile/artifacts/${artifactId}/review`,
    body
  ),

  runMobileAnalysis: (jobId: string) =>
    api.post<{ status: string; reason?: string; detail?: string; artifacts?: number; inventory_total?: number }>(
      `/api/jobs/${jobId}/mobile/analysis/run`,
      {},
      { timeoutMs: 300_000 }
    ),

  downloadMobileCasePackage: (jobId: string) =>
    api.download(`/api/jobs/${jobId}/mobile/case-package`, `mobile_case_${jobId.slice(0, 8)}.zip`),

  downloadArtifactCatalogExport: (jobId: string) =>
    api.download(`/api/jobs/${jobId}/artifact-catalog/export`, `artifacts_${jobId.slice(0, 8)}.xlsx`),

  downloadArtifactsExport: (
    jobId: string,
    query?: {
      q?: string;
      category?: string;
      catalog_key?: string;
      catalog_section?: string;
    }
  ) => api.download(`/api/jobs/${jobId}/artifacts/export`, `extracted_artifacts_${jobId.slice(0, 8)}.xlsx`, query),

  updateArtifactScope: (jobId: string, payload: ArtifactScopeUpdate) =>
    api.put<ArtifactScope>(`/api/jobs/${jobId}/artifact-scope`, payload),

  saveSelectedJobArtifacts: (jobId: string, payload: { artifact_ids: string[]; report_type?: string }) =>
    api.put<{
      job_id: string;
      report_type_id?: string;
      artifact_ids: string[];
      artifacts_json?: unknown[];
      saved_at?: string | null;
    }>(`/api/jobs/${jobId}/selected-job-artifacts`, payload),

  getSelectedJobArtifacts: (jobId: string) =>
    api.get<{
      job_id: string;
      report_type_id?: string;
      artifact_ids: string[];
      artifacts_json?: unknown[];
      saved_at?: string | null;
    }>(`/api/jobs/${jobId}/selected-job-artifacts`),

  getSelectedJobObjectives: (jobId: string) =>
    api.get<{
      job_id: string;
      report_type_id?: string;
      objective_ids: string[];
      custom_objectives?: unknown[];
      objectives_json?: unknown[];
      saved_at?: string | null;
    }>(`/api/jobs/${jobId}/selected-job-objectives-procedure`),

  rerunArtifactInventory: (jobId: string) =>
    api.post<{ queued: boolean; platform?: string; total?: number; completed?: number }>(
      `/api/jobs/${jobId}/artifact-inventory/rerun`,
      {}
    ),

  refreshArtifactInventory: (jobId: string) =>
    api.post<{
      job_id: string;
      inventory: { platform?: string; total: number; completed: number; done: boolean };
      pipeline_progress?: Job["pipeline_progress"];
      job: Job;
    }>(`/api/jobs/${jobId}/artifact-inventory/refresh`, {}),

  ensureArtifactInventory: (jobId: string) =>
    api.post<{
      job_id: string;
      queued: boolean;
      reason?: string;
      total?: number;
      completed?: number;
      done?: boolean;
      platform?: string;
    }>(`/api/jobs/${jobId}/artifact-inventory/ensure`, {}),

  getObjectiveProcedureScope: (jobId: string) =>
    api.get<ObjectiveProcedureScope>(`/api/jobs/${jobId}/objective-procedure-scope`),

  updateObjectiveProcedureScope: (jobId: string, payload: ObjectiveProcedureScopeUpdate) =>
    api.put<ObjectiveProcedureScope>(`/api/jobs/${jobId}/objective-procedure-scope`, payload),

  getReportStatus: (jobId: string) =>
    api.get<{
      job_id: string;
      status: string;
      report_run_id: string | null;
      sections_completed: number;
      sections_total: number;
      duration_ms?: number;
      error?: string;
    }>(`/api/jobs/${jobId}/report`),

  startReport: (jobId: string, payload?: ReportStartPayload) =>
    api.post<ReportStartResult>(`/api/jobs/${jobId}/report/start`, payload ?? {}),

  listReportSections: (jobId: string) => api.get<ReportSection[]>(`/api/reports/${jobId}/sections`),

  patchReportSection: (jobId: string, sectionKey: string, payload: ReportSectionPatch) =>
    api.patch<ReportSection>(`/api/reports/${jobId}/sections/${sectionKey}`, payload),

  approveReport: (jobId: string, notes?: string) =>
    api.post<ReportSection[]>(`/api/reports/${jobId}/approve`, { notes }),

  submitFeedback: (
    jobId: string,
    payload: { section_key?: string; artifact_id?: string; feedback_type: string; content?: string }
  ) => api.post<HumanFeedback>(`/api/reports/${jobId}/feedback`, payload),

  reportGate: (jobId: string) => api.get<ReportGate>(`/api/reports/${jobId}/gate`),

  exportReport: (jobId: string, payload: { format?: string; template?: string; case_id?: string }) =>
    api.post<ReportExport>(`/api/reports/${jobId}/export`, payload, { timeoutMs: 180_000 }),

  uploadPreviewPdf: (jobId: string, blob: Blob) => {
    const form = new FormData();
    form.append("file", blob, "report.pdf");
    return api.postForm<ReportExport>(`/api/reports/${jobId}/export/preview-pdf`, form);
  },

  listReportExports: (jobId: string) =>
    api.get<{ items: ReportExport[] }>(`/api/reports/${jobId}/exports`),

  listAllReportExports: (query?: {
    job_id?: string;
    format?: string;
    run_status?: string;
    from?: string;
    to?: string;
    page?: number;
    page_size?: number;
  }) =>
    api.get<{ items: ReportExport[]; total: number; page: number; page_size: number }>(
      "/api/reports/exports",
      query
    ),

  listReportCatalog: (query?: {
    job_id?: string;
    run_status?: string;
    from?: string;
    to?: string;
    page?: number;
    page_size?: number;
  }) =>
    api.get<ReportCatalogList>("/api/reports/list", query, { timeoutMs: 8_000 }),

  searchEvidence: (
    jobId: string,
    query?: {
      from?: string;
      to?: string;
      q?: string;
      scope?: "artifacts" | "all";
      page?: number;
      page_size?: number;
      limit?: number;
    }
  ) => api.get<EvidenceSearchResult>(`/api/jobs/${jobId}/evidence-search`, query),

  downloadReportExport: (exportId: string) =>
    api.download(`/api/reports/exports/${exportId}/download`, `forensic-report-${exportId.slice(0, 8)}.bin`),

  // Agents
  listAgents: () => api.get<{ items: AgentDefinition[] }>("/api/agents"),

  listAgentRuns: (jobId: string) => api.get<AgentRunList>(`/api/agents/jobs/${jobId}/runs`),

  scopeAdvise: (jobId: string) => api.post<AgentInvokeResult>(`/api/agents/jobs/${jobId}/scope-advise`),

  intakeValidate: (jobId: string) => api.post<AgentInvokeResult>(`/api/agents/jobs/${jobId}/intake-validate`),

  reportQa: (jobId: string) => api.post<AgentInvokeResult>(`/api/agents/jobs/${jobId}/report-qa`),

  agentChat: (
    jobId: string,
    payload: { query: string; thread_id?: string | null; async_run?: boolean }
  ) => api.post<AgentInvokeResult>(`/api/agents/jobs/${jobId}/chat`, payload),

  // Cases
  listCases: (query?: { page?: number; page_size?: number; status?: string }) =>
    api.get<CaseList>("/api/cases", query),

  /** Cases with non-empty gap_site_json between from_date and today (Asia/Kolkata). */
  listGapMergeCandidates: (query?: { from_date?: string }) =>
    api.get<{ items: GapMergeCandidate[]; total: number; from_date?: string; to_date?: string }>(
      "/api/cases/gap-merge-candidates",
      query,
    ),

  getCase: (caseId: string) => api.get<Case>(`/api/cases/${caseId}`),

  createCase: (payload: CaseCreate) => api.post<Case>("/api/cases", payload),

  updateCase: (caseId: string, payload: CaseUpdate) => api.patch<Case>(`/api/cases/${caseId}`, payload),

  deleteCase: (caseId: string) =>
    api.del<{ ok: boolean; id: string; deleted_scan_jobs: number }>(`/api/cases/${caseId}`),

  getCaseIntake: (caseId: string) => api.get<Intake>(`/api/cases/${caseId}/intake`),

  upsertCaseIntake: (caseId: string, payload: IntakePatch) =>
    api.put<Intake>(`/api/cases/${caseId}/intake`, payload),

  listCaseMembers: (caseId: string) => api.get<CaseMember[]>(`/api/cases/${caseId}/members`),

  listChainOfCustody: (caseId: string) =>
    api.get<ChainOfCustodyEntry[]>(`/api/cases/${caseId}/chain-of-custody`),

  listAudit: (caseId: string, query?: { page?: number; page_size?: number }) =>
    api.get<AuditList>(`/api/cases/${caseId}/audit`, query),

  // Image Evidence RAG (selection workspace)
  listRagProfiles: () =>
    api.get<{ profiles: Array<{ id: string; label: string; description?: string; stages?: string }> }>(
      "/api/rag/profiles"
    ),
  createRagSelectionSession: (payload?: { case_id?: string; processing_profile?: string }) =>
    api.post<{ session: Record<string, unknown> }>("/api/rag/selection-sessions", payload || {}, {
      timeoutMs: 30_000,
    }),
  getRagSelectionSession: (sessionId: string) =>
    api.get<{ session: Record<string, unknown>; artifacts: Array<Record<string, unknown>> }>(
      `/api/rag/selection-sessions/${sessionId}`
    ),
  uploadRagSessionFile: (
    sessionId: string,
    file: File,
    relativePath: string,
    onProgress?: (pct: number) => void
  ) => {
    const form = new FormData();
    form.append("files", file, file.name);
    form.append("paths", relativePath);
    return uploadMultipart(`/api/rag/selection-sessions/${sessionId}/upload`, form, onProgress) as Promise<
      UploadResult & { items?: Array<Record<string, unknown>> }
    >;
  },
  putRagManifest: (
    sessionId: string,
    body: {
      items: Array<Record<string, unknown>>;
      processing_profile?: string;
    }
  ) =>
    api.put<{ session: Record<string, unknown>; selected_count: number; selected_bytes: number }>(
      `/api/rag/selection-sessions/${sessionId}/manifest`,
      body
    ),
  getRagRepositoryTree: (query?: {
    parent?: string;
    drive?: string;
    path?: string;
    host_path?: string;
    limit?: number;
  }) =>
    api.get<{
      nodes: Array<Record<string, unknown>>;
      roots?: string[];
      error?: string;
      mount_hint?: string;
      display_path?: string;
      drive_root?: string;
      current_path?: string;
      parent_path?: string | null;
      drives?: Array<Record<string, unknown>>;
    }>("/api/rag/repository/tree", query),
  getRagRepositoryListFiles: (query?: {
    drive?: string;
    path?: string;
    host_path?: string;
    max_files?: number;
    max_depth?: number;
  }) =>
    api.get<{
      files: Array<Record<string, unknown>>;
      truncated?: boolean;
      error?: string | null;
      root_label?: string;
      root_absolute_path?: string | null;
      drive_root?: string;
      browse_path?: string;
      total?: number;
    }>("/api/rag/repository/list-files", query, { timeoutMs: 180_000 }),
  startRagImageJob: (
    sessionId: string,
    body?: {
      processing_profile?: string;
      case_id?: string;
      source_paths?: Record<string, string>;
    }
  ) =>
    api.post<{
      job_id: string;
      session_id: string;
      profile: string;
      registered: number;
      selected: number;
      job: Record<string, unknown>;
    }>(`/api/rag/selection-sessions/${sessionId}/start`, body || {}, { timeoutMs: 300_000 }),
  listJobImageAssets: (jobId: string) =>
    api.get<{ items: Array<Record<string, unknown>>; total: number }>(`/api/rag/jobs/${jobId}/image-assets`),
};
