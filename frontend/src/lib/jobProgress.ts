import type { ExtractionLog, Job, UploadProgressState } from "./types/forensic";
import { effectiveJobProgressPct, jobHasPendingPaths } from "./extractCoverage";
import { currentAgentDisplay, isPipelineFullyComplete } from "./orchestrationStages";
import { stripAxiomBranding } from "./displayText";

/** Log stages that are not pipeline progress (Q&A, ad-hoc retrieval, etc.). */
const NON_PIPELINE_LOG_STAGES = new Set(["rag_qa", "qa", "retrieve", "query"]);

export function isPipelineStatusLog(entry: Pick<ExtractionLog, "stage" | "message">): boolean {
  const stage = (entry.stage ?? "").trim().toLowerCase();
  if (NON_PIPELINE_LOG_STAGES.has(stage)) return false;
  const msg = (entry.message ?? "").trim();
  if (/^Q&A answered\b/i.test(msg)) return false;
  if (/^query understand\b/i.test(msg)) return false;
  return Boolean(msg);
}

/** Most recent extraction log line suitable for pipeline banners (excludes Q&A). */
export function pickLatestPipelineLogMessage(logs: ExtractionLog[]): string | null {
  for (let i = logs.length - 1; i >= 0; i -= 1) {
    const entry = logs[i];
    if (!isPipelineStatusLog(entry)) continue;
    const msg = entry.message?.trim();
    if (!msg) continue;
    if (entry.level === "error") return stripAxiomBranding(`ERROR: ${msg}`);
    if (entry.level === "warn" || entry.level === "warning") return stripAxiomBranding(`WARN: ${msg}`);
    return stripAxiomBranding(msg);
  }
  return null;
}

export interface JobProgressView {
  show: boolean;
  title: string;
  message: string;
  pct: number;
  indeterminate?: boolean;
  statusLabel: string;
  variant?: "default" | "warning" | "error";
  hint?: string | null;
  pathProgress?: string | null;
}

const TERMINAL = new Set(["completed", "classified", "report_ready", "failed"]);

const PIPELINE_ACTIVE = new Set([
  "processing",
  "building_disk",
  "disk_ready",
  "extracting",
  "extracted",
  "indexing",
  "interrupted",
  "paused",
  "report_generating",
]);

const STATUS_RANK: Record<string, number> = {
  created: 0,
  awaiting_segments: 0,
  registered: 1,
  processing: 2,
  building_disk: 3,
  paused: 3,
  disk_ready: 4,
  extracting: 5,
  extracted: 6,
  indexing: 7,
  indexed: 8,
  ready: 9,
  report_generating: 9,
  reporting: 10,
  completed: 11,
  classified: 11,
  failed: -1,
};

export function jobStatusRank(status: string): number {
  return STATUS_RANK[status] ?? 0;
}

/** Keep the furthest pipeline status when polling briefly returns an older value. */
export function mergeJobProgress(prev: Job | null, incoming: Job): Job {
  if (!prev || prev.id !== incoming.id) return incoming;
  if (TERMINAL.has(prev.status) && !TERMINAL.has(incoming.status)) return incoming;

  const coverage = incoming.extract_coverage ?? prev.extract_coverage;
  const extractCaughtUp =
    Boolean(coverage?.interesting_total) &&
    (coverage?.extracted ?? 0) >= (coverage?.interesting_total ?? 0);
  const pipelineDone =
    incoming.pipeline_progress?.phase === "complete" ||
    ["ready", "indexed", "completed", "classified", "report_ready"].includes(incoming.status);
  const pending = pipelineDone || extractCaughtUp
    ? incoming.enrichment?.artifacts_pending ?? 0
    : incoming.enrichment?.artifacts_pending ??
      incoming.extract_coverage?.pending ??
      prev.enrichment?.artifacts_pending ??
      prev.extract_coverage?.pending ??
      0;
  const progress_pct = coverage?.interesting_total
    ? effectiveJobProgressPct({ ...incoming, extract_coverage: coverage })
    : Math.max(prev.progress_pct ?? 0, incoming.progress_pct ?? 0);

  if (pending > 0 && !pipelineDone) {
    const active = ["processing", "extracting", "indexing", "extracted", "disk_ready", "building_disk"];
    let status = incoming.status;
    if (incoming.status === "failed") {
      status = "failed";
    } else if (active.includes(incoming.status)) {
      status = incoming.status;
    } else if (active.includes(prev.status)) {
      status = prev.status;
    } else {
      status = "processing";
    }
    return {
      ...incoming,
      status,
      progress_pct,
      extract_coverage: coverage ?? incoming.extract_coverage,
      error: incoming.error ?? prev.error,
      pipeline_progress: incoming.pipeline_progress ?? prev.pipeline_progress,
    };
  }

  const prevRank = jobStatusRank(prev.status);
  const incomingRank = jobStatusRank(incoming.status);
  let status = incoming.status;
  if (incoming.status !== "failed" && prevRank > incomingRank) {
    status = prev.status;
  }

  let pp = incoming.pipeline_progress ?? prev.pipeline_progress;
  // Never let a poll that briefly reopens artifact_inventory overwrite a finalized pipeline.
  if (
    prev.pipeline_progress?.phase === "complete" &&
    incoming.pipeline_progress &&
    (incoming.pipeline_progress.phase === "artifact_inventory" ||
      incoming.pipeline_progress.phase === "axiom_artifacts") &&
    ["ready", "indexed", "completed", "classified", "report_ready"].includes(status)
  ) {
    pp = prev.pipeline_progress;
  }
  const invIncomplete =
    pp &&
    (pp.phase === "artifact_inventory" || pp.phase === "axiom_artifacts") &&
    (pp.total ?? 0) > 0 &&
    (pp.completed ?? 0) < (pp.total ?? 0);
  if (invIncomplete && status === "indexed") {
    status = "indexing";
  }

  return {
    ...incoming,
    status,
    progress_pct,
    extract_coverage: coverage ?? incoming.extract_coverage,
    error: incoming.error ?? prev.error,
    pipeline_progress: pp,
  };
}

function statusTitle(status: string): string {
  switch (status) {
    case "building_disk":
      return "Building virtual disk";
    case "paused":
      return "Extraction paused";
    case "disk_ready":
      return "Virtual disk ready";
    case "extracting":
      return "Extracting artifacts";
    case "extracted":
      return "Extraction complete";
    case "indexing":
      return "Building RAG index";
    case "processing":
      return "Pipeline running";
    case "failed":
      return "Pipeline failed";
    default:
      return "Processing pipeline";
  }
}

function statusMessage(
  status: string,
  pct: number,
  enrichSubProgress?: string | null,
  filesTotal?: number,
  filesExtracted?: number,
): string {
  if (status === "building_disk") {
    const total = filesTotal ?? 0;
    const done = filesExtracted ?? 0;
    if (total > 0) {
      return `Extracting filesystem to MinIO — ${done.toLocaleString()} / ${total.toLocaleString()} files (${pct}%).`;
    }
    return pct >= 10
      ? "Mounting EWF segments and indexing the filesystem — large images can take several minutes."
      : "Worker started — opening segments and preparing the read-only virtual disk.";
  }
  if (status === "disk_ready") {
    return "Virtual disk mounted. Extraction stage starting next.";
  }
  if (status === "extracting") {
    return "Materializing forensic artifacts from the disk index for RAG indexing.";
  }
  if (status === "extracted") {
    if (enrichSubProgress?.includes("GPU")) {
      return `Embedding on GPU — ${enrichSubProgress}.`;
    }
    return "Artifacts extracted. GPU embedding and graph indexing in progress.";
  }
  if (status === "indexing") {
    if (enrichSubProgress?.includes("GPU")) {
      return `Embedding on GPU — ${enrichSubProgress}.`;
    }
    if (pct >= 96 && enrichSubProgress) {
      return `RAG enrichment in progress — ${enrichSubProgress} (job completes at 100%).`;
    }
    return "Chunking artifacts and embedding vectors on GPU (when configured).";
  }
  if (status === "processing" && pct <= 5) {
    return "Worker queued — building virtual disk and validating segments. Watch the extraction log below.";
  }
  if (pct >= 35 && pct < 55) {
    return "Scanning the full disk — carving paths and queuing extraction specs.";
  }
  if (pct >= 60 && pct < 85) {
    return "Classifying carved data (registry, browser, email, documents, …).";
  }
  if (pct >= 90 && pct < 98) {
    return "Embedding vectors, building Neo4j graph, running LLM on high-value artifacts.";
  }
  return "Pipeline running — live detail appears in the extraction log below.";
}

export function getJobProgressView(opts: {
  job: Job;
  enrichSubProgress?: string | null;
  latestLog?: string | null;
  registering?: boolean;
  registerPct?: number;
  registerFileName?: string;
  uploading?: boolean;
  uploadProgress?: UploadProgressState | null;
  processRequested?: boolean;
  pollStopped?: boolean;
  pathProgress?: string | null;
}): JobProgressView {
  const {
    job,
    enrichSubProgress,
    latestLog,
    registering,
    registerPct = 0,
    registerFileName,
    uploading,
    uploadProgress,
    processRequested = false,
    pollStopped = false,
    pathProgress = null,
  } = opts;

  const logLine = latestLog?.trim() ? stripAxiomBranding(latestLog.trim()) : null;

  const statusLabel = job.status.replace(/_/g, " ");
  const pct = effectiveJobProgressPct(job);
  const segmentReady = job.segment_readiness?.ready ?? false;
  const pollHint = pollStopped
    ? "Live updates paused — click Refresh on the log panel or reload the page."
    : null;

  if (uploading && uploadProgress) {
    const overall = Math.round(
      ((uploadProgress.index + uploadProgress.filePct / 100) / Math.max(uploadProgress.total, 1)) * 100
    );
    return {
      show: true,
      title: "Uploading evidence",
      message: `File ${uploadProgress.index + 1} of ${uploadProgress.total}: ${uploadProgress.fileName} (${uploadProgress.filePct}%)`,
      pct: overall,
      statusLabel: "uploading",
    };
  }

  if (registering) {
    return {
      show: true,
      title: "Registering disk segments",
      message: registerFileName
        ? `Registering ${registerFileName} from its current location — no copy.`
        : "Registering the selected folder — files upload from this computer, then the server processes them.",
      pct: registerPct > 0 ? registerPct : 0,
      indeterminate: registerPct <= 0,
      statusLabel: "registering evidence",
    };
  }

  // Idle "select folder" state: HostEvidencePanel already covers this —
  // do not show a top banner with a 0% progress bar.
  if (!segmentReady && ["created", "registered", "awaiting_segments"].includes(job.status)) {
    return {
      show: false,
      title: "Select evidence folder",
      message: "",
      pct: 0,
      statusLabel,
    };
  }

  if (job.status === "failed") {
    return {
      show: true,
      title: "Pipeline failed",
      message: job.error?.trim() || "The pipeline stopped with an error. Check the extraction log for details.",
      pct: pct,
      statusLabel,
      variant: "error",
      hint: pollHint,
    };
  }

  if (isPipelineFullyComplete(job) && !jobHasPendingPaths(job)) {
    return {
      show: true,
      title: "Pipeline complete",
      message:
        "All pipeline stages finished. Complete case intake, then generate the report.",
      pct: 100,
      statusLabel,
      variant: "default",
    };
  }

  if (["indexed", "ready"].includes(job.status) && !jobHasPendingPaths(job) && !isPipelineFullyComplete(job)) {
    const pp = job.pipeline_progress;
    const invLabel =
      pp?.phase === "artifact_inventory" && pp.total
        ? `${(pp.completed ?? 0).toLocaleString()} / ${pp.total.toLocaleString()} artifact inventory`
        : null;
    return {
      show: true,
      title: "Pipeline finishing",
      message:
        logLine ||
        (invLabel
          ? `Final pipeline stages in progress — ${invLabel}.`
          : "Final pipeline stages still running — see agent cards below."),
      pct: effectiveJobProgressPct(job),
      statusLabel: job.status === "indexed" ? "finishing" : statusLabel,
      hint: pollHint,
      pathProgress,
    };
  }

  if (jobHasPendingPaths(job) && job.status !== "indexed" && job.status !== "ready") {
    const e = job.enrichment;
    const cov = job.extract_coverage;
    const pendingPaths =
      cov?.interesting_total != null && cov?.extracted != null
        ? `${cov.extracted.toLocaleString()} / ${cov.interesting_total.toLocaleString()} interesting paths`
        : e?.artifacts_total != null
          ? `${(e.artifacts_parsed ?? 0).toLocaleString()} / ${e.artifacts_total.toLocaleString()} artifacts parsed`
          : "background paths";
    const stageMessage =
      logLine ||
      (e?.enriching
        ? `Baseline ready — ${(e.rag_chunks ?? 0).toLocaleString()} chunks searchable. Enriching +${(e.artifacts_pending ?? 0).toLocaleString()} artifacts in background.`
        : `Processing ${pendingPaths} — auto-continuing in background.`);
    const enrichAgent = currentAgentDisplay(job);
    return {
      show: true,
      title: enrichAgent
        ? `${enrichAgent.label} agent`
        : e?.enriching
          ? "Baseline ready — enriching"
          : "Processing pipeline",
      message: stageMessage,
      pct,
      statusLabel: e?.enriching ? "enriching" : "processing",
      hint: pollHint,
      pathProgress,
    };
  }

  if (processRequested && job.status === "registered") {
    return {
      show: true,
      title: "Starting pipeline",
      message:
        logLine ||
        "Process requested — queuing the worker to build the virtual disk. This usually takes a few seconds.",
      pct: Math.max(pct, 5),
      indeterminate: true,
      statusLabel: "starting",
      variant: "warning",
      hint:
        pollHint ||
        "If this stays unchanged for 30+ seconds, run: docker compose logs worker --tail 50",
    };
  }

  if (PIPELINE_ACTIVE.has(job.status)) {
    const stageMessage =
      logLine ||
      statusMessage(job.status, pct, enrichSubProgress, job.files_total, job.files_extracted);
    const agent = currentAgentDisplay(job);
    return {
      show: true,
      title: agent ? `${agent.label} agent` : statusTitle(job.status),
      message: stageMessage,
      pct: Math.max(pct, job.status === "processing" ? 5 : pct),
      statusLabel,
      hint: pollHint,
      pathProgress,
    };
  }

  if (job.status === "registered" && segmentReady) {
    return {
      show: true,
      title: "Starting pipeline",
      message:
        logLine ||
        `${job.segment_readiness?.message ?? "All disk segments registered."} Starting virtual disk build automatically…`,
      pct: Math.max(pct, 5),
      indeterminate: true,
      statusLabel: "starting",
    };
  }

  if (TERMINAL.has(job.status)) {
    return {
      show: false,
      title: "",
      message: "",
      pct: 100,
      statusLabel,
    };
  }

  return {
    show: pct > 0 || Boolean(logLine) || Boolean(pathProgress),
    title: "Job status",
    message: logLine || `Status: ${statusLabel}`,
    pct,
    statusLabel,
    hint: pollHint,
    pathProgress,
  };
}
