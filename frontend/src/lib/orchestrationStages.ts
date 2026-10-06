import type { Job, PipelineProgress } from "./types/forensic";
import type { PipelineStageProgress, PipelineStageState } from "./pipelineStages";
import { sanitizePipelineLabel, stripAxiomBranding } from "./displayText";
import { enrichmentRagPct, isBackgroundEnriching } from "./enrichmentStatus";

export interface PipelineAgentState {
  state: PipelineStageState;
  pct: number;
  label: string;
  detail?: string;
  started_at?: string;
  finished_at?: string;
  duration_sec?: number;
}

export interface PipelineOrchestration {
  agents: Record<string, PipelineAgentState>;
  overall_pct: number;
  progress_high_water?: number;
  current_agent_id?: string | null;
  current_agent_label?: string | null;
  current_agent_state?: "running" | "pending" | null;
  sequential?: boolean;
  pipeline_started_at?: string | null;
  total_duration_sec?: number | null;
  huddle?: {
    observe?: string;
    drives_ready?: boolean;
    mounted_letters?: string[];
  };
}

export function drivesAlreadyMounted(job: Job): boolean {
  const orch = job.pipeline_progress?.orchestration as PipelineOrchestration | undefined;
  const mount = orch?.agents?.drive_mount_agent;
  if (mount?.state === "done") return true;
  const huddle = orch?.huddle;
  if (huddle?.drives_ready) return true;
  if ((huddle?.mounted_letters?.length ?? 0) > 0) return true;
  const observe = String(huddle?.observe || "");
  return /Docker\s+[A-Z]/i.test(observe);
}

export function extractStillRunning(job: Job): boolean {
  // A finalized extracted_disk_uri is the hard phase barrier. Older jobs can
  // temporarily carry status=indexing while the disk walk is still active, so
  // status alone is not enough to declare Phase 1 finished.
  if (!job.extracted_disk_uri && ["processing", "building_disk", "extracting", "indexing"].includes(job.status)) {
    return true;
  }
  const filesTotal = job.files_total ?? 0;
  const filesDone = job.files_extracted ?? 0;
  return !job.extracted_disk_uri && filesTotal > 0 && filesDone < filesTotal;
}

const POST_EXTRACT_AGENT_IDS = new Set([
  "materialize_agent",
  "ocr_agent",
  "parse_agent",
  "chunk_agent",
  "embed_agent",
  "entity_agent",
  "neo4j_agent",
  "annotation_agent",
  "ontology_agent",
  "artifacts_agent",
]);

const PRE_OCR_AGENT_IDS = new Set([
  "drive_mount_agent",
  "download_agent",
  "list_folder_agent",
  "segments_agent",
  "virtual_disk_agent",
  "extraction_agent",
  "materialize_agent",
]);

export const AGENT_ORDER: Array<{ id: string; label: string }> = [
  { id: "iosagent", label: "iOS Agent" },
  { id: "androidagent", label: "Android Agent" },
  { id: "drive_mount_agent", label: "Drive mount" },
  { id: "download_agent", label: "Download" },
  { id: "list_folder_agent", label: "List folder" },
  { id: "segments_agent", label: "Get segments" },
  { id: "virtual_disk_agent", label: "Virtual disk" },
  { id: "extraction_agent", label: "Extraction" },
  { id: "materialize_agent", label: "Register artifacts" },
  { id: "parse_agent", label: "Parse forensic files" },
  { id: "ocr_agent", label: "OCR enrich" },
  { id: "chunk_agent", label: "RAG chunking" },
  { id: "embed_agent", label: "RAG embedding" },
  { id: "entity_agent", label: "Entity extraction" },
  { id: "annotation_agent", label: "Annotation" },
  { id: "ontology_agent", label: "Ontology" },
  { id: "neo4j_agent", label: "Neo4j graph" },
  { id: "artifacts_agent", label: "Artifact inventory" },
];

const DISK_ONLY_AGENT_IDS = new Set([
  "drive_mount_agent",
  "download_agent",
  "virtual_disk_agent",
]);

export function mobileJobPlatform(job: Job): "ios" | "android" | null {
  const type = String(job.type || "").toLowerCase();
  const ds = (job.disk_source || {}) as Record<string, unknown>;
  const raw = String(
    ds.owner_agent || ds.mobile_os || ds.axiom_platform || ds.evidence_platform || ds.os_family || type || "",
  ).toLowerCase();
  if (raw.includes("ios") || raw.includes("iphone") || type === "ios_backup") return "ios";
  if (raw.includes("android") || type === "android_backup") return "android";
  return null;
}

export function isMobilePipelineJob(job: Job): boolean {
  const type = String(job.type || "").toLowerCase();
  if (["mobile_extraction", "ios_backup", "android_backup"].includes(type)) return true;
  const ds = (job.disk_source || {}) as Record<string, unknown>;
  // A host_disk E01 must never be reclassified as Android/iOS from stale mobile metadata.
  if (type === "host_disk" || type === "disk") return String(ds.source_type || "").toLowerCase() === "mobile";
  if (String(ds.source_type || "").toLowerCase() === "mobile") return true;
  return !type && mobileJobPlatform(job) != null;
}

export type EvidenceTransportMode = "server" | "client" | "unknown";

export function evidenceTransportModeForJob(job: Job | null | undefined): EvidenceTransportMode {
  if (!job) return "unknown";
  const ds = (job.disk_source || {}) as Record<string, unknown>;
  const intake = String(ds.intake || "").toLowerCase();
  const residency = String(ds.source_residency || "").toLowerCase();
  const origin = String(ds.source_origin || "").toLowerCase();
  const mode = String(ds.transport_mode || ds.transport || "").toLowerCase();
  if (intake === "browser_upload" || residency === "client_uploaded_to_server" || origin === "client_browser" || origin === "client_workstation" || mode === "staged_upload") return "client";
  if (intake === "server_local" || residency === "server_local" || residency === "server_accessible" || origin.startsWith("server_") || origin === "forensic_server" || mode === "zero_copy" || mode === "in_place") return "server";
  return "unknown";
}

export function hasSelectedEvidence(job: Job | null | undefined): boolean {
  if (!job) return false;
  const ds = (job.disk_source || {}) as Record<string, unknown>;
  return Boolean(job.segment_readiness?.ready || job.extracted_disk_uri || ds.evidence_folder || ds.host_path || ds.path);
}

export function agentOrderForJob(job: Job): Array<{ id: string; label: string }> {
  const mobile = isMobilePipelineJob(job);
  const platform = mobileJobPlatform(job);
  const transport = evidenceTransportModeForJob(job);
  const ds = (job.disk_source || {}) as Record<string, unknown>;
  const clientUpload = String(ds.intake || "") === "browser_upload" || transport === "client";
  return AGENT_ORDER.filter(({ id }) => {
    if (id === "iosagent") return mobile && platform !== "android";
    if (id === "androidagent") return mobile && platform !== "ios";
    if (mobile && DISK_ONLY_AGENT_IDS.has(id)) return false;
    // Download Agent is a client-transfer stage only. A server/local-network/
    // removable source is registered and processed in place, so showing a
    // Download stage there is both misleading and can preserve stale UI state.
    if (!mobile && id === "download_agent") return clientUpload;
    if (!mobile && id === "drive_mount_agent") return !clientUpload;
    return !mobile ? id !== "iosagent" && id !== "androidagent" : true;
  });
}

/** -1 = all pending (job not started). AGENT_ORDER.length = all done. */
export function inferRunningAgentIndex(job: Job): number {
  const status = job.status;
  const phase = (job.pipeline_progress?.phase || "").toLowerCase();
  const idleCreated =
    ["created", "registered", "awaiting_segments"].includes(status) &&
    (job.progress_pct ?? 0) <= 0 &&
    !job.extracted_disk_uri &&
    !["processing", "building_disk"].includes(status);

  const ds = job.disk_source as { intake?: unknown; upload_status?: unknown } | null | undefined;
  const downloadReceiving =
    String(ds?.intake || "") === "browser_upload" && String(ds?.upload_status || "") === "receiving";
  if (downloadReceiving) {
    return AGENT_ORDER.findIndex((a) => a.id === "download_agent");
  }
  if (idleCreated && !job.segment_readiness?.ready) {
    if (drivesAlreadyMounted(job)) {
      return AGENT_ORDER.findIndex((a) => a.id === "list_folder_agent");
    }
    return AGENT_ORDER.findIndex((a) => a.id === "drive_mount_agent");
  }
  if (["created", "registered", "awaiting_segments"].includes(status) && !job.segment_readiness?.ready) {
    return AGENT_ORDER.findIndex((a) => a.id === "list_folder_agent");
  }
  if (job.segment_readiness?.ready && ["created", "registered"].includes(status)) {
    return AGENT_ORDER.findIndex((a) => a.id === "virtual_disk_agent");
  }
  if (extractStillRunning(job)) {
    if (isMobilePipelineJob(job)) {
      const platform = mobileJobPlatform(job);
      if (platform === "ios") return AGENT_ORDER.findIndex((a) => a.id === "iosagent");
      if (platform === "android") return AGENT_ORDER.findIndex((a) => a.id === "androidagent");
    }
    if ((job.files_extracted ?? 0) > 0 || (job.files_total ?? 0) > 0) {
      return AGENT_ORDER.findIndex((a) => a.id === "extraction_agent");
    }
    return AGENT_ORDER.findIndex((a) => a.id === "virtual_disk_agent");
  }
  if (status === "disk_ready") {
    return AGENT_ORDER.findIndex((a) => a.id === "extraction_agent");
  }
  if (phase === "materialize" || status === "extracted" || status === "artifacts_registered") {
    return AGENT_ORDER.findIndex((a) => a.id === "materialize_agent");
  }
  if (phase === "ocr") return AGENT_ORDER.findIndex((a) => a.id === "ocr_agent");
  if (phase === "parse" || status === "parsed") {
    return AGENT_ORDER.findIndex((a) => a.id === "parse_agent");
  }
  if (phase === "artifact_inventory" || phase === "axiom_artifacts") {
    return AGENT_ORDER.findIndex((a) => a.id === "artifacts_agent");
  }
  if (phase === "rag" || status === "indexing") {
    if (job.enrichment?.rag_done && (job.enrichment.rag_pending ?? 0) <= 0) {
      return AGENT_ORDER.findIndex((a) => a.id === "entity_agent");
    }
    if (job.enrichment?.rag_embedding_enabled) {
      return AGENT_ORDER.findIndex((a) => a.id === "embed_agent");
    }
    return AGENT_ORDER.findIndex((a) => a.id === "chunk_agent");
  }
  if (["indexed", "ready", "completed", "classified", "report_ready"].includes(status)) {
    // A stale phase=complete must not hide live OCR / parse work.
    if ((job.enrichment?.ocr_pending ?? 0) > 0) {
      return AGENT_ORDER.findIndex((a) => a.id === "ocr_agent");
    }
    if (job.pipeline_progress?.phase === "complete") return AGENT_ORDER.length;
    return AGENT_ORDER.findIndex((a) => a.id === "artifacts_agent");
  }
  return -1;
}

export function readOrchestration(job: Job): PipelineOrchestration | null {
  const pp = job.pipeline_progress as (PipelineProgress & { orchestration?: PipelineOrchestration }) | null | undefined;
  return pp?.orchestration ?? null;
}

export function orchestratedStages(job: Job): PipelineStageProgress[] {
  const serial = job.pipeline_progress?.serial_pipeline;
  if (serial) return serial.stages.map((stage) => ({
    id: stage.agent_id as PipelineStageProgress["id"],
    label: stage.label,
    state: stage.status === "done" || stage.status === "skipped" ? "done"
      : stage.status === "failed" ? "failed" : stage.status === "running" ? "running" : "pending",
    pct: stage.pct,
    detail: stage.error || null,
  }));
  const orch = readOrchestration(job);
  const inferredIdx = inferRunningAgentIndex(job);
  const invUiPct = job.pipeline_progress?.inventory_ui_pct;
  const invStage = job.pipeline_progress?.inventory_stage;
  const ocrPending = job.enrichment?.ocr_pending ?? 0;
  const ocrDone = job.enrichment?.ocr_done ?? 0;
  const ragPending = job.enrichment?.rag_pending ?? 0;
  const ragBg = job.enrichment?.rag_background_enabled !== false;
  const embedOn = job.enrichment?.rag_embedding_enabled === true;
  const pipelineStarted = Boolean(orch?.agents) || inferredIdx >= 0;
  const ocrLiveIdx = ocrPending > 0 ? AGENT_ORDER.findIndex((a) => a.id === "ocr_agent") : -1;
  const orchCurrentIdx =
    orch?.current_agent_id != null
      ? AGENT_ORDER.findIndex((a) => a.id === orch.current_agent_id)
      : -1;
  const liveIdx = Math.max(inferredIdx, ocrLiveIdx, orchCurrentIdx);
  const ds = job.disk_source as { intake?: unknown; upload_status?: unknown } | null | undefined;
  const downloadReceiving =
    String(ds?.intake || "") === "browser_upload" && String(ds?.upload_status || "") === "receiving";
  return AGENT_ORDER.map(({ id, label }, index) => {
    const a = orch?.agents?.[id];
    let state: PipelineStageState;
    let pct: number;
    const extracting = extractStillRunning(job);
    const filesTotal = job.files_total ?? 0;
    const filesDone = job.files_extracted ?? 0;
    const uploadInProgress = filesTotal > 0 && filesDone < filesTotal;
    const extractActivity = job.pipeline_progress?.extraction_activity;
    const hasArtifacts =
      (job.enrichment?.files_registered ?? 0) > 0 || (job.enrichment?.artifacts_total ?? 0) > 0;
    // Stale 100% counts from a prior extract stay visible during re-enumeration.
    // Never treat that as "almost done" while status is still extracting.
    const orchExtractPct = orch?.agents?.extraction_agent?.pct ?? 0;
    const extractFilePct =
      filesTotal > 0
        ? Math.min(99, Math.round((100 * filesDone) / filesTotal))
        : Math.min(99, Math.max(1, orchExtractPct || 1));

    if (id === "drive_mount_agent" && drivesAlreadyMounted(job)) {
      state = "done";
      pct = 100;
    } else if (a?.state) {
      state = a.state as PipelineStageState;
      pct = a.pct ?? (state === "done" ? 100 : 0);
      // Backend pending/0% must not hide finished prior cards while later work is live.
      if (
        !extracting &&
        liveIdx > index &&
        state === "pending" &&
        !(id === "artifacts_agent" && inventoryIncomplete(job))
      ) {
        state = "done";
        pct = 100;
      } else if (
        !extracting &&
        liveIdx > index &&
        PRE_OCR_AGENT_IDS.has(id) &&
        state !== "failed" &&
        pct <= 0
      ) {
        state = "done";
        pct = 100;
      }
    } else if (inferredIdx < 0) {
      state = "pending";
      pct = 0;
    } else if (inferredIdx >= AGENT_ORDER.length) {
      state = "done";
      pct = 100;
    } else if (index < inferredIdx) {
      state = "done";
      pct = 100;
    } else if (index === inferredIdx) {
      state = "running";
      pct = Math.min(99, Math.max(1, job.progress_pct ?? 1));
    } else {
      state = "pending";
      pct = 0;
    }
    let detail = a?.detail ? stripAxiomBranding(a.detail) : null;
    if (id === "drive_mount_agent" && drivesAlreadyMounted(job)) {
      state = "done";
      pct = 100;
      if (!detail) detail = "Drives already mounted — no remount";
    }
    const awaitingFolder =
      ["created", "registered", "awaiting_segments", "pending", "uploaded"].includes(job.status) &&
      !job.segment_readiness?.ready &&
      !job.extracted_disk_uri &&
      !job.disk_source;
    if (id === "list_folder_agent" && drivesAlreadyMounted(job) && awaitingFolder && !downloadReceiving && state !== "done") {
      state = "running";
      pct = Math.max(pct, 10);
      if (!detail) detail = "Choose the .E01 folder";
    }
    if (downloadReceiving && id === "download_agent") {
      state = "running";
      pct = Math.max(pct, 5);
      if (!detail) detail = "Receiving segments — 5 parallel slots. Other agents blocked.";
    }
    if (!downloadReceiving && evidenceTransportModeForJob(job) === "server" && id === "download_agent") {
      state = "done";
      pct = 100;
      detail = "Skipped — server-local HDD/SSD/USB evidence is processed in place (zero copy).";
    }
    if (downloadReceiving && id === "list_folder_agent") {
      state = "pending";
      pct = 0;
      if (!detail) detail = "Waiting for Download Agent";
    }
    if (
      (awaitingFolder || downloadReceiving) &&
      id !== "drive_mount_agent" &&
      id !== "download_agent" &&
      id !== "list_folder_agent" &&
      !(id === "embed_agent" && !embedOn) &&
      !(typeof a?.pct === "number" && a.pct > 0)
    ) {
      state = "pending";
      pct = 0;
      if (!detail) detail = "Waiting for extraction";
    }
    if (extracting) {
      if (id === "drive_mount_agent" || id === "download_agent" || id === "list_folder_agent" || id === "segments_agent" || id === "virtual_disk_agent") {
        state = "done";
        pct = 100;
      }
      if (id === "extraction_agent") {
        state = "running";
        pct = extractFilePct;
        if (extractActivity?.subphase === "enumerating") {
          const found = extractActivity.files_found ?? 0;
          detail = found > 0
            ? `Filesystem inventory — ${found.toLocaleString()} files discovered; total still growing`
            : "Enumerating filesystem tree — total not known yet";
        } else if (extractActivity?.subphase === "finalizing") {
          detail = `All ${filesDone.toLocaleString()} files extracted — finalizing evidence manifest`;
        } else if (uploadInProgress || filesTotal > 0) {
          const remaining = Math.max(filesTotal - filesDone, 0);
          detail = `${filesDone.toLocaleString()} / ${filesTotal.toLocaleString()} files → MinIO · ${remaining.toLocaleString()} remaining`;
        } else {
          detail = extractActivity?.label || "Preparing one-time evidence extraction plan";
        }
      }
    }
    // Prefer runner-published inventory_ui_pct so GET snapshot lag cannot pin 1%.
    if (id === "artifacts_agent" && state === "running" && typeof invUiPct === "number" && invUiPct > 0) {
      pct = Math.max(pct, Math.min(99, Math.round(invUiPct)));
      if (!detail && invStage) {
        detail = `Artifact inventory — ${invStage} (${pct}%)`;
      }
    }
    // Correct stale "done" cards when enrichment snapshot still has work.
    if (!extracting && id === "ocr_agent" && ocrPending > 0) {
      const ocrTotal = Math.max(ocrDone + ocrPending, 1);
      state = "running";
      pct = Math.min(99, Math.round((100 * ocrDone) / ocrTotal));
      detail = `OCR — ${ocrDone.toLocaleString()} done / ${ocrTotal.toLocaleString()}`;
    } else if (id === "ocr_agent" && extracting && ocrDone <= 0 && ocrPending <= 0 && !(typeof a?.pct === "number" && a.pct > 0)) {
      state = "pending";
      pct = 0;
      detail = "Waiting for extracted files";
    } else if (id === "ocr_agent" && !extracting && !hasArtifacts && ocrDone <= 0 && !(typeof a?.pct === "number" && a.pct > 0)) {
      state = "pending";
      pct = 0;
      detail = "Waiting for materialized files";
    } else if (
      id === "parse_agent" &&
      !extracting &&
      (job.enrichment?.artifacts_pending ?? 0) <= 0 &&
      ((job.enrichment?.artifacts_parsed ?? 0) > 0 || hasArtifacts) &&
      state !== "failed"
    ) {
      state = "done";
      pct = 100;
      const parsed = job.enrichment?.artifacts_parsed ?? 0;
      if (!detail && parsed > 0) detail = `${parsed.toLocaleString()} forensic files parsed`;
    } else if (
      !extracting &&
      id === "parse_agent" &&
      (job.enrichment?.artifacts_pending ?? 0) > 0
    ) {
      const parsed = job.enrichment?.artifacts_parsed ?? 0;
      const pending = job.enrichment?.artifacts_pending ?? 0;
      const parseTotal = Math.max(parsed + pending, 1);
      state = "running";
      pct = Math.min(99, Math.round((100 * parsed) / parseTotal));
      detail = `${parsed.toLocaleString()} / ${parseTotal.toLocaleString()}`;
    } else if (
      id === "ocr_agent" &&
      state === "done" &&
      ocrDone <= 0 &&
      (job.enrichment?.parse_done === false || (job.enrichment?.artifacts_pending ?? 0) > 0)
    ) {
      state = "pending";
      pct = 0;
      detail = "Waiting for parse";
    }
    if (!embedOn && id === "embed_agent") {
      state = "done";
      pct = 100;
      if (!detail) detail = "Embeddings disabled — 100%";
    }
    if (!extracting && pipelineStarted && !embedOn && id === "chunk_agent") {
      const chunks = job.enrichment?.rag_chunks ?? 0;
      const pending = job.enrichment?.rag_pending ?? 0;
      if (pending > 0) {
        const total = Math.max(job.enrichment?.rag_total ?? 0, chunks + pending, 1);
        state = "running";
        pct = Math.min(99, Math.round((100 * chunks) / total));
        detail = `${chunks.toLocaleString()} chunks · ${pending.toLocaleString()} artifacts left`;
      } else if (chunks > 0 && !extracting) {
        state = "done";
        pct = 100;
        if (!detail) detail = `${chunks.toLocaleString()} chunks`;
      } else if (chunks <= 0 && !["indexed", "ready", "completed", "classified", "report_ready"].includes(job.status)) {
        state = "pending";
        pct = 0;
        if (!detail) detail = "Waiting for parsed evidence";
      }
    }
    if (!extracting && id === "embed_agent" && embedOn && ragBg && ragPending > 0) {
      state = "running";
      pct = Math.min(99, Math.max(1, enrichmentRagPct(job)));
      const chunks = job.enrichment?.rag_chunks ?? 0;
      const total = Math.max(job.enrichment?.rag_total ?? 0, chunks, 1);
      detail = `Baseline ready — ${chunks.toLocaleString()} searchable (${ragPending.toLocaleString()} still embedding)`;
      if (chunks <= 0) detail = `RAG embedding — 0 / ${total.toLocaleString()}`;
    }
    // RAG embed: never show 100 while still marked running.
    if (id === "embed_agent" && state === "running") {
      pct = Math.min(99, Math.max(1, pct));
    }
    // Backend said this agent finished — do not overlay a lower percent or reopen it.
    // Created jobs must not keep a false OCR 100% from an empty-catalog huddle write.
    const laterWhileWaiting =
      (awaitingFolder || downloadReceiving) &&
      id !== "drive_mount_agent" &&
      id !== "download_agent" &&
      id !== "list_folder_agent" &&
      !(id === "embed_agent" && !embedOn) &&
      !(typeof a?.pct === "number" && a.pct > 0);
    if (laterWhileWaiting) {
      state = "pending";
      pct = 0;
    } else if (a?.state === "done" && id !== "embed_agent") {
      state = "done";
      pct = 100;
    } else if (a?.state === "done" && id === "embed_agent" && !embedOn) {
      state = "done";
      pct = 100;
    } else if (typeof a?.pct === "number" && a.pct > pct) {
      if (!(extracting && POST_EXTRACT_AGENT_IDS.has(id) && a.pct >= 100)) {
        pct = a.pct;
      }
    }
    // Final UI barrier override. Stale counters from an older streaming run
    // may exist in the DB, but no downstream card is allowed to look active
    // until the extracted image manifest is finalized.
    if (extracting && POST_EXTRACT_AGENT_IDS.has(id)) {
      if (id === "embed_agent" && !embedOn) {
        state = "done";
        pct = 100;
        detail = "Embeddings disabled — skipped";
      } else {
        state = "pending";
        pct = 0;
        detail = "Waiting for evidence extraction to finish";
      }
    }
    return {
      id: id as PipelineStageProgress["id"],
      label: sanitizePipelineLabel(label),
      state,
      pct,
      indeterminate: state === "running" && pct <= 0,
      detail,
    };
  }).filter((stage) => agentOrderForJob(job).some((a) => a.id === stage.id));
}

export function orchestratedOverallPct(job: Job): number | null {
  const filesTotal = job.files_total ?? 0;
  const filesDone = job.files_extracted ?? 0;
  if (extractStillRunning(job) && filesTotal > 0) {
    return Math.min(99, Math.round((100 * filesDone) / filesTotal));
  }
  if (extractStillRunning(job)) {
    // Enumeration has an unknown denominator; show an early-stage value rather
    // than inheriting a stale 99% from a previous streaming downstream lane.
    return Math.min(10, Math.max(1, job.progress_pct ?? 1));
  }
  const orch = readOrchestration(job);
  const pp = job.pipeline_progress;
  // A job created by the older streaming pipeline can briefly carry the
  // extraction card's 99% high-water into Phase 2. Ignore that stale
  // extraction-owned snapshot once a finalized extracted image exists.
  const staleExtractionSnapshot =
    Boolean(job.extracted_disk_uri) &&
    orch?.current_agent_id === "extraction_agent" &&
    pp?.phase !== "extract";
  if (staleExtractionSnapshot) return null;
  if (orch?.overall_pct != null) return orch.overall_pct;
  return null;
}

function inventoryCountsFinished(job: Job): boolean {
  const pp = job.pipeline_progress;
  if (!pp) return false;
  const stage = pp.inventory_stage;
  // Prewarm stages are never "finished" even if completed was mapped for the bar.
  if (stage && stage !== "counting" && stage !== "done" && stage !== "complete") {
    return false;
  }
  if (typeof pp.inventory_ui_pct === "number" && pp.inventory_ui_pct < 100) {
    if (pp.phase === "artifact_inventory" || pp.phase === "axiom_artifacts") return false;
  }
  const total = pp.total ?? 0;
  const completed = pp.completed ?? 0;
  // Counts win over a stale phase=complete (catalog can grow after finalize).
  if (total > 0 && completed < total) return false;
  if (pp.phase === "complete") return true;
  if (pp.phase !== "artifact_inventory" && pp.phase !== "axiom_artifacts") return false;
  return total > 0 && completed >= total;
}

function inventoryIncomplete(job: Job): boolean {
  const pp = job.pipeline_progress;
  if (!pp) return false;
  const stage = pp.inventory_stage;
  if (stage && stage !== "counting" && stage !== "done" && stage !== "complete") {
    return true;
  }
  if (typeof pp.inventory_ui_pct === "number" && pp.inventory_ui_pct < 100) {
    if (pp.phase === "artifact_inventory" || pp.phase === "axiom_artifacts") return true;
  }
  const total = pp.total ?? 0;
  const completed = pp.completed ?? 0;
  if (total > 0 && completed < total) return true;
  if (pp.phase !== "artifact_inventory" && pp.phase !== "axiom_artifacts") return false;
  return total > 0 && completed < total;
}

const ENRICH_AGENT_IDS = ["entity_agent", "neo4j_agent", "annotation_agent", "ontology_agent"] as const;

/** True while the top-level parse/RAG/OCR counters in pipeline_progress show remaining work. */
function stageCountersHaveWork(job: Job): boolean {
  const pp = job.pipeline_progress;
  if (!pp) return false;
  const phase = String(pp.phase ?? "").toLowerCase();
  if (phase !== "parse" && phase !== "rag" && phase !== "ocr") return false;
  const total = pp.total ?? 0;
  const completed = pp.completed ?? 0;
  return total > 0 && completed < total;
}

/** True when an orchestration block exists and any weighted agent is not done. */
function orchestratedAgentsIncomplete(job: Job): boolean {
  const orch = readOrchestration(job);
  if (!orch?.agents) {
    if ((job.enrichment?.ocr_pending ?? 0) > 0) return true;
    const inferred = inferRunningAgentIndex(job);
    return inferred >= 0 && inferred < AGENT_ORDER.length;
  }
  for (const { id } of agentOrderForJob(job)) {
    if (id === "embed_agent") continue;
    if (id === "artifacts_agent" && inventoryCountsFinished(job)) continue;
    if ((orch.agents[id]?.state ?? "pending") !== "done") return true;
  }
  return false;
}

/** Required cards still open after live OCR/chunk overlays (embed is optional). */
export function requiredPipelineStagesOpen(job: Job): boolean {
  return orchestratedStages(job).some(
    (s) => s.id !== "embed_agent" && s.state !== "done" && s.state !== "failed"
  );
}

function orchestratedEnrichIncomplete(job: Job): boolean {
  const orch = readOrchestration(job);
  if (!orch?.agents) return false;
  for (const id of ENRICH_AGENT_IDS) {
    if ((orch.agents[id]?.state ?? "pending") !== "done") return true;
  }
  return false;
}

/** True only when every orchestrated agent is done and inventory (if any) is finished. */
export function isPipelineFullyComplete(job: Job): boolean {
  if (job.pipeline_progress?.serial_pipeline) return job.pipeline_progress.serial_pipeline.complete;
  const pp = job.pipeline_progress;
  const terminalStatus = ["indexed", "ready", "completed", "classified", "report_ready", "report_generating"].includes(
    job.status
  );

  // Never show complete while any catalog artifact is still uncounted.
  if (inventoryIncomplete(job)) return false;
  // Never show complete while parse/RAG/OCR counters still have work, or the
  // worker reports pending files. A stale status='ready' / progress_pct=100
  // written by a stage milestone must not override live stage counters
  // (that produced "100% / Pipeline finished" with Parse pinned at 99%).
  if (stageCountersHaveWork(job)) return false;
  if ((job.extract_coverage?.pending ?? 0) > 0) return false;
  if ((job.enrichment?.artifacts_pending ?? 0) > 0) return false;
  // Never complete while OCR / background RAG still have real work.
  if ((job.enrichment?.ocr_pending ?? 0) > 0) return false;
  if (requiredPipelineStagesOpen(job)) return false;
  if (
    job.enrichment?.rag_embedding_enabled === true &&
    job.enrichment?.rag_background_enabled !== false &&
    (job.enrichment?.rag_pending ?? 0) > 0 &&
    (job.enrichment?.rag_chunks ?? 0) > 0
  ) {
    return false;
  }

  if (pp?.phase === "complete") {
    // phase=complete is a backend claim; still require every orchestrated agent
    // (when the orchestration block exists) to be done.
    return (
      terminalStatus &&
      inventoryCountsFinished(job) &&
      !isBackgroundEnriching(job) &&
      !orchestratedAgentsIncomplete(job)
    );
  }

  // Counts finished but phase not yet flipped to complete — only if nothing else remains.
  if (inventoryCountsFinished(job) && terminalStatus && !isBackgroundEnriching(job)) {
    if (!orchestratedEnrichIncomplete(job)) {
      const orch = readOrchestration(job);
      if (orch?.agents) {
        const agentsDone = agentOrderForJob(job).every(({ id }) => {
          if (id === "embed_agent") return true;
          if (id === "artifacts_agent" && inventoryCountsFinished(job)) return true;
          return (orch.agents[id]?.state ?? "pending") === "done";
        });
        if (agentsDone) return true;
      }
    }
  }
  if (job.status === "indexing") return false;
  if (isBackgroundEnriching(job)) return false;
  if (orchestratedEnrichIncomplete(job)) return false;

  const orch = readOrchestration(job);
  if (orch?.agents) {
    for (const { id } of AGENT_ORDER) {
      if (id === "embed_agent") continue;
      if (id === "artifacts_agent" && inventoryCountsFinished(job)) continue;
      const state = orch.agents[id]?.state ?? "pending";
      if (state !== "done") return false;
    }
    if ((orch.overall_pct ?? 0) < 100 && !inventoryCountsFinished(job)) return false;
    return terminalStatus;
  }

  // Legacy pipeline cards — require every stage done, not job.status alone.
  const invProgress = job.pipeline_progress;
  if (invProgress?.phase === "artifact_inventory" || invProgress?.phase === "axiom_artifacts") {
    const total = invProgress.total ?? 0;
    const completed = invProgress.completed ?? 0;
    if (total > 0 && completed < total) return false;
  }

  if (!terminalStatus) {
    return false;
  }

  return !inventoryIncomplete(job);
}

/** Overall % — live extract file ratio, else max of card average and high-water. Never a single card. */
export function computeOverallPipelinePct(job: Job, stages: PipelineStageProgress[]): number {
  if (job.pipeline_progress?.serial_pipeline) return job.pipeline_progress.serial_pipeline.overall_pct;
  if (isPipelineFullyComplete(job)) return 100;
  const filesTotal = job.files_total ?? 0;
  const filesDone = job.files_extracted ?? 0;
  if (extractStillRunning(job) && filesTotal > 0) {
    return Math.min(99, Math.round((100 * filesDone) / filesTotal));
  }
  if (extractStillRunning(job)) {
    return Math.min(10, Math.max(1, job.progress_pct ?? 1));
  }
  const extractCard = stages.find((s) => s.id === "extraction_agent");
  if (extractCard?.state === "running" && filesTotal > 0 && filesDone < filesTotal) {
    return Math.min(99, Math.round((100 * filesDone) / filesTotal));
  }
  const fromCards =
    stages.length > 0
      ? Math.round(
          stages.reduce((acc, s) => acc + (s.state === "done" ? 100 : Math.max(0, s.pct)), 0) /
            stages.length,
        )
      : 0;
  const orch = readOrchestration(job);
  const pp = job.pipeline_progress;
  const staleExtractionSnapshot =
    Boolean(job.extracted_disk_uri) &&
    orch?.current_agent_id === "extraction_agent" &&
    pp?.phase !== "extract";
  const highWater = staleExtractionSnapshot
    ? 0
    : (orch?.progress_high_water ?? orch?.overall_pct ?? 0);
  let invPct = 0;
  if (pp?.phase === "artifact_inventory" || pp?.phase === "axiom_artifacts") {
    const total = pp.total ?? 0;
    const completed = pp.completed ?? 0;
    if (total > 0) invPct = Math.round((100 * completed) / total);
  }
  // progress_pct is a legacy per-phase field (disk extraction writes 100 when
  // extraction completes). Once orchestration exists it must not masquerade as
  // the overall pipeline percentage.
  const legacyJobPct = orch ? 0 : (job.progress_pct ?? 0);
  const n = Math.max(fromCards, typeof highWater === "number" ? highWater : 0, invPct, legacyJobPct);
  if (isPipelineFullyComplete(job)) return 100;
  return Math.min(99, n >= 100 ? 99 : n);
}

function canonicalAgentLabel(job: Job): string | null {
  const orch = readOrchestration(job);
  if (!orch) return null;
  const fromOrder = AGENT_ORDER.find((a) => a.id === orch.current_agent_id);
  if (fromOrder) return fromOrder.label;
  return orch.current_agent_label ? sanitizePipelineLabel(orch.current_agent_label) : null;
}

export function currentAgentLabel(job: Job): string | null {
  const fromOrch = canonicalAgentLabel(job);
  if (fromOrch) return fromOrch;
  return currentAgentDisplay(job)?.label ?? null;
}

export type CurrentAgentDisplay = {
  label: string;
  mode: "running" | "next";
};

/** Banner text for the active or upcoming pipeline agent (never mis-label pending as running). */
export function currentAgentDisplay(job: Job): CurrentAgentDisplay | null {
  if (isPipelineFullyComplete(job) && !requiredPipelineStagesOpen(job)) {
    return null;
  }
  const orch = readOrchestration(job);
  if (orch?.current_agent_label) {
    const state = orch.current_agent_state ?? "pending";
    const label = canonicalAgentLabel(job) ?? sanitizePipelineLabel(orch.current_agent_label);
    if (state === "running") {
      return { label, mode: "running" };
    }
    if (state === "pending") {
      const pipelineStarted =
        job.status !== "created" ||
        Boolean(job.disk_source || job.extracted_disk_uri || (job.progress_pct ?? 0) > 0);
      if (!pipelineStarted) {
        return { label: agentOrderForJob(job)[0]?.label || label, mode: "next" };
      }
      return { label, mode: "next" };
    }
  }

  const inferred = inferRunningAgentIndex(job);
  if (inferred < 0) {
    return { label: agentOrderForJob(job)[0]?.label || "Drive mount", mode: "next" };
  }
  if (inferred >= AGENT_ORDER.length) return null;
  return { label: AGENT_ORDER[inferred].label, mode: "running" };
}
