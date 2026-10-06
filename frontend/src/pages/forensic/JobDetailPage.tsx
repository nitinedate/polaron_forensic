import { useCallback, useEffect, useMemo, useRef, useState } from "react";

import { Link, useLocation, useNavigate, useParams } from "react-router-dom";

import {

  ArrowRight,

  Download,


  ListChecks,

  Play,

  RefreshCw,

  Square,

  Trash2,

  Upload,

} from "lucide-react";

import { Badge, Button, Card, PageHeader, Spinner } from "../../components/ui";

import { HostEvidencePanel, type HostEvidencePanelHandle } from "../../components/forensic/HostEvidencePanel";
import { JobInventoryButton } from "../../components/forensic/JobInventoryDialog";

import { JobActivityPanel } from "../../components/forensic/JobActivityPanel";

import { AgentPipelineBanner } from "../../components/forensic/AgentPipelineBanner";
import { ProgressAgentPanel } from "../../components/forensic/ProgressAgentPanel";
import { PipelineStepModal } from "../../components/forensic/PipelineStepModal";
import { isJobStale } from "../../lib/pipelineStages";
import { JobProgressBanner } from "../../components/forensic/JobProgressBanner";
import { RagQaPanel } from "../../components/forensic/RagQaPanel";

import { ApiError, refreshAccessToken } from "../../lib/api";

import { forensicApi } from "../../lib/forensicApi";

import { useToast } from "../../lib/toast";

import { useAuth } from "../../lib/auth";

import { useJobUploadSession } from "../../hooks/useJobUploadSession";
import { jobUploadSession } from "../../lib/jobUploadSession";
import { usePipelineStepTracker } from "../../hooks/usePipelineStepTracker";

import type { ExtractionLog, Job } from "../../lib/types/forensic";
import { effectiveJobProgressPct } from "../../lib/extractCoverage";
import { mergeJobProgress, pickLatestPipelineLogMessage } from "../../lib/jobProgress";
import { evidenceTransportModeForJob, isPipelineFullyComplete, type EvidenceTransportMode } from "../../lib/orchestrationStages";
import { formatPipelineProgress, parsePathProgressFromLog } from "../../lib/pipelineProgress";



const STATUS_TONE: Record<string, "neutral" | "green" | "amber" | "red" | "indigo"> = {

  pending: "amber",

  uploaded: "amber",

  processing: "indigo",

  extracting: "indigo",

  running: "indigo",

  classified: "green",

  interrupted: "amber",

  paused: "amber",

  completed: "green",

  failed: "red",

};



const TERMINAL_STATUSES = new Set(["completed", "failed", "classified"]);

const ACTIVE_STATUSES = new Set([
  "processing",
  "building_disk",
  "disk_ready",
  "artifacts_registered",
  "parsed",
  "extracting",
  "extracted",
  "indexing",
  "interrupted",
  "paused",
]);



const MAX_LIVE_LOGS = 200;

function mergeLogs(prev: ExtractionLog[], incoming: ExtractionLog[]): ExtractionLog[] {
  if (incoming.length === 0) return prev;
  const ids = new Set(prev.map((l) => l.id));
  const merged = [...prev, ...incoming.filter((l) => !ids.has(l.id))];
  merged.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
  // Keep the live DOM bounded. The database still retains the complete audit log.
  return merged.length > MAX_LIVE_LOGS ? merged.slice(-MAX_LIVE_LOGS) : merged;
}



const EMPTY_DRIVE_LETTERS: string[] = [];

export function JobDetailPage() {

  const { jobId } = useParams<{ jobId: string }>();
  const navigate = useNavigate();
  const location = useLocation();
  const locationState = (location.state || {}) as {
    autoSelectFolder?: boolean;
    lockedSourceType?: "disk" | "mobile" | "ios_backup" | "android_backup";
    mobileOs?: string;
    prefillEvidencePath?: string;
    driveMount?: { newly_attached?: string[]; missing?: string[]; drives?: string[] };
  };
  const recommendedDriveLetters = useMemo(
    () => locationState.driveMount?.newly_attached || locationState.driveMount?.missing || EMPTY_DRIVE_LETTERS,
    [locationState.driveMount?.newly_attached, locationState.driveMount?.missing],
  );

  const toast = useToast();

  const { hasPermission } = useAuth();

  const canRun = hasPermission("job:run");

  const canRegisterEvidence = hasPermission("job:run") || hasPermission("artifact:manage");



  const [job, setJob] = useState<Job | null>(null);

  const [logs, setLogs] = useState<ExtractionLog[]>([]);

  const [logsLoading, setLogsLoading] = useState(true);

  const [loading, setLoading] = useState(true);
  const [jobNotFound, setJobNotFound] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  const [processing, setProcessing] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [deleting, setDeleting] = useState(false);

  const [processRequested, setProcessRequested] = useState(false);

  const [pollStopped, setPollStopped] = useState(false);

  const pollFailures = useRef(0);

  const pollBackoffMs = useRef(5000);

  const pollStoppedRef = useRef(pollStopped);

  const lastLogTsRef = useRef<string | undefined>();
  const uploadPanelRef = useRef<HTMLDivElement>(null);
  const evidencePanelRef = useRef<HostEvidencePanelHandle>(null);
  const autoResumeAttempted = useRef<string | null>(null);
  const autoProcessRegisteredAttempted = useRef(false);
  const pageAliveRef = useRef(true);
  const [registerProgress, setRegisterProgress] = useState({
    active: false,
    pct: 0,
    fileName: "",
    phase: "idle" as "idle" | "mounting" | "listing" | "registering",
  });
  const [pipelineError, setPipelineError] = useState<string | null>(null);
  const [pipelineErrorStep, setPipelineErrorStep] = useState<number | undefined>(undefined);
  const [refreshingArtifacts, setRefreshingArtifacts] = useState(false);
  const [receivingSegmentsStarted, setReceivingSegmentsStarted] = useState(false);
  const [evidenceTransferMode, setEvidenceTransferMode] = useState<"none" | "server" | "client">("none");
  const [selectedTransportMode, setSelectedTransportMode] = useState<EvidenceTransportMode>("unknown");

  pollStoppedRef.current = pollStopped;

  useEffect(() => {
    pageAliveRef.current = true;
    return () => {
      pageAliveRef.current = false;
    };
  }, [jobId]);

  const toastRef = useRef(toast);

  toastRef.current = toast;

  const uploadSession = useJobUploadSession(jobId ?? "");

  // The current examiner choice is authoritative for presentation even before
  // a server mount/register request finishes. This prevents stale browser-upload
  // metadata from showing Download Agent after the examiner selects a server HDD.
  const pipelineDisplayJob = useMemo(() => {
    if (!job || evidenceTransferMode === "none") return job;
    const diskSource = { ...(job.disk_source || {}) };
    diskSource.intake = evidenceTransferMode === "client" ? "browser_upload" : "server_local";
    return { ...job, disk_source: diskSource };
  }, [job, evidenceTransferMode]);

  const pipelineSteps = usePipelineStepTracker(pipelineDisplayJob, {
    registering: registerProgress.active && registerProgress.phase !== "listing",
    receivingSegmentsStarted,
    processRequested,
    pipelineError,
    pipelineErrorStep,
    listingFolder: registerProgress.phase === "listing",
    mountingDrive: registerProgress.phase === "mounting",
    uploading:
      evidenceTransferMode === "client" && (uploadSession.uploading || uploadSession.isRunning),
    uploadDetail: evidenceTransferMode === "client" && uploadSession.progress
      ? `Uploading ${uploadSession.progress.index + 1}/${uploadSession.progress.total}: ${uploadSession.progress.fileName} (${uploadSession.progress.filePct}%)`
      : evidenceTransferMode === "client" && uploadSession.uploading
        ? "Uploading evidence files from this computer…"
        : null,
  });



  const load = useCallback(async (opts?: { silent?: boolean }) => {
    if (!jobId || !pageAliveRef.current) return;
    if (!opts?.silent) {
      setLoading(true);
      setLogsLoading(true);
    }

    try {
      // Resolve the owning API first (mobile extract vs disk forensic), then
      // load logs. Logs are best-effort and must not 404 the job.
      const j = await forensicApi.getJob(jobId);
      if (!pageAliveRef.current) return;
      const logResult = await Promise.allSettled([
        forensicApi.listLogs(jobId, { from: lastLogTsRef.current, limit: 100 }),
      ]).then((r) => r[0]);
      if (!pageAliveRef.current) return;
      setJobNotFound(false);
      setLoadError(null);
      setJob((prev) => mergeJobProgress(prev, j));

      if (logResult.status === "fulfilled") {
        const logRes = logResult.value;
        if (logRes.items.length > 0) {
          setLogs((prev) => mergeLogs(prev, logRes.items));
          const newest = logRes.items.reduce(
            (max, item) => (item.timestamp > max ? item.timestamp : max),
            logRes.items[0].timestamp
          );
          lastLogTsRef.current = newest;
        }
      } else {
        const logErr = logResult.reason;
        if (!opts?.silent && logErr instanceof ApiError && logErr.status === 401) {
          void refreshAccessToken();
        }
      }

      pollFailures.current = 0;
      pollBackoffMs.current =
        j.status === "building_disk"
          ? 3000
          : j.status === "indexing"
            ? 8000
            : processRequested || ACTIVE_STATUSES.has(j.status)
              ? 4000
              : j.status === "registered"
                ? 5000
                : 10_000;
      setPollStopped(false);
    } catch (e: unknown) {
      const err = e instanceof Error ? e : null;
      const isUnauthorized = e instanceof ApiError && e.status === 401;
      const isNotFound = e instanceof ApiError && e.status === 404;
      const isTenantRequired = e instanceof ApiError && e.status === 400 && e.code === "tenant_required";
      const isBadGateway = e instanceof ApiError && e.status === 502;
      const isRateLimited = e instanceof ApiError && e.status === 429;

      if (isNotFound) {
        // Stay on this job URL. Never send the examiner to Disk Jobs — a 404
        // is often a sibling-API miss or a poll that finished after they left.
        if (!pageAliveRef.current) return;
        setJobNotFound(true);
        setLoadError(null);
        setPollStopped(true);
        if (!opts?.silent) {
          toastRef.current.info("This job is no longer available from the current API.");
        }
        return;
      }

      if (isTenantRequired) {
        setLoadError("Organization context was lost. Refresh the page or sign in again.");
        setPollStopped(true);
        return;
      }

      if (isUnauthorized) {
        // api.ts already performs refresh-token rotation before surfacing 401.
        if (!pageAliveRef.current) return;
        setLoadError("Authentication could not be refreshed. Please sign in again.");
        setPollStopped(true);
        return;
      }

      pollFailures.current += 1;
      const isTimeout = e instanceof ApiError && e.code === "timeout";
      if (isTimeout && opts?.silent) {
        pollFailures.current = Math.max(0, pollFailures.current - 1);
      }
      if (isBadGateway || isRateLimited) {
        pollBackoffMs.current = Math.min(pollBackoffMs.current * 2, 60_000);
      }
      if (pollFailures.current >= 8) setPollStopped(true);

      // Keep any previously loaded job on transient failures. On first load show
      // a retryable error, never the misleading "job deleted" message.
      if (!pageAliveRef.current) return;
      setLoadError(err?.message ?? "Unable to load job detail");
      if (!opts?.silent && !isRateLimited && !isTimeout) {
        toastRef.current.error(err?.message ?? "Failed to load job");
      }
    } finally {
      if (pageAliveRef.current) {
        if (!opts?.silent) setLoading(false);
        setLogsLoading(false);
      }
    }
  }, [jobId, processRequested]);

  useEffect(() => {
    setJobNotFound(false);
    setLoadError(null);
    setPollStopped(false);
    setEvidenceTransferMode("none");
    setSelectedTransportMode("unknown");
  }, [jobId]);

  // Restore transport mode after a reload, but never overwrite an explicit
  // selection made on this page (server browser vs client upload control).
  useEffect(() => {
    if (!job || evidenceTransferMode !== "none") return;
    const persisted = evidenceTransportModeForJob(job);
    setSelectedTransportMode(persisted);
    if (persisted === "client") setEvidenceTransferMode("client");
    else if (persisted === "server") setEvidenceTransferMode("server");
  }, [job, evidenceTransferMode]);

  const evidenceTransportMode: EvidenceTransportMode =
    selectedTransportMode !== "unknown"
      ? selectedTransportMode
      : evidenceTransferMode === "none"
        ? evidenceTransportModeForJob(job)
        : evidenceTransferMode;
  const clientTransferActive = evidenceTransportMode === "client";

  useEffect(() => {
    if (!job || !receivingSegmentsStarted) return;
    if (
      job.segment_readiness?.ready ||
      !["created", "registered", "awaiting_segments"].includes(job.status)
    ) {
      setReceivingSegmentsStarted(false);
    }
  }, [job?.status, job?.segment_readiness?.ready, receivingSegmentsStarted, job]);

  // Watchdog: if "Receiving segments" spins with no progress, surface an error.
  // Do not fire while a browser upload is still moving bytes (E01s take minutes).
  useEffect(() => {
    if (!receivingSegmentsStarted && !registerProgress.active) return undefined;
    if (registerProgress.phase === "mounting") return undefined;
    const snap = jobId ? jobUploadSession.get(jobId) : null;
    const uploadBusy =
      uploadSession.uploading ||
      uploadSession.isRunning ||
      Boolean(
        snap?.files.some((f) => f.status === "queued" || f.status === "uploading")
      );
    if (uploadBusy) return undefined;
    if (job?.segment_readiness?.ready) return undefined;
    const id = window.setTimeout(() => {
      if (job?.segment_readiness?.ready) {
        setReceivingSegmentsStarted(false);
        return;
      }
      const live = jobId ? jobUploadSession.get(jobId) : null;
      if (
        jobUploadSession.isRunning(jobId ?? "") ||
        live?.uploading ||
        live?.files.some((f) => f.status === "queued" || f.status === "uploading")
      ) {
        return;
      }
      setReceivingSegmentsStarted(false);
      setRegisterProgress({ active: false, pct: 0, fileName: "", phase: "idle" });
      pipelineSteps.setRegisterError(
        "Still waiting for segment registration. If you attached a new drive, wait for it to mount, choose that folder, then Try again."
      );
    }, 600_000);
    return () => window.clearTimeout(id);
    // Re-arm when upload/register progress changes so a live transfer is not treated as stuck.
  }, [
    receivingSegmentsStarted,
    registerProgress.active,
    registerProgress.pct,
    registerProgress.fileName,
    uploadSession.uploading,
    uploadSession.isRunning,
    uploadSession.progress?.index,
    uploadSession.progress?.filePct,
    uploadSession.files,
    job?.segment_readiness?.ready,
    jobId,
  ]);

  useEffect(() => {
    if (!processRequested || !job) return;
    if (!["registered", "created"].includes(job.status)) {
      setProcessRequested(false);
    }
  }, [processRequested, job?.status, job]);

  useEffect(() => {
    if (!pipelineError || !job) return;
    if (job.status === "failed" || job.status === "paused") return;
    if (ACTIVE_STATUSES.has(job.status) || registerProgress.active) {
      setPipelineError(null);
      setPipelineErrorStep(undefined);
    }
  }, [job?.status, pipelineError, registerProgress.active, job]);

  const enrichSubProgress = useMemo(() => {
    for (let i = logs.length - 1; i >= 0; i -= 1) {
      const msg = logs[i]?.message ?? "";
      const llm = msg.match(/LLM\s+\[(\d+)\/(\d+)\]/i);
      if (llm) return `LLM ${llm[1]}/${llm[2]}`;
      const rag = msg.match(/RAG progress\s+\[(\d+)\/(\d+)\]/i);
      if (rag) {
        const gpu = msg.match(/on GPU \(([^)]+)\)/i);
        return gpu
          ? `GPU embed ${rag[1]}/${rag[2]} (${gpu[1]})`
          : `embed/index ${rag[1]}/${rag[2]}`;
      }
      const neo = msg.match(/neo4j_entities=(\d+)\s+neo4j_relationships=(\d+)/i);
      if (neo) return `Neo4j ${neo[1]} entities · ${neo[2]} rels`;
      const enrichStats = msg.match(
        /artifacts_annotated=(\d+).*postgres_entities=(\d+)/i
      );
      if (enrichStats) {
        return `annotated ${enrichStats[1]} · entities ${enrichStats[2]}`;
      }
      const legacy = msg.match(/entities=(\d+)\s+relationships=(\d+)/i);
      if (legacy) return `Neo4j ${legacy[1]} entities · ${legacy[2]} rels`;
    }
    return null;
  }, [logs]);

  const latestLogMessage = useMemo(() => pickLatestPipelineLogMessage(logs), [logs]);

  const pathProgressLabel = useMemo(() => {
    if (job) {
      const live = formatPipelineProgress(job.pipeline_progress, job);
      if (live) return live;
    }
    for (let i = logs.length - 1; i >= 0; i -= 1) {
      const parsed = parsePathProgressFromLog(logs[i]?.message ?? "");
      if (parsed) return formatPipelineProgress(parsed);
    }
    return null;
  }, [job, logs]);

  const displayProgressPct = job ? effectiveJobProgressPct(job) : 0;
  const pipelineFullyComplete = useMemo(() => (job ? isPipelineFullyComplete(job) : false), [job]);

  const autoFolderOpened = useRef(false);
  const autoIngested = useRef(false);
  useEffect(() => {
    if (!job) return;
    const prefill = (locationState.prefillEvidencePath || "").trim();
    // Register the acquired run once, only while the job has no evidence yet.
    // The folder may already be persisted by POST /jobs (no longer registers
    // synchronously), so "hasFolder" alone must not suppress this step. Never
    // re-register a job that is running or finished — that used to re-open the
    // Receiving segments modal on a completed pipeline.
    const hasSegments =
      (job.evidence_count ?? 0) > 0 || Boolean(job.segment_readiness?.has_disk_segments);
    const idle = ["created", "registered", "awaiting_segments"].includes(job.status);
    if (prefill && !autoIngested.current && !hasSegments && idle) {
      autoIngested.current = true;
      autoFolderOpened.current = true;
      const timer = window.setTimeout(() => {
        evidencePanelRef.current?.registerHostPath(prefill)?.catch((err: unknown) => {
          // The panel already surfaced the error via onRegisterError/toast.
          console.warn("auto-register of acquired folder failed", err);
        });
      }, 250);
      return () => window.clearTimeout(timer);
    }
    if (prefill && (hasSegments || !idle)) {
      autoIngested.current = true;
      autoFolderOpened.current = true;
      return;
    }
    if (autoFolderOpened.current) return;
    if (!locationState.autoSelectFolder) return;
    autoFolderOpened.current = true;
    const timer = window.setTimeout(() => {
      evidencePanelRef.current?.openEvidenceFolder();
    }, 250);
    return () => window.clearTimeout(timer);
  }, [job, locationState.autoSelectFolder, locationState.prefillEvidencePath]);

  const refreshArtifacts = useCallback(async () => {
    if (!jobId) return;
    setRefreshingArtifacts(true);
    try {
      const res = await forensicApi.refreshArtifactInventory(jobId);
      setJob((prev) => mergeJobProgress(prev, res.job));
      toastRef.current.success("Artifact counts refreshed from database");
    } catch (e: unknown) {
      toastRef.current.error(e instanceof Error ? e.message : "Failed to refresh artifacts");
    } finally {
      setRefreshingArtifacts(false);
    }
  }, [jobId]);

  useEffect(() => {

    pollFailures.current = 0;

    setPollStopped(false);
    setProcessRequested(false);

    lastLogTsRef.current = undefined;

    setLogs([]);

    load();

  }, [load]);



  useEffect(() => {
    const ragActive = Boolean(
      job?.enrichment?.rag_embedding_enabled &&
        (job?.enrichment?.rag_indexing || (job?.enrichment?.rag_pending ?? 0) > 0)
    );
    if (
      !jobId ||
      !job ||
      pollStopped ||
      pipelineFullyComplete ||
      (TERMINAL_STATUSES.has(job.status) && !ragActive)
    )
      return;

    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const schedule = () => {
      timer = setTimeout(async () => {
        if (cancelled || !pageAliveRef.current) return;
        await load({ silent: true });
        if (!cancelled && pageAliveRef.current && !pollStoppedRef.current) schedule();
      }, pollBackoffMs.current);
    };

    schedule();

    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };

  }, [jobId, job?.status, pollStopped, processRequested, load, pipelineFullyComplete]);

  useEffect(() => {
    if (!jobId || !registerProgress.active || pollStopped) return;
    let cancelled = false;
    void load({ silent: true });
    const id = setInterval(() => {
      if (cancelled || !pageAliveRef.current) return;
      void load({ silent: true });
    }, 1500);
    return () => {
      cancelled = true;
      clearInterval(id);
    };
  }, [jobId, registerProgress.active, pollStopped, load]);

  // Auto-start processing when segments registered but worker queue missed (folder-select automation)
  useEffect(() => {
    if (!jobId || !job || !canRun || processing || autoProcessRegisteredAttempted.current) return;
    if (job.status !== "registered" || !job.segment_readiness?.ready) return;
    if (!job.segment_readiness.has_disk_segments && !(job.evidence_count ?? 0)) return;
    autoProcessRegisteredAttempted.current = true;
    setProcessRequested(true);
    setProcessing(true);
    void (async () => {
      try {
        await forensicApi.processJob(jobId);
        toastRef.current.success("Pipeline started automatically");
        lastLogTsRef.current = undefined;
        await load({ silent: true });
      } catch (e: unknown) {
        autoProcessRegisteredAttempted.current = false;
        toastRef.current.error(e instanceof Error ? e.message : "Could not start pipeline automatically");
      } finally {
        setProcessing(false);
      }
    })();
  }, [jobId, job, canRun, processing, load]);

  // Auto-resume stalled GPU RAG when embedding was interrupted.
  // Never thrash OCR: after baseline, finish OCR before background corpus RAG.
  useEffect(() => {
    if (!jobId || !job || !canRun || processing) return;
    if (job.enrichment?.rag_embedding_enabled !== true) return;
    const ragPending = job.enrichment?.rag_pending ?? 0;
    const ocrPending = job.enrichment?.ocr_pending ?? 0;
    const baselineReady = Boolean(job.enrichment?.baseline_ready);
    if (baselineReady && ocrPending > 0) return;
    if (job.enrichment?.background_rag_deferred_for_ocr) return;
    const ragStalled =
      ragPending > 0 &&
      Boolean(job.enrichment?.rag_indexing) &&
      isJobStale(job.updated_at, true, 180_000) &&
      !pollStopped;
    if (!ragStalled) return;
    const key = `${job.id}:rag-resume:${Math.floor(ragPending / 5000)}`;
    if (autoResumeAttempted.current === key) return;
    autoResumeAttempted.current = key;
    setProcessing(true);
    void (async () => {
      try {
        const res = await forensicApi.resumeRag(jobId);
        if ((res as { deferred_for_ocr?: boolean }).deferred_for_ocr) {
          toastRef.current.info(res.message || "Finishing OCR before background RAG");
        } else {
          toastRef.current.success(res.message || "GPU RAG resume queued");
        }
        lastLogTsRef.current = undefined;
        await load({ silent: true });
      } catch (e: unknown) {
        toastRef.current.error(e instanceof Error ? e.message : "RAG auto-resume failed");
      } finally {
        setProcessing(false);
      }
    })();
  }, [jobId, job, canRun, processing, pollStopped, load]);

  // Auto-continue pipeline when extract failed/stalled (mount→extract→phase3→RAG)
  useEffect(() => {
    if (!jobId || !job || !canRun || processing) return;
    const extracting = job.status === "building_disk" || job.status === "processing";
    // V45.5: a worker that is heartbeating its lease is alive even if updated_at lags.
    const workerAlive = job.worker_liveness?.alive === true;
    const stale = extracting && !workerAlive && isJobStale(job.updated_at, true, 240_000);
    const needsResume =
      job.status === "failed" ||
      job.status === "paused" ||
      (stale && !["indexing", "extracted", "disk_ready", "indexed"].includes(job.status));
    if (!needsResume) return;
    const key = `${job.id}:${job.status}:${job.error || ""}:${stale ? "stale" : ""}`;
    if (autoResumeAttempted.current === key) return;
    autoResumeAttempted.current = key;
    setProcessing(true);
    setProcessRequested(true);
    void (async () => {
      try {
        const res = await forensicApi.resumeJob(jobId);
        toastRef.current.success(res.message || "Pipeline resumed automatically");
        lastLogTsRef.current = undefined;
        setJob((prev) =>
          prev
            ? {
                ...prev,
                status: res.status === "paused" ? "paused" : "processing",
                progress_pct: Math.max(prev.progress_pct ?? 0, 5),
                error: null,
                stop_requested: false,
              }
            : prev
        );
        await load({ silent: true });
      } catch (e: unknown) {
        setProcessRequested(false);
        const msg = e instanceof Error ? e.message : "Auto-resume failed";
        setPipelineErrorStep(undefined);
        setPipelineError(msg);
        toastRef.current.error(msg);
        await load({ silent: true });
      } finally {
        setProcessing(false);
      }
    })();
  }, [jobId, job, canRun, processing, load]);

  async function runProcess(resume = false) {
    if (!jobId) return;
    setProcessing(true);
    setProcessRequested(true);
    try {
      const res = resume
        ? await forensicApi.resumeJob(jobId)
        : await forensicApi.processJob(jobId);
      toast.success(res.message);
      lastLogTsRef.current = undefined;
      setJob((prev) =>
        prev
          ? {
              ...prev,
              status: res.status === "paused" ? "paused" : "processing",
              progress_pct: Math.max(prev.progress_pct ?? 0, 5),
              error: null,
              stop_requested: false,
            }
          : prev
      );
      await load({ silent: true });
    } catch (e: unknown) {
      setProcessRequested(false);
      const msg = e instanceof Error ? e.message : "Action failed";
      setPipelineErrorStep(undefined);
      setPipelineError(msg);
      toast.error(msg);
      await load({ silent: true });
    } finally {
      setProcessing(false);
    }
  }

  function handlePipelineStepRetry() {
    pipelineSteps.clearRegisterError();
    setPipelineError(null);
    setPipelineErrorStep(undefined);
    if (uploadSession.uploading || uploadSession.isRunning) {
      return;
    }
    setReceivingSegmentsStarted(false);
    setRegisterProgress({ active: false, pct: 0, fileName: "", phase: "idle" });
    const evidenceStepId = pipelineSteps.currentStep.id;
    if (evidenceStepId === "download_agent") {
      evidencePanelRef.current?.openEvidenceFolder();
      return;
    }
    if (["drive_mount_agent", "list_folder_agent", "segments_agent"].includes(evidenceStepId)) {
      if (evidencePanelRef.current?.registerManualPath) {
        evidencePanelRef.current.registerManualPath();
      } else {
        evidencePanelRef.current?.openEvidenceFolder();
      }
      return;
    }
    void runProcess(true);
  }

  function handlePipelineStepCancel() {
    setReceivingSegmentsStarted(false);
    setRegisterProgress({ active: false, pct: 0, fileName: "", phase: "idle" });
    pipelineSteps.setRegisterError(
      "Registration cancelled. Choose the evidence directory again and retry."
    );
  }

  async function hardDeleteJob() {
    if (!jobId || deleting) return;
    const mobileDelete = Boolean(
      job &&
        (job.type === "mobile_extraction" ||
          job.type === "ios_backup" ||
          job.type === "android_backup" ||
          job.type === "android_mobile" ||
          job.type === "ios_mobile" ||
          String(job.disk_source?.source_type || "") === "mobile" ||
          Boolean(job.disk_source?.mobile_os))
    );
    const ok = window.confirm(
      mobileDelete
        ? `Permanently delete job ${jobId}?\n\nRemoves job metadata, RAG index, staging copies and database rows.\nOriginal mobile/disk image files on the host evidence folder are NOT deleted.`
        : `Permanently delete job ${jobId}?\n\nThis hard-deletes the job and every related file, object, and database row. Host evidence folders selected for in-place processing are preserved. This cannot be undone.`
    );
    if (!ok) return;
    setDeleting(true);
    try {
      await forensicApi.deleteJob(jobId);
      toast.success(mobileDelete ? "Job deleted — host image files preserved" : "Job deleted");
      const os = String(job?.disk_source?.mobile_os || job?.type || "").toLowerCase();
      navigate(
        mobileDelete
          ? os.includes("ios")
            ? "/mobile/ios"
            : "/mobile/android"
          : "/forensic/jobs"
      );
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Could not delete job");
      setDeleting(false);
    }
  }

  async function runStop() {
    if (!jobId) return;
    setStopping(true);
    try {
      const res = await forensicApi.stopJob(jobId);
      toast.success(res.message);
      setJob((prev) => (prev ? { ...prev, stop_requested: true } : prev));
      await load({ silent: true });
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Stop failed");
      await load({ silent: true });
    } finally {
      setStopping(false);
    }
  }



  if (loading && !job && !loadError && !jobNotFound) {
    return (
      <div>
        <PageHeader title="Forensic job" subtitle="Loading job details…" />
        <Card>
          <Spinner />
        </Card>
      </div>
    );
  }

  if (jobNotFound) {
    return (
      <div className="px-1 py-10 text-center">
        <p className="text-sm text-ink-500">Job not found — it may have been deleted.</p>
        <div className="mt-3 flex flex-col items-center gap-2">
          <Link to="/forensic/mobile" className="text-sm font-semibold text-brand-600 hover:underline">
            Back to mobile extraction
          </Link>
          <Link to="/forensic/jobs" className="text-sm font-semibold text-brand-600 hover:underline">
            Back to forensic jobs
          </Link>
        </div>
      </div>
    );
  }

  if (!job) {
    return (
      <div className="px-1 py-10 text-center">
        <p className="text-sm font-semibold text-ink-700">Unable to load this job right now.</p>
        <p className="mx-auto mt-2 max-w-2xl text-sm text-ink-500">
          {loadError || "The API is busy. The job has not been marked as deleted."}
        </p>
        <div className="mt-4 flex justify-center gap-2">
          <Button variant="outline" onClick={() => void load()}>Try again</Button>
          <Link to="/forensic/jobs" className="inline-flex items-center text-sm font-semibold text-brand-600 hover:underline">
            Back to forensic jobs
          </Link>
        </div>
      </div>
    );
  }

  const isMobileJob =
    locationState.lockedSourceType === "mobile" ||
    job.type === "mobile_extraction" ||
    job.type === "ios_backup" ||
    job.type === "android_backup" ||
    String(job.disk_source?.source_type || "") === "mobile" ||
    Boolean(job.disk_source?.mobile_os);
  const mobileOsRaw = String(locationState.mobileOs || job.disk_source?.mobile_os || "").toLowerCase();
  const mobileOsLabel =
    mobileOsRaw === "android" ? "Android" : mobileOsRaw === "ios" ? "iOS" : mobileOsRaw === "other" ? "Other / Unknown" : null;
  const capabilityLabel = String(job.disk_source?.capability_label || (isMobileJob ? "SUPPORTED_IMPORT" : "") || "") || null;

  const noCaseLinked = !job.case_id && ["registered", "processing"].includes(job.status);
  const needsFolderPick = job.status === "created";
  const isExtracting = job.status === "building_disk" || job.status === "processing";
  // Long E01 walks can exceed 90s without file counters — use 4 min; heartbeats refresh updated_at
  const extractionStale = isExtracting && isJobStale(job.updated_at, true, 240_000);
  const isPipelineRunning =
    isExtracting ||
    ["indexing", "extracted", "extracting", "disk_ready", "parsed", "artifacts_registered"].includes(job.status);
  const canStop = canRun && isPipelineRunning && !job.stop_requested && job.status !== "paused" && !extractionStale;
  const showResume =
    canRun &&
    (job.status === "paused" || job.status === "failed" || extractionStale);
  const showProcess =
    canRun &&
    !isExtracting &&
    !["paused", "created", "registered", "disk_ready", "indexing", "indexed"].includes(job.status);
  const showTopProgressBanner =
    registerProgress.active ||
    uploadSession.uploading ||
    uploadSession.isRunning;

  return (

    <div>

      {needsFolderPick && (
        <Card className="mb-4 border-brand-300 bg-brand-50 p-4 text-sm text-brand-950">
          <p className="font-semibold">
            {isMobileJob
              ? "Job ready — select your mobile extraction folder to start"
              : "Job ready — select your evidence folder to start"}
          </p>
          <p className="mt-1 text-brand-900">
            {isMobileJob ? (
              <>
                Click <strong>Select directory…</strong>, choose the mobile extraction/image directory from any
                available HDD, SSD, USB/pendrive, external drive or mapped drive, then start processing.
                {mobileOsLabel ? (
                  <>
                    {" "}
                    Selected OS: <strong>{mobileOsLabel}</strong>
                    {capabilityLabel ? (
                      <>
                        {" "}
                        · Capability: <strong>{capabilityLabel}</strong>
                      </>
                    ) : null}
                  </>
                ) : null}
              </>
            ) : (
              <>
                Click <strong>Select evidence directory…</strong>, choose the required folder from any available
                HDD, SSD, USB/pendrive, external drive or mapped network drive. The selected path is processed
                in place without a separate download step.
              </>
            )}
          </p>
        </Card>
      )}

      {job.disk_source?.intake === "server_local" ? (
        <Card className="mb-4 border-emerald-200 bg-emerald-50 p-4 text-sm text-emerald-950">
          <p className="font-semibold">Evidence directory ready</p>
          <p className="mt-1 text-xs text-emerald-800">
            The selected evidence path is processed in place. No separate download or duplicate staging copy is required.
          </p>
          {job.disk_source?.evidence_folder ? (
            <p className="mt-2 break-all font-mono text-xs text-emerald-800">
              {String(job.disk_source.evidence_folder)}
            </p>
          ) : null}
        </Card>
      ) : null}

      {(typeof job.disk_source?.staging_host_path === "string" && job.disk_source.staging_host_path) ||
      job.disk_source?.intake === "browser_upload" ? (
        <Card className="mb-4 border-ink-200 bg-white p-4 text-sm text-ink-800">
          <p className="font-semibold">Server dump folder</p>
          <p className="mt-1 font-mono text-xs text-ink-700">
            {String(job.disk_source?.staging_host_path || `data/uploads/${job.id}/intake`)}
          </p>
          {job.disk_source?.staging_container_path ? (
            <p className="mt-1 text-xs text-ink-500">
              Container: <span className="font-mono">{String(job.disk_source.staging_container_path)}</span>
            </p>
          ) : null}
          {job.disk_source?.staging_object_prefix && job.disk_source?.source_type === "mobile" ? (
            <p className="mt-1 text-xs text-ink-500">
              Object store: <span className="font-mono">{String(job.disk_source.staging_object_prefix)}</span>
            </p>
          ) : null}
          <p className="mt-2 text-xs text-ink-600">
            {job.disk_source?.staging_purged
              ? "This dump was deleted after the pipeline finished. Extracted artifacts stay in the job store."
              : "Client disk images upload with up to 5 concurrent transfers. The staging folder is deleted only after extraction and the complete forensic pipeline finish successfully; failed/interrupted jobs retain it for resume."}
          </p>
        </Card>
      ) : null}

      {noCaseLinked && !needsFolderPick && (
        <Card className="mb-4 border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
          <p className="font-semibold">Case not linked</p>
          <p className="mt-1 text-amber-800">
            {isMobileJob
              ? "Select a mobile extraction folder below — a case is created automatically when evidence is registered."
              : "Select a disk folder below — a case is created automatically when evidence is registered."}
          </p>
        </Card>
      )}

      {job.status === "paused" && (
        <Card className="mb-4 border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
          <p className="font-semibold">Extraction paused</p>
          <p className="mt-1 text-amber-800">
            {job.error || "Click Resume to continue from the last saved checkpoint."}
          </p>
        </Card>
      )}

      {extractionStale && (
        <Card className="mb-4 border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
          <p className="font-semibold">Extraction stalled</p>
          <p className="mt-1 text-amber-800">
            No progress for 4+ minutes — auto-resume will re-queue from checkpoint (~
            {job.files_extracted?.toLocaleString() ?? 0} files saved). You can also click{" "}
            <strong>Resume</strong>.
          </p>
        </Card>
      )}

      {job.status === "interrupted" && job.error && (
        <Card className="mb-4 border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
          <p className="font-semibold">Action required</p>
          <p className="mt-1 text-amber-800">{job.error}</p>
        </Card>
      )}

      <PageHeader

        title={job.id}

        titleClassName="font-mono text-base font-semibold tracking-normal text-brand-600"

        subtitle={`${job.domain_pack} · ${job.type}`}

        actions={

          <div className="flex flex-wrap gap-2">

            <Link to={`/forensic/jobs/${job.id}/artifacts`}>

              <Button variant="outline">

                <ListChecks className="h-4 w-4" /> Artifacts

              </Button>

            </Link>

            {["classified", "report_ready", "report_generating", "completed"].includes(job.status) && (
              <>
                <Button
                  variant="outline"
                  onClick={() => forensicApi.downloadEvidenceLog(job.id, "csv").catch(() => {})}
                >
                  <Download className="h-4 w-4" /> Evidence log
                </Button>
              </>
            )}

            {jobId && <JobInventoryButton jobId={jobId} />}

            {canRun && (
              <>
                {canStop && (
                  <Button variant="danger" loading={stopping} onClick={() => void runStop()}>
                    <Square className="h-4 w-4" /> Stop
                  </Button>
                )}

                {job.stop_requested && isExtracting && (
                  <Button variant="outline" disabled>
                    Stopping…
                  </Button>
                )}

                {showProcess && (
                  <Button variant="brand" loading={processing} onClick={() => runProcess(false)}>
                    <Play className="h-4 w-4" /> Process
                  </Button>
                )}

                {showResume && (
                  <Button variant="outline" loading={processing} onClick={() => runProcess(true)}>
                    <RefreshCw className="h-4 w-4" /> Resume
                  </Button>
                )}

                <Button variant="danger" loading={deleting} onClick={() => void hardDeleteJob()}>
                  <Trash2 className="h-4 w-4" /> Delete job
                </Button>
              </>
            )}

          </div>

        }

      />



      <div className="mb-6 grid gap-4 sm:grid-cols-4">

        <Card className="p-4">

          <p className="text-xs font-semibold uppercase tracking-wider text-ink-400">Status</p>

          <Badge tone={STATUS_TONE[job.status] ?? "neutral"}>

            {job.status}

          </Badge>

        </Card>

        <Card className="p-4">

          <p className="text-xs font-semibold uppercase tracking-wider text-ink-400">Progress</p>

          <p className="mt-2 text-2xl font-bold text-ink-900">{displayProgressPct}%</p>
          {pathProgressLabel ? (
            <p className="mt-1 text-xs font-semibold tabular-nums text-brand-700">{pathProgressLabel}</p>
          ) : enrichSubProgress ? (
            <p className="mt-1 text-xs text-ink-500">{enrichSubProgress}</p>
          ) : null}

        </Card>

        <Card className="p-4">

          <p className="text-xs font-semibold uppercase tracking-wider text-ink-400">Created</p>

          <p className="mt-2 text-sm text-ink-700">{new Date(job.created_at).toLocaleString()}</p>

        </Card>

        <Card className="p-4">

          <p className="text-xs font-semibold uppercase tracking-wider text-ink-400">Case</p>

          {job.case_id ? (

            <Link

              to={`/forensic/cases/${job.case_id}`}

              className="mt-2 inline-flex items-center gap-1 text-sm font-semibold text-brand-600 hover:underline"

            >

              View case <ArrowRight className="h-3.5 w-3.5" />

            </Link>

          ) : (

            <p className="mt-2 text-sm text-ink-400">—</p>

          )}

        </Card>

      </div>



      {job.extracted_disk_uri && job.status === "disk_ready" && (
        <Card className="mb-6 border-emerald-200 bg-emerald-50 p-4">
          <p className="text-sm font-semibold text-emerald-800">Extracted disk (MinIO)</p>
          <p className="mt-1 break-all text-sm text-emerald-700">{job.extracted_disk_uri}</p>
          <p className="mt-2 text-xs text-emerald-600">
            {job.files_extracted ?? 0} of {job.files_total ?? 0} files materialized — raw E01 segments were not copied.
          </p>
        </Card>
      )}

      {job.error && job.status === "failed" && (

        <Card className="mb-6 border-red-200 bg-red-50 p-4">

          <p className="text-sm font-semibold text-red-700">Error</p>

          <p className="mt-1 text-sm text-red-600">{job.error}</p>

        </Card>

      )}



      {showTopProgressBanner ? (
      <JobProgressBanner
        job={pipelineDisplayJob ?? job}
        enrichSubProgress={enrichSubProgress}
        latestLog={latestLogMessage}
        registering={registerProgress.active}
        registerPct={registerProgress.pct}
        registerFileName={registerProgress.fileName}
        uploading={evidenceTransferMode === "client" && (uploadSession.uploading || uploadSession.isRunning)}
        uploadProgress={evidenceTransferMode === "client" ? uploadSession.progress : null}
        processRequested={processRequested}
        pollStopped={pollStopped}
        pathProgress={pathProgressLabel}
        canStop={canStop}
        stopping={stopping}
        stopRequested={Boolean(job.stop_requested)}
        onStop={canStop ? () => void runStop() : undefined}
      />
      ) : null}

      <PipelineStepModal
        open={pipelineSteps.ctx.open}
        step={pipelineSteps.currentStep}
        steps={pipelineSteps.steps}
        stepIndex={pipelineSteps.ctx.stepIndex}
        status={pipelineSteps.ctx.status}
        detail={pipelineSteps.ctx.detail}
        completedStepIndexes={pipelineSteps.ctx.completedStepIndexes}
        elapsedLabel={pipelineSteps.elapsedLabel}
        onRetry={handlePipelineStepRetry}
        onCancel={
          pipelineSteps.ctx.status === "running" && pipelineSteps.ctx.stepIndex <= 1
            ? handlePipelineStepCancel
            : undefined
        }
      />

      {canRegisterEvidence ? (
        <div className="mb-6" ref={uploadPanelRef}>
          <Card className="flex flex-col p-5">
            <div className="mb-4 flex items-center gap-2">
              <Upload className="h-4 w-4 text-brand-600" />
              <h3 className="text-sm font-bold text-ink-800">
                {isMobileJob ? "Select mobile evidence directory" : "Select evidence directory"}
              </h3>
            </div>
            <HostEvidencePanel
              ref={evidencePanelRef}
              jobId={job.id}
              embedded
              autoProcess
              highlightStart={needsFolderPick}
              disabled={!canRegisterEvidence}
              lockedSourceType={isMobileJob ? "mobile" : undefined}
              initialSourceType={isMobileJob ? "mobile" : undefined}
              initialEvidencePath={
                locationState.prefillEvidencePath
                || (typeof job.disk_source?.evidence_folder === "string" ? job.disk_source.evidence_folder : "")
                || (typeof job.disk_source?.last_host_path === "string" ? job.disk_source.last_host_path : "")
              }
              recommendedLetters={recommendedDriveLetters}
              capabilityLabel={capabilityLabel}
              mobileOsLabel={mobileOsLabel}
              onSourceModeChange={(mode) => {
                setEvidenceTransferMode(mode);
                setSelectedTransportMode(mode);
              }}
              onSourceTransportChanged={(mode) => {
                setEvidenceTransferMode(mode);
                setSelectedTransportMode(mode);
              }}
              onEvidenceOriginChange={(mode) => {
                setEvidenceTransferMode(mode);
                setSelectedTransportMode(mode);
              }}
              onRegistered={() => load({ silent: true })}
              onProcessingStarted={async () => {
                setPipelineError(null);
                setPipelineErrorStep(undefined);
                pipelineSteps.clearRegisterError();
                setProcessRequested(true);
                lastLogTsRef.current = undefined;
                setJob((prev) =>
                  prev ? { ...prev, status: "processing", progress_pct: Math.max(prev.progress_pct, 1) } : prev
                );
                await load({ silent: true });
              }}
              onRegisterProgress={(state) =>
                setRegisterProgress({
                  active: state.active,
                  pct: state.pct,
                  fileName: state.fileName,
                  phase: state.phase ?? (state.active ? "registering" : "idle"),
                })
              }
              onReceivingSegmentsStarted={() => {
                setReceivingSegmentsStarted(false);
                window.requestAnimationFrame(() => setReceivingSegmentsStarted(true));
              }}
              onRegisterError={(msg) => {
                setReceivingSegmentsStarted(false);
                pipelineSteps.setRegisterError(msg);
              }}
              onProcessingError={(message) => {
                // Let the tracker derive the visible product-specific stage. Fixed numeric
                // indexes used to point Disk errors at the Android Agent card.
                setPipelineErrorStep(undefined);
                setPipelineError(message);
              }}
            />
          </Card>
        </div>
      ) : null}

      <div className="flex min-w-0 flex-col gap-6">
        <div className="min-w-0">
          <AgentPipelineBanner
            job={pipelineDisplayJob ?? job}
            processRequested={processRequested}
            latestLog={latestLogMessage}
            pathProgress={pathProgressLabel}
            pollStopped={pollStopped}
            pipelineElapsedLabel={pipelineSteps.finalElapsedLabel}
            liveElapsedLabel={pipelineSteps.liveElapsedLabel}
            stepDurations={pipelineSteps.stepDurations}
            onRefreshArtifacts={() => void refreshArtifacts()}
            refreshingArtifacts={refreshingArtifacts}
            compact
          />
        </div>

        <div className="flex min-w-0 flex-col gap-4">
          {jobId ? (
            <JobActivityPanel
              jobId={jobId}
              uploadLines={uploadSession.lines}
              uploadProgress={uploadSession.progress}
              uploading={clientTransferActive && (uploadSession.uploading || uploadSession.isRunning)}
              showUploadActivity={evidenceTransferMode === "client"}
              showClientTransfer={clientTransferActive}
              sourceTransport={evidenceTransportMode}
              extractionLogs={logs}
              extractionLogsLoading={logsLoading || registerProgress.active}
              registering={registerProgress.active}
              onRefreshLogs={() => load({ silent: true })}
              panelHeight={520}
            />
          ) : null}
          {jobId ? <ProgressAgentPanel jobId={jobId} active={!pollStopped} /> : null}
        </div>
      </div>

      {jobId ? (
        <div className="mt-6 min-w-0">
          <RagQaPanel
            jobId={jobId}
            jobStatus={job.status}
            enrichment={job.enrichment}
            onActivity={() => void load({ silent: true })}
          />
        </div>
      ) : null}

    </div>

  );

}
