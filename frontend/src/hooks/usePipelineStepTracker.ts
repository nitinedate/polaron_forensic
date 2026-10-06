import { useEffect, useMemo, useRef, useState } from "react";

import {
  derivePipelineStepContext,
  formatElapsed,
  PIPELINE_STEP_DEFS,
  pipelineStepDefsForJob,
  sanitizeRegisterError,
  type PipelineStepContext,
} from "../lib/pipelineStepModal";
import { getPipelineStages } from "../lib/pipelineStages";
import { isPipelineFullyComplete, readOrchestration } from "../lib/orchestrationStages";
import type { Job } from "../lib/types/forensic";

export type StepDurationMap = Record<string, { ms: number; label: string; running?: boolean }>;

function secToMs(sec: number | null | undefined): number | null {
  if (sec == null || Number.isNaN(sec)) return null;
  return Math.max(0, Math.floor(sec) * 1000);
}

export function usePipelineStepTracker(
  job: Job | null,
  opts: {
    registering: boolean;
    receivingSegmentsStarted: boolean;
    processRequested: boolean;
    pipelineError: string | null;
    pipelineErrorStep?: number;
    listingFolder?: boolean;
    mountingDrive?: boolean;
    uploading?: boolean;
    uploadDetail?: string | null;
  }
) {
  const [registerError, setRegisterError] = useState<string | null>(null);
  const [elapsedMs, setElapsedMs] = useState(0);
  const [liveTotalMs, setLiveTotalMs] = useState(0);
  const [finalElapsedMs, setFinalElapsedMs] = useState<number | null>(null);
  const [stepDurations, setStepDurations] = useState<StepDurationMap>({});
  const startedAtRef = useRef<number | null>(null);
  const pipelineStartedAtRef = useRef<number | null>(null);
  const stepStartedAtRef = useRef<Record<string, number>>({});
  const stepFinalMsRef = useRef<Record<string, number>>({});
  const wasOpenRef = useRef(false);
  const prevStageStateRef = useRef<Record<string, string>>({});

  const stepDefs = useMemo(() => {
    if (!job) return PIPELINE_STEP_DEFS;
    const intake = String((job.disk_source as { intake?: unknown } | null | undefined)?.intake || "");
    const includeClientDownload = Boolean(opts.uploading) || intake === "browser_upload";
    return pipelineStepDefsForJob(job, { includeClientDownload });
  }, [job, opts.uploading]);

  const ctx: PipelineStepContext = derivePipelineStepContext(job, {
    registering: opts.registering,
    receivingSegmentsStarted: opts.receivingSegmentsStarted,
    registerError,
    pipelineError: opts.pipelineError,
    pipelineErrorStep: opts.pipelineErrorStep,
    processRequested: opts.processRequested,
    listingFolder: opts.listingFolder,
    mountingDrive: opts.mountingDrive,
    uploading: opts.uploading,
    uploadDetail: opts.uploadDetail,
  });

  const stages = useMemo(() => (job ? getPipelineStages(job) : []), [job]);
  const pipelineComplete = Boolean(job && isPipelineFullyComplete(job));

  // Start wall-clock as soon as segments are selected / registration begins.
  useEffect(() => {
    const shouldRun =
      opts.receivingSegmentsStarted ||
      opts.registering ||
      opts.processRequested ||
      Boolean(
        job &&
          ![
            "created",
            "awaiting_segments",
            "failed",
            "cancelled",
          ].includes(job.status)
      );
    if (shouldRun && pipelineStartedAtRef.current == null) {
      const orch = job ? readOrchestration(job) : null;
      const serverStart = orch?.pipeline_started_at
        ? Date.parse(orch.pipeline_started_at)
        : NaN;
      pipelineStartedAtRef.current = Number.isFinite(serverStart) ? serverStart : Date.now();
      setFinalElapsedMs(null);
    }
  }, [
    opts.receivingSegmentsStarted,
    opts.registering,
    opts.processRequested,
    job?.status,
    job,
  ]);

  // Modal timer (receiving segments overlay)
  useEffect(() => {
    if (ctx.open && startedAtRef.current == null) {
      startedAtRef.current = Date.now();
      setFinalElapsedMs(null);
    }
    if (wasOpenRef.current && !ctx.open && ctx.status === "done" && startedAtRef.current != null) {
      setFinalElapsedMs(Date.now() - startedAtRef.current);
      startedAtRef.current = null;
      setElapsedMs(0);
    }
    if (!ctx.open && !wasOpenRef.current && ctx.status !== "done") {
      startedAtRef.current = null;
      setElapsedMs(0);
    }
    wasOpenRef.current = ctx.open;
  }, [ctx.open, ctx.status]);

  useEffect(() => {
    if (!ctx.open) return undefined;
    const tick = () => {
      if (startedAtRef.current != null) {
        setElapsedMs(Date.now() - startedAtRef.current);
      }
    };
    tick();
    const id = window.setInterval(tick, 1000);
    return () => window.clearInterval(id);
  }, [ctx.open]);

  // Per-step + total live timers from stage state transitions / server fields.
  useEffect(() => {
    if (!job) return undefined;

    const rangeMs = (startedAt?: string, finishedAt?: string): number | null => {
      if (!startedAt || !finishedAt) return null;
      const a = Date.parse(String(startedAt));
      const b = Date.parse(String(finishedAt));
      if (!Number.isFinite(a) || !Number.isFinite(b) || b < a) return null;
      return Math.max(0, b - a);
    };

    const tick = () => {
      const orch = readOrchestration(job);
      const next: StepDurationMap = {};
      const now = Date.now();

      for (const stage of stages) {
        const agent = orch?.agents?.[stage.id];
        const fromRange = rangeMs(agent?.started_at, agent?.finished_at);
        const serverDurMs = secToMs(
          typeof agent?.duration_sec === "number" ? agent.duration_sec : null
        );
        // Prefer non-zero server/range durations (fixes collapsed pending→done stamps).
        const bestServerMs =
          serverDurMs != null && serverDurMs > 0
            ? serverDurMs
            : fromRange != null && fromRange > 0
              ? fromRange
              : serverDurMs ?? fromRange;
        const prevState = prevStageStateRef.current[stage.id] ?? "pending";
        const state = stage.state;

        if (state === "running" && prevState !== "running") {
          const serverStart = agent?.started_at ? Date.parse(String(agent.started_at)) : NaN;
          stepStartedAtRef.current[stage.id] = Number.isFinite(serverStart)
            ? serverStart
            : now;
        }
        if ((state === "done" || state === "failed") && prevState === "running") {
          const started = stepStartedAtRef.current[stage.id] ?? now;
          stepFinalMsRef.current[stage.id] =
            bestServerMs != null && bestServerMs > 0
              ? bestServerMs
              : Math.max(0, now - started);
        }
        if ((state === "done" || state === "failed") && bestServerMs != null && bestServerMs > 0) {
          stepFinalMsRef.current[stage.id] = bestServerMs;
        }

        if (state === "running") {
          const started = stepStartedAtRef.current[stage.id] ?? now;
          const ms =
            bestServerMs != null && bestServerMs > 0
              ? bestServerMs
              : Math.max(0, now - started);
          next[stage.id] = { ms, label: formatElapsed(ms), running: true };
        } else if (state === "done" || state === "failed") {
          const ms = stepFinalMsRef.current[stage.id] ?? bestServerMs ?? 0;
          next[stage.id] = { ms, label: formatElapsed(ms), running: false };
        }

        prevStageStateRef.current[stage.id] = state;
      }

      setStepDurations(next);

      // Header elapsed = wall-clock since pipeline start (not sum of step times).
      // Steps can overlap (OCR / inventory / RAG), so summing them overstates elapsed.
      const serverStartMs = orch?.pipeline_started_at
        ? Date.parse(String(orch.pipeline_started_at))
        : NaN;
      if (Number.isFinite(serverStartMs)) {
        const prevStart = pipelineStartedAtRef.current;
        // A rewritten orchestration blob can stamp a new "start". Never jump the
        // elapsed clock forward while this page is still open.
        if (prevStart == null || serverStartMs < prevStart) {
          pipelineStartedAtRef.current = serverStartMs;
        }
      }
      const serverTotal = secToMs(
        typeof orch?.total_duration_sec === "number" ? orch.total_duration_sec : null
      );
      let total = 0;
      if (pipelineComplete) {
        const frozen =
          (serverTotal != null && serverTotal > 0
            ? serverTotal
            : pipelineStartedAtRef.current != null
              ? Math.max(0, now - pipelineStartedAtRef.current)
              : liveTotalMs) || 0;
        if (frozen > 0) {
          setLiveTotalMs(frozen);
          setFinalElapsedMs((prev) => (prev != null && prev > 0 ? prev : frozen));
        }
        return;
      }
      if (pipelineStartedAtRef.current != null) {
        total = Math.max(0, now - pipelineStartedAtRef.current);
      } else if (serverTotal != null && serverTotal > 0) {
        total = serverTotal;
      }
      if (total > 0) {
        setLiveTotalMs(total);
      }
    };

    tick();
    if (pipelineComplete) return undefined;
    const id = window.setInterval(tick, 1000);
    return () => window.clearInterval(id);
  }, [job, stages, pipelineComplete]);

  useEffect(() => {
    if (opts.registering || opts.uploading) {
      setRegisterError(null);
    }
  }, [opts.registering, opts.uploading]);

  const currentStep = stepDefs[ctx.stepIndex] ?? stepDefs[0] ?? PIPELINE_STEP_DEFS[0];
  const totalLabel =
    finalElapsedMs != null
      ? formatElapsed(finalElapsedMs)
      : liveTotalMs > 0
        ? formatElapsed(liveTotalMs)
        : null;

  return {
    ctx,
    steps: stepDefs,
    currentStep,
    elapsedLabel: formatElapsed(elapsedMs),
    /** Live total while pipeline runs; final after complete. */
    liveElapsedLabel: liveTotalMs > 0 ? formatElapsed(liveTotalMs) : null,
    finalElapsedLabel: finalElapsedMs != null ? formatElapsed(finalElapsedMs) : totalLabel,
    stepDurations,
    registerError,
    setRegisterError: (msg: string | null) => setRegisterError(sanitizeRegisterError(msg)),
    clearRegisterError: () => setRegisterError(null),
  };
}
