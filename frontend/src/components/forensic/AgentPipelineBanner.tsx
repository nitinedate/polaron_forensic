import { useMemo } from "react";
import { SerialPipelineBanner } from "./SerialPipelineBanner";

import clsx from "clsx";

import { Bot, CheckCircle2, RefreshCw, XCircle } from "lucide-react";

import { Button } from "../ui";

import type { Job } from "../../lib/types/forensic";
import {
  enrichmentBannerMessage,
  enrichmentBannerTitle,
  enrichmentOverallLabel,
  isBackgroundEnriching,
} from "../../lib/enrichmentStatus";
import { getPipelineStages, isJobStale } from "../../lib/pipelineStages";
import {
  computeOverallPipelinePct,
  currentAgentDisplay,
  currentAgentLabel,
  extractStillRunning,
  isPipelineFullyComplete,
} from "../../lib/orchestrationStages";
import { sanitizePipelineLabel, stripAxiomBranding } from "../../lib/displayText";

function formatBytes(value: number | null | undefined): string {
  const n = Math.max(Number(value || 0), 0);
  if (n < 1024) return `${Math.round(n)} B`;
  const units = ["KB", "MB", "GB", "TB"];
  let scaled = n;
  let idx = -1;
  do {
    scaled /= 1024;
    idx += 1;
  } while (scaled >= 1024 && idx < units.length - 1);
  return `${scaled >= 100 ? scaled.toFixed(0) : scaled >= 10 ? scaled.toFixed(1) : scaled.toFixed(2)} ${units[idx]}`;
}

const PIPELINE_POLL_STATUSES = new Set([
  "processing",
  "building_disk",
  "disk_ready",
  "extracting",
  "extracted",
  "indexing",
  "indexed",
  "ready",
]);

interface AgentPipelineBannerProps {
  job: Job;
  processRequested?: boolean;
  latestLog?: string | null;
  pathProgress?: string | null;
  pollStopped?: boolean;
  /** Final total when complete (legacy). */
  pipelineElapsedLabel?: string | null;
  /** Live total elapsed after segment selection. */
  liveElapsedLabel?: string | null;
  /** Per-step durations keyed by stage id. */
  stepDurations?: Record<string, { ms: number; label: string; running?: boolean }>;
  onRefreshArtifacts?: () => void;
  refreshingArtifacts?: boolean;
  /** When true, omit outer margin (embedded in the job layout). */
  compact?: boolean;
}

export function AgentPipelineBanner({
  job,
  processRequested: _processRequested = false,
  latestLog,
  pathProgress,
  pollStopped = false,
  pipelineElapsedLabel = null,
  liveElapsedLabel = null,
  stepDurations = {},
  onRefreshArtifacts,
  refreshingArtifacts = false,
  compact = false,
}: AgentPipelineBannerProps) {
  const stages = useMemo(() => getPipelineStages(job), [job]);
  const stageOverallPct = computeOverallPipelinePct(job, stages);
  const activeAgent = currentAgentLabel(job);
  const agentDisplay = currentAgentDisplay(job);
  const enriching = isBackgroundEnriching(job);
  const enrichLabel = enrichmentOverallLabel(job);
  const requiredOpen = stages.some(
    (s) => s.id !== "embed_agent" && s.state !== "done" && s.state !== "failed"
  );
  const remainingStages = stages.filter(
    (s) => s.id !== "embed_agent" && s.state !== "done" && s.state !== "failed"
  ).length;
  const pending = job.enrichment?.artifacts_pending ?? 0;
  const pp = job.pipeline_progress;
  const extracting = extractStillRunning(job);
  const filesTotal = job.files_total ?? 0;
  const filesDone = job.files_extracted ?? 0;
  const filesRemaining = Math.max(filesTotal - filesDone, 0);
  const extractActivity = pp?.extraction_activity;
  const filesFound = extractActivity?.files_found ?? 0;
  const bytesRemaining = extractActivity?.bytes_remaining ?? null;
  const bytesTotal = extractActivity?.bytes_total ?? null;
  const pipelineComplete =
    !requiredOpen && isPipelineFullyComplete(job) && pending === 0 && !enriching;
  const active =
    (PIPELINE_POLL_STATUSES.has(job.status) ||
      (pp?.phase === "artifact_inventory" && !pipelineComplete) ||
      (!pipelineComplete && job.status === "indexed")) &&
    !pipelineComplete;
  const stale = isJobStale(job.updated_at, active && !pollStopped) && job.worker_liveness?.alive !== true;
  // Overall is the extract file ratio while copying, then the backend high-water
  // overall. Never an equal average of 15 cards (that made 91% extract look like 35%).
  const pct = pipelineComplete ? 100 : Math.min(99, Math.max(0, stageOverallPct));

  if (pp?.serial_pipeline) return <SerialPipelineBanner
    pipeline={pp.serial_pipeline} paused={pollStopped || job.status === "paused"}
    compact={compact} elapsed={liveElapsedLabel || pipelineElapsedLabel}
  />;

  return (
    <div
      className={clsx(
        "rounded-xl border border-slate-200 bg-white p-4",
        !compact && "mb-4"
      )}
    >
      <div className="mb-3 flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-sm font-medium text-ink-900">
          <Bot className="h-4 w-4 text-amber-600" />
          Processing pipeline
          {active && !pollStopped ? (
            <span className="inline-flex items-center gap-1 rounded-full bg-amber-100 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-amber-900">
              <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-amber-500" />
              Live
            </span>
          ) : pollStopped ? (
            <span className="rounded-full bg-amber-100 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-amber-800">
              Paused
            </span>
          ) : null}
        </div>
        <div className="flex items-center gap-2">
          {onRefreshArtifacts ? (
            <Button
              type="button"
              variant="outline"
              loading={refreshingArtifacts}
              onClick={onRefreshArtifacts}
              className="h-7 border-slate-200 bg-white px-2 text-[11px] text-ink-700 hover:bg-slate-50"
            >
              <RefreshCw className="h-3 w-3" />
              Refresh artifacts
            </Button>
          ) : null}
          <span className="text-xs tabular-nums text-ink-600">
            {!pipelineComplete && pathProgress ? `${pathProgress} · ` : ""}
            {!pipelineComplete && activeAgent ? `Agent: ${stripAxiomBranding(activeAgent)} · ` : ""}
            {!pipelineComplete && enriching && enrichLabel ? `${enrichLabel} · ` : ""}
            {pct}%{pipelineComplete ? " complete" : ""}
            {!pipelineComplete
              ? ` · ${extracting ? "extracting" : enriching ? "enriching" : job.status.replace(/_/g, " ")}`
              : ""}
            {!pipelineComplete && liveElapsedLabel ? ` · ${liveElapsedLabel} elapsed` : ""}
            {pipelineComplete && (pipelineElapsedLabel || liveElapsedLabel)
              ? ` · ${pipelineElapsedLabel || liveElapsedLabel} total`
              : ""}
          </span>
        </div>
      </div>

      <div className="mb-3">
        <div className="mb-1 flex items-center justify-between text-[11px] font-medium text-ink-800">
          <span>{extracting ? "Extraction progress" : "Overall pipeline"}</span>
          <span className="tabular-nums">
            {pct}%
            {(liveElapsedLabel || pipelineElapsedLabel) && (
              <span className="ml-2 font-normal text-ink-500">
                · {liveElapsedLabel || pipelineElapsedLabel}
                {pipelineComplete ? " total" : " elapsed"}
              </span>
            )}
          </span>
        </div>
        <div className="h-2.5 overflow-hidden rounded-full bg-slate-200">
          <div
            className={clsx(
              "h-2.5 rounded-full transition-all duration-500",
              pipelineComplete || pct >= 100 ? "bg-emerald-500" : "bg-amber-400"
            )}
            style={{ width: `${Math.min(100, Math.max(0, pct))}%` }}
          />
        </div>
      </div>

      {!pipelineComplete ? (
        <div
          className={clsx(
            "mb-3 rounded-lg border px-3 py-2.5",
            extracting ? "border-amber-200 bg-amber-50/80" : "border-sky-200 bg-sky-50/70",
          )}
        >
          <div className="flex flex-wrap items-start justify-between gap-2">
            <div>
              <p className="text-xs font-semibold text-ink-900">
                {extracting ? "Phase 1 · One-time evidence extraction" : "Phase 2 · Post-extraction processing"}
              </p>
              <p className="mt-1 text-[11px] leading-snug text-ink-700">
                {extracting
                  ? extractActivity?.subphase === "enumerating"
                    ? filesFound > 0
                      ? `Enumerating filesystem: ${filesFound.toLocaleString()} files discovered so far. The final denominator is not known yet.`
                      : "Enumerating the complete filesystem. The final file count is not known yet."
                    : extractActivity?.subphase === "finalizing"
                      ? `All ${filesDone.toLocaleString()} files are extracted. Finalizing the immutable evidence manifest before Phase 2 starts.`
                      : filesTotal > 0
                        ? `Extracting ${filesDone.toLocaleString()} / ${filesTotal.toLocaleString()} files; ${filesRemaining.toLocaleString()} remaining.`
                        : extractActivity?.label || "Preparing the single extraction plan."
                  : agentDisplay
                    ? `${agentDisplay.mode === "running" ? "Current" : "Next"}: ${sanitizePipelineLabel(agentDisplay.label)} · ${remainingStages.toLocaleString()} required stage${remainingStages === 1 ? "" : "s"} remaining`
                    : `Extraction is complete; ${remainingStages.toLocaleString()} required stage${remainingStages === 1 ? "" : "s"} remaining.`}
              </p>
            </div>
            {extracting && filesTotal > 0 ? (
              <div className="text-right text-[11px] font-semibold tabular-nums text-amber-900">
                <div>{filesRemaining.toLocaleString()} files left</div>
                {typeof job.bytes_extracted === "number" && job.bytes_extracted > 0 ? (
                  <div className="mt-0.5 font-normal text-ink-600">
                    {formatBytes(job.bytes_extracted)} extracted
                    {bytesTotal && bytesTotal > 0 ? ` / ${formatBytes(bytesTotal)}` : ""}
                  </div>
                ) : null}
                {bytesRemaining != null && bytesRemaining > 0 ? (
                  <div className="mt-0.5 font-normal text-ink-600">
                    {formatBytes(bytesRemaining)} remaining by size
                  </div>
                ) : null}
              </div>
            ) : null}
          </div>
          {extracting ? (
            <p className="mt-2 text-[11px] font-medium text-amber-900">
              Artifact registration, OCR, parsing, RAG, entity extraction and artifact inventory are locked until extraction reaches 100% and the extracted-image manifest is finalized.
            </p>
          ) : (
            <p className="mt-2 text-[11px] text-sky-900">
              Evidence is read from the extracted image; the source image is not re-extracted for each downstream agent.
            </p>
          )}
        </div>
      ) : null}

      {agentDisplay ? (
        <p className="mb-3 text-xs font-semibold text-ink-800">
          {agentDisplay.mode === "running" ? "Running" : "Next"}: {sanitizePipelineLabel(agentDisplay.label)}
        </p>
      ) : null}

      {enriching && enrichmentBannerTitle(job) ? (
        <div className="mb-3 rounded-lg border border-emerald-200 bg-emerald-50/90 px-3 py-2.5">
          <p className="text-xs font-semibold text-emerald-900">{enrichmentBannerTitle(job)}</p>
          <p className="mt-1 text-[11px] leading-snug text-emerald-800">{enrichmentBannerMessage(job)}</p>
        </div>
      ) : null}

      <ul className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {stages.map((stage) => {
          const done = stage.state === "done";
          const running = stage.state === "running" && !done;
          const failed = stage.state === "failed";
          const displayPct = done ? 100 : Math.min(100, Math.max(0, stage.pct));

          return (
            <li
              key={stage.id}
              className={clsx(
                "flex min-w-0 items-start justify-between gap-3 rounded-lg border border-slate-100 px-3 py-3 text-sm",
                done && "bg-emerald-50/70",
                running && "bg-amber-50/80",
                failed && "bg-red-50/80"
              )}
            >
              <div className="flex min-w-0 items-start gap-2">
                {done ? (
                  <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-600" aria-label="Complete" />
                ) : failed ? (
                  <XCircle className="h-4 w-4 shrink-0 text-red-600" aria-label="Failed" />
                ) : (
                  <span
                    className={clsx(
                      "h-4 w-4 shrink-0 rounded-full border-2",
                      running ? "border-amber-500" : "border-slate-300"
                    )}
                    aria-hidden
                  />
                )}
                <div className="min-w-0">
                  <div
                    className={clsx(
                      "break-words font-medium",
                      done ? "text-emerald-900" : failed ? "text-red-800" : "text-ink-800"
                    )}
                  >
                    {sanitizePipelineLabel(stage.label)}
                  </div>
                  {stage.detail ? (
                    <div className="mt-0.5 line-clamp-2 text-[10px] font-normal leading-snug text-ink-500">
                      {stripAxiomBranding(stage.detail)}
                    </div>
                  ) : null}
                </div>
              </div>
              <span
                className={clsx(
                  "shrink-0 text-right text-xs font-bold tabular-nums",
                  done ? "text-emerald-700" : failed ? "text-red-700" : running ? "text-amber-800" : "text-ink-500"
                )}
              >
                {failed ? (
                  "—"
                ) : (
                  <>
                    <span>{displayPct}%</span>
                    {stepDurations[stage.id]?.label ? (
                      <span
                        className={clsx(
                          "ml-2 font-semibold",
                          running ? "text-amber-700" : done ? "text-emerald-600" : "text-ink-400"
                        )}
                        title={
                          running
                            ? `Time on this step so far: ${stepDurations[stage.id].label}`
                            : `Time required for this step: ${stepDurations[stage.id].label}`
                        }
                      >
                        {stepDurations[stage.id].label}
                      </span>
                    ) : null}
                  </>
                )}
              </span>
            </li>
          );
        })}
      </ul>

      {active && !pollStopped ? (
        <div className="mt-3 space-y-1 text-[11px] text-ink-600">
          <p>
            {extracting
              ? "Extraction barrier is active: only evidence extraction may advance. Downstream agents remain waiting."
              : "Post-extraction agents are coordinated from the extracted evidence set; progress below shows the current work and the remaining stages."}
          </p>

        </div>
      ) : null}

      {stale && (
        <p className="mt-2 text-[11px] font-medium text-amber-800">
          No useful update in 1+ minute — progressAgent will inspect the active stage
          {pp?.phase === "artifact_inventory" ||
          stages.some((s) => s.id === "artifact_inventory" && s.state === "running")
            ? " (artifact inventory runs on the disk worker — not the GPU)."
            : " (OCR and visual review use the GPU; RAG uses text retrieval)."}
        </p>
      )}

      {pipelineComplete && (
        <p className="mt-2 text-[11px] text-emerald-800">
          Pipeline finished. Complete case intake before generating a report.
        </p>
      )}

      {pending > 0 && !enriching && (
        <p className="mt-2 text-[11px] font-medium text-ink-700">
          Batch processing — {(job.extract_coverage?.extracted ?? 0).toLocaleString()} /{" "}
          {(job.extract_coverage?.interesting_total ?? 0).toLocaleString()} paths indexed ({pct}%). Auto-continuing…
        </p>
      )}

      {enriching && (
        <p className="mt-2 text-[11px] text-ink-600">
          Post-extraction enrichment is running from the extracted evidence set; the original image is not being read again.
        </p>
      )}

      {!pipelineComplete && latestLog ? (
        <p className="mt-2 truncate text-[11px] text-ink-500">
          Latest: {stripAxiomBranding(latestLog)}
        </p>
      ) : null}
    </div>
  );
}
