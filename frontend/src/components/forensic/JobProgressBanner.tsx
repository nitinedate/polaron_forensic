import clsx from "clsx";
import { Loader2, Square } from "lucide-react";

import { Button } from "../ui";
import { getJobProgressView } from "../../lib/jobProgress";
import type { Job, UploadProgressState } from "../../lib/types/forensic";

const PIPELINE_ACTIVE = new Set([
  "processing",
  "building_disk",
  "disk_ready",
  "artifacts_registered",
  "parsed",
  "extracting",
  "extracted",
  "indexing",
]);

interface JobProgressBannerProps {
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
  onStop?: () => void;
  stopping?: boolean;
  stopRequested?: boolean;
  canStop?: boolean;
}

export function JobProgressBanner({
  job,
  enrichSubProgress,
  latestLog,
  registering,
  registerPct,
  registerFileName,
  uploading,
  uploadProgress,
  processRequested,
  pollStopped,
  pathProgress,
  onStop,
  stopping,
  stopRequested,
  canStop,
}: JobProgressBannerProps) {
  const view = getJobProgressView({
    job,
    enrichSubProgress,
    latestLog,
    registering,
    registerPct,
    registerFileName,
    uploading,
    uploadProgress,
    processRequested,
    pollStopped,
    pathProgress,
  });

  if (!view.show) return null;

  const showPct = !view.indeterminate;
  const border =
    view.variant === "error"
      ? "border-red-200 bg-red-50/80"
      : view.variant === "warning"
        ? "border-amber-200 bg-amber-50/80"
        : "border-brand-200 bg-brand-50/70";

  return (
    <div className={clsx("mb-4 rounded-xl border p-4 shadow-sm", border)}>
      <div className="mb-2 flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <p className="text-sm font-semibold text-ink-900">{view.title}</p>
          <p className="mt-1 text-sm leading-snug text-ink-700">{view.message}</p>
          {view.pathProgress && view.message !== view.pathProgress ? (
            <p className="mt-1.5 text-sm font-semibold tabular-nums text-brand-800">{view.pathProgress}</p>
          ) : null}
          {view.hint ? (
            <p
              className={clsx(
                "mt-2 text-xs leading-snug",
                view.variant === "error" ? "text-red-700" : "text-amber-800"
              )}
            >
              {view.hint}
            </p>
          ) : null}
        </div>
        <div className="flex shrink-0 flex-col items-end gap-2 text-right">
          {canStop && onStop ? (
            <Button variant="danger" loading={stopping} onClick={onStop}>
              <Square className="h-4 w-4" /> Stop
            </Button>
          ) : stopRequested ? (
            <span className="rounded-lg border border-amber-300 bg-amber-100 px-3 py-2 text-xs font-semibold text-amber-900">
              Stopping…
            </span>
          ) : null}
          {view.pathProgress && job.status === "indexing" ? (
            <p className="max-w-[12rem] text-sm font-bold leading-tight tabular-nums text-brand-800">
              {view.pathProgress}
            </p>
          ) : view.pathProgress ? (
            <p className="max-w-[12rem] text-xs tabular-nums text-brand-700">{view.pathProgress}</p>
          ) : null}
          {view.indeterminate ? (
            <Loader2 className="h-5 w-5 animate-spin text-brand-600" aria-hidden />
          ) : (
            <p className="text-2xl font-bold tabular-nums text-brand-700">{view.pct}%</p>
          )}
          <p className="max-w-[7rem] text-[10px] font-semibold uppercase tracking-wider text-ink-400">
            {view.statusLabel}
          </p>
        </div>
      </div>

      <div className="h-2.5 overflow-hidden rounded-full bg-brand-100">
        {view.indeterminate ? (
          <div className="h-full w-1/3 animate-pulse rounded-full bg-brand-500" />
        ) : (
          <div
            className="h-full rounded-full bg-brand-500 transition-all duration-500 ease-out"
            style={{ width: `${Math.min(100, Math.max(0, view.pct))}%` }}
          />
        )}
      </div>

      {showPct && view.pct > 0 && view.pct < 100 && PIPELINE_ACTIVE.has(job.status) ? (
        <p className="mt-1.5 text-xs text-ink-500">
          {(job.files_total ?? 0) > 0
            ? `Extraction: ${(job.files_extracted ?? 0).toLocaleString()} / ${job.files_total!.toLocaleString()} files`
            : view.pct < 10
              ? "Virtual disk stage — mounting segments"
              : view.pct < 35
                ? "Virtual disk & mount"
                : view.pct < 60
                  ? "Disk scan"
                  : view.pct < 85
                    ? "Artifact extraction"
                    : view.pct < 98
                      ? "RAG index & enrichment"
                      : "Finishing up"}
        </p>
      ) : null}
    </div>
  );
}
