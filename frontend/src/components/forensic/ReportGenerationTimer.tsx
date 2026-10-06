import clsx from "clsx";
import { Clock } from "lucide-react";

import { Card } from "../ui";

function formatElapsed(ms: number): string {
  const sec = Math.floor(ms / 1000);
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export interface ReportGenerationTimerProps {
  streaming: boolean;
  elapsedMs: number;
  finalDurationMs?: number | null;
  progressPct?: number;
  stage?: string;
  pipelineStage?: string;
  primaryModel?: string;
  reviewModel?: string;
  confidenceGrade?: string;
  activityLines?: string[];
  className?: string;
}

export function ReportGenerationTimer({
  streaming,
  elapsedMs,
  finalDurationMs,
  progressPct = 0,
  stage,
  pipelineStage,
  primaryModel,
  reviewModel,
  confidenceGrade,
  activityLines = [],
  className,
}: ReportGenerationTimerProps) {
  if (!streaming && finalDurationMs == null) return null;

  if (!streaming && finalDurationMs != null) {
    return (
      <Card className={clsx("mb-6 border-green-200 bg-green-50 p-3 text-sm text-green-900", className)}>
        <div className="flex items-center gap-2">
          <Clock className="h-4 w-4" />
          Report generated in <span className="font-mono font-semibold">{formatElapsed(finalDurationMs)}</span>
        </div>
      </Card>
    );
  }

  return (
    <Card className={clsx("mb-6 border-brand-200 bg-brand-50 p-4", className)}>
      <div className="mb-2 flex items-center justify-between text-sm font-medium text-brand-900">
        <span className="flex items-center gap-2">
          <Clock className="h-4 w-4" />
          Generation timer
        </span>
        <span className="font-mono">{formatElapsed(elapsedMs)}</span>
      </div>

      {activityLines.length > 0 && (
        <div className="mb-3 max-h-40 overflow-y-auto rounded bg-ink-900/90 p-3 font-mono text-xs text-green-300">
          {activityLines.slice(-12).map((line, i) => (
            <div key={i} className="whitespace-pre-wrap leading-relaxed">
              <span className="text-ink-500">›</span> {line}
            </div>
          ))}
        </div>
      )}

      <div className="flex items-center justify-between gap-3">
        <p className="text-sm font-semibold text-brand-800">
          {stage ? `Working: ${stage}` : "Connecting to backend…"}
        </p>
        <span className="shrink-0 text-sm text-brand-600">{progressPct}%</span>
      </div>

      {(pipelineStage || primaryModel) && (
        <p className="mt-1 text-xs text-brand-700">
          {pipelineStage && pipelineStage !== "running" && (
            <>Step: {pipelineStage} · </>
          )}
          {pipelineStage === "running" && <>Generating · </>}
          {primaryModel && <>Draft: {primaryModel}</>}
          {reviewModel && <> · Review: {reviewModel}</>}
          {confidenceGrade && <> · Grade: {confidenceGrade}</>}
        </p>
      )}

      <div className="mt-2 h-2 overflow-hidden rounded-full bg-brand-100">
        <div
          className="h-2 rounded-full bg-brand-500 transition-[width] duration-700 ease-out"
          style={{ width: `${Math.min(100, Math.max(2, progressPct))}%` }}
        />
      </div>
    </Card>
  );
}

export { formatElapsed };
