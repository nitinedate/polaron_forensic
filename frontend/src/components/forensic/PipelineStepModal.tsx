import clsx from "clsx";
import { AlertCircle, CheckCircle2, GripVertical, Loader2, RefreshCw } from "lucide-react";

import { Button } from "../ui";
import { useDraggablePanel } from "../../hooks/useDraggablePanel";
import { stripAxiomBranding } from "../../lib/displayText";
import {
  PIPELINE_STEP_DEFS,
  type PipelineStepDef,
  type PipelineStepStatus,
} from "../../lib/pipelineStepModal";

interface PipelineStepModalProps {
  open: boolean;
  step: PipelineStepDef;
  steps?: PipelineStepDef[];
  stepIndex: number;
  status: PipelineStepStatus;
  detail: string | null;
  completedStepIndexes: number[];
  elapsedLabel: string;
  onRetry?: () => void;
  /** Clear a stuck "Receiving segments" spinner without waiting for the request. */
  onCancel?: () => void;
}

export function PipelineStepModal({
  open,
  step,
  steps,
  stepIndex,
  status,
  detail,
  completedStepIndexes,
  elapsedLabel,
  onRetry,
  onCancel,
}: PipelineStepModalProps) {
  const { panelStyle, dragHandleProps } = useDraggablePanel(open);
  const visibleSteps = steps?.length ? steps : PIPELINE_STEP_DEFS;

  if (!open) return null;

  const message =
    status === "error"
      ? detail?.trim() || step.errorMessage
      : status === "done"
        ? step.doneMessage
        : step.runningMessage;

  return (
    <div className="fixed inset-0 z-50 pointer-events-none">
      <div
        className="pointer-events-auto absolute left-1/2 top-1/2 w-full max-w-lg rounded-2xl border border-ink-200 bg-white shadow-soft"
        style={panelStyle}
        role="dialog"
        aria-modal="true"
        aria-labelledby="pipeline-step-title"
      >
        <div
          {...dragHandleProps}
          className={clsx("border-b border-ink-100 px-6 py-4", dragHandleProps.className)}
        >
          <div className="flex items-center justify-between gap-3">
            <div className="flex min-w-0 items-center gap-2">
              <GripVertical className="h-4 w-4 shrink-0 text-ink-300" aria-hidden />
              <h3 id="pipeline-step-title" className="text-lg font-bold text-ink-900">
                {step.title}
              </h3>
            </div>
            <span className="rounded-full bg-indigo-50 px-3 py-1 text-xs font-semibold tabular-nums text-indigo-700">
              {elapsedLabel}
            </span>
          </div>
          <p className="mt-1 text-xs text-ink-500">
            Step {stepIndex + 1} of {Math.max(1, visibleSteps.length - 1)} · Elapsed time
          </p>
        </div>

        <div className="px-6 py-5">
          <div
            className={clsx(
              "mb-4 flex items-start gap-3 rounded-xl border px-4 py-3",
              status === "error" && "border-red-200 bg-red-50",
              status === "running" && "border-indigo-200 bg-indigo-50/80",
              status === "done" && "border-emerald-200 bg-emerald-50"
            )}
          >
            {status === "error" ? (
              <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-red-600" />
            ) : status === "done" ? (
              <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0 text-emerald-600" />
            ) : (
              <Loader2 className="mt-0.5 h-5 w-5 shrink-0 animate-spin text-indigo-600" />
            )}
            <div className="min-w-0">
              <p
                className={clsx(
                  "text-sm font-semibold",
                  status === "error" ? "text-red-900" : status === "done" ? "text-emerald-900" : "text-indigo-900"
                )}
              >
                {message}
              </p>
              {detail && status === "running" ? (
                <p className="mt-1 truncate text-xs text-ink-600">{stripAxiomBranding(detail)}</p>
              ) : null}
            </div>
          </div>

          <ol className="max-h-52 space-y-2 overflow-y-auto text-xs">
            {visibleSteps.slice(0, -1).map((def, index) => {
              const done = completedStepIndexes.includes(index);
              const current = index === stepIndex && status === "running";
              const failed = index === stepIndex && status === "error";
              return (
                <li
                  key={def.id}
                  className={clsx(
                    "flex items-center gap-2 rounded-lg px-2 py-1.5",
                    current && "bg-indigo-50 font-semibold text-indigo-900",
                    done && !current && "text-emerald-800",
                    failed && "bg-red-50 text-red-900",
                    !done && !current && !failed && "text-ink-400"
                  )}
                >
                  {done ? (
                    <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-emerald-600" />
                  ) : current ? (
                    <Loader2 className="h-3.5 w-3.5 shrink-0 animate-spin text-indigo-600" />
                  ) : failed ? (
                    <AlertCircle className="h-3.5 w-3.5 shrink-0 text-red-600" />
                  ) : (
                    <span className="inline-block h-3.5 w-3.5 shrink-0 rounded-full border border-ink-200" />
                  )}
                  <span>{def.title}</span>
                </li>
              );
            })}
          </ol>
        </div>

        {status === "error" || (status === "running" && onCancel) ? (
          <div className="flex justify-end gap-2 border-t border-ink-100 px-6 py-4">
            {status === "running" && onCancel ? (
              <Button variant="ghost" onClick={onCancel}>
                Cancel
              </Button>
            ) : null}
            {status === "error" && onRetry ? (
              <Button variant="brand" onClick={onRetry}>
                <RefreshCw className="h-4 w-4" /> Try again
              </Button>
            ) : null}
          </div>
        ) : null}
      </div>
    </div>
  );
}
