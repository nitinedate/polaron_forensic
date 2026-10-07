import { CheckCircle2, Circle, Loader2, XCircle } from "lucide-react";
import type { PipelineProgress } from "../../lib/types/forensic";

type SerialPipeline = NonNullable<PipelineProgress["serial_pipeline"]>;

export function SerialPipelineBanner({ pipeline, paused, compact, elapsed }: {
  pipeline: SerialPipeline; paused: boolean; compact: boolean; elapsed?: string | null;
}) {
  const active = pipeline.stages.find((stage) => stage.id === pipeline.current_stage);
  const exceptionSkips = (stage: SerialPipeline["stages"][number]) => {
    const policy = Number(stage.details?.policy_skipped || 0);
    return Math.max(0, stage.skipped - policy);
  };
  const exceptions = pipeline.stages.filter((stage) => stage.failed > 0 || exceptionSkips(stage) > 0 || stage.status === "skipped"
    || stage.error || Number(stage.details?.errors || 0) > 0 || stage.details?.coverage_complete === false);
  const exceptionText = (stage: SerialPipeline["stages"][number]) => stage.error
    || (stage.failed > 0 ? `${stage.failed.toLocaleString()} failed work units`
      : exceptionSkips(stage) > 0 ? `${exceptionSkips(stage).toLocaleString()} skipped · ${stage.details?.skip_reason || "recorded evidence exceptions"}`
        : stage.status === "skipped" ? String(stage.details?.reason || "Stage explicitly skipped")
          : "Coverage exceptions recorded; review evidence counters.");
  const stateLabel = (status: string) => status === "done" ? "Completed" : status === "skipped" ? "Skipped"
    : status === "running" && !paused ? "Running" : status === "failed" ? "Failed"
      : paused && status === "running" ? "Paused" : "Waiting";
  return <div className={`rounded-xl border border-slate-200 bg-white p-4 ${compact ? "" : "mb-4"}`}>
    <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
      <p className="text-sm font-semibold text-ink-900">Forensic processing</p>
      <span className="text-xs tabular-nums text-ink-600">{pipeline.overall_pct}%{elapsed ? ` · ${elapsed}` : ""}</span>
    </div>
    <div className="mb-3 h-2 overflow-hidden rounded-full bg-slate-200">
      <div className={`h-2 transition-all ${pipeline.complete ? "bg-emerald-500" : "bg-amber-400"}`} style={{ width: `${pipeline.overall_pct}%` }} />
    </div>
    <p className="mb-3 text-xs text-ink-700">{pipeline.complete ? "Ready — completeness check finished" : paused ? "Processing paused"
      : pipeline.upgrade_required ? "Reprocess this case to apply the updated evidence stages"
      : active ? `${stateLabel(active.status)}: ${active.label}` : "Waiting for the next stage"}</p>
    <ul className="grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
      {pipeline.stages.map((stage, index) => <li key={stage.id}
        className={`min-w-0 rounded-lg border p-3 text-xs ${stage.status === "running" ? "border-amber-200 bg-amber-50"
          : stage.status === "failed" ? "border-red-200 bg-red-50"
            : stage.status === "done" || stage.status === "skipped" ? "border-emerald-100 bg-emerald-50" : "border-slate-200"}`}>
        <div className="flex items-start gap-2">
          {stage.status === "done" || stage.status === "skipped" ? <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-600" />
            : stage.status === "failed" ? <XCircle className="h-4 w-4 shrink-0 text-red-600" />
              : stage.status === "running" && !paused ? <Loader2 className="h-4 w-4 shrink-0 animate-spin text-amber-600" /> : <Circle className="h-4 w-4 shrink-0 text-slate-400" />}
          <span className="min-w-0 flex-1 break-words font-semibold text-ink-900">{index + 1}. {stage.label}</span>
          <span className="shrink-0 font-bold tabular-nums">{stage.pct}%</span>
        </div>
        <div className="mt-2 flex flex-wrap justify-between gap-2 text-ink-600">
          <span>{stateLabel(stage.status)}</span>
          {stage.total > 0 && <span className="tabular-nums">{(stage.completed + stage.failed + stage.skipped).toLocaleString()} / {stage.total.toLocaleString()} items</span>}
        </div>
      </li>)}
    </ul>
    {active?.error && <p className="mt-3 rounded bg-amber-50 p-2 text-xs text-amber-900">{active.error}</p>}
    {exceptions.length > 0 && <div className="mt-3 rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-900">
      <p className="mb-1 font-semibold">Processing exceptions</p>
      {exceptions.map((stage) => <p key={stage.id}>{stage.label}: {exceptionText(stage)}</p>)}
    </div>}
  </div>;
}
