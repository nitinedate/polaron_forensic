import { CheckCircle2, Circle, Loader2, XCircle } from "lucide-react";
import type { PipelineProgress } from "../../lib/types/forensic";

type SerialPipeline = NonNullable<PipelineProgress["serial_pipeline"]>;

export function SerialPipelineBanner({ pipeline, paused, compact, elapsed }: {
  pipeline: SerialPipeline; paused: boolean; compact: boolean; elapsed?: string | null;
}) {
  const active = pipeline.stages.find((stage) => stage.id === pipeline.current_stage);
  const exceptions = pipeline.stages.filter((stage) => stage.failed > 0 || stage.skipped > 0 || stage.status === "skipped"
    || stage.error || Number(stage.details?.errors || 0) > 0 || stage.details?.coverage_complete === false);
  const exceptionText = (stage: SerialPipeline["stages"][number]) => stage.error
    || (stage.failed > 0 ? `${stage.failed.toLocaleString()} failed work units`
      : stage.skipped > 0 ? `${stage.skipped.toLocaleString()} skipped · ${stage.details?.skip_reason || "recorded evidence exceptions"}`
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
    <div className="overflow-x-auto">
      <table className="w-full text-left text-xs">
        <thead><tr className="border-b text-ink-500"><th className="py-2 pr-2">Stage</th><th className="pr-2">Status</th><th className="pr-2">Progress</th><th className="text-right">Items</th></tr></thead>
        <tbody>{pipeline.stages.map((stage, index) => <tr key={stage.id} className={`border-b border-slate-100 ${stage.status === "running" ? "bg-amber-50" : ""}`}>
          <td className="py-2 pr-2"><div className="flex items-center gap-2">
            {stage.status === "done" || stage.status === "skipped" ? <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-600" />
              : stage.status === "failed" ? <XCircle className="h-4 w-4 shrink-0 text-red-600" />
                : stage.status === "running" && !paused ? <Loader2 className="h-4 w-4 shrink-0 animate-spin text-amber-600" /> : <Circle className="h-4 w-4 shrink-0 text-slate-400" />}
            <span>{index + 1}. {stage.label}</span>
          </div></td>
          <td className="pr-2">{stateLabel(stage.status)}</td><td className="pr-2 tabular-nums">{stage.pct}%</td>
          <td className="text-right tabular-nums">{stage.total > 0 ? `${(stage.completed + stage.failed + stage.skipped).toLocaleString()} / ${stage.total.toLocaleString()}` : "—"}</td>
        </tr>)}</tbody>
      </table>
    </div>
    {active?.error && <p className="mt-3 rounded bg-amber-50 p-2 text-xs text-amber-900">{active.error}</p>}
    {exceptions.length > 0 && <div className="mt-3 rounded-lg border border-red-200 bg-red-50 p-3 text-xs text-red-900">
      <p className="mb-1 font-semibold">Processing exceptions</p>
      {exceptions.map((stage) => <p key={stage.id}>{stage.label}: {exceptionText(stage)}</p>)}
    </div>}
  </div>;
}
