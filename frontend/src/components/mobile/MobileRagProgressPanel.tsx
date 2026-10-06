import { AlertCircle, CheckCircle2, LoaderCircle } from "lucide-react";

import { Card } from "../ui";
import type { Job } from "../../lib/types/forensic";

type StageState = "pending" | "running" | "done" | "failed";

type StageView = {
  id: string;
  label: string;
  state: StageState;
  pct: number;
  detail?: string;
};

const AGENT_STAGES = [
  ["extraction_agent", "Extraction"],
  ["materialize_agent", "Artifact materialization"],
  ["parse_agent", "Parsing"],
  ["ocr_agent", "OCR"],
  ["chunk_agent", "Chunking"],
  ["embed_agent", "Vector embedding"],
  ["entity_agent", "Entity extraction"],
  ["neo4j_agent", "Knowledge graph"],
  ["annotation_agent", "Annotation"],
  ["ontology_agent", "Ontology"],
  ["artifacts_agent", "Artifact inventory"],
] as const;

const RAG_READY_STATUS = new Set([
  "indexed",
  "ready",
  "report_ready",
  "report_generating",
  "reporting",
  "completed",
  "classified",
]);

function normalizeState(value: string | undefined): StageState {
  const state = String(value || "pending").toLowerCase();
  if (["done", "complete", "completed", "success"].includes(state)) return "done";
  if (["failed", "error"].includes(state)) return "failed";
  if (["running", "active", "processing"].includes(state)) return "running";
  return "pending";
}

function clampPct(value: unknown, state: StageState): number {
  const n = Number(value);
  if (state === "done") return 100;
  if (!Number.isFinite(n)) return state === "running" ? 1 : 0;
  return Math.max(0, Math.min(state === "running" ? 99 : 100, Math.round(n)));
}

function buildStages(job: Job): StageView[] {
  const agents = job.pipeline_progress?.orchestration?.agents ?? {};
  const hasEvidence =
    (job.evidence_count ?? job.files_total ?? 0) > 0 || Boolean(job.disk_source?.evidence_folder);

  const selected: StageView = {
    id: "evidence",
    label: "Evidence directory selected",
    state: hasEvidence ? "done" : "pending",
    pct: hasEvidence ? 100 : 0,
  };

  const agentStages = AGENT_STAGES.map(([id, label]): StageView => {
    const agent = agents[id];
    const state = normalizeState(agent?.state);
    return {
      id,
      label,
      state,
      pct: clampPct(agent?.pct, state),
      detail: agent?.detail,
    };
  });

  const ragReady =
    Boolean(job.enrichment?.baseline_ready) ||
    RAG_READY_STATUS.has(String(job.status || "").toLowerCase());
  const failed = String(job.status || "").toLowerCase() === "failed";
  const ragPct = ragReady
    ? 100
    : Math.max(
        0,
        Math.min(
          99,
          Number(job.pipeline_progress?.orchestration?.overall_pct ?? job.progress_pct ?? 0),
        ),
      );

  return [
    selected,
    ...agentStages,
    {
      id: "rag-ready",
      label: "RAG ready",
      state: ragReady ? "done" : failed ? "failed" : ragPct > 0 ? "running" : "pending",
      pct: ragPct,
      detail: ragReady ? "Index is ready for search and Q&A." : undefined,
    },
  ];
}

function collectErrors(job: Job, stages: StageView[]): string[] {
  const messages = new Set<string>();
  const jobError = String(job.error || "").trim();
  if (jobError) messages.add(jobError);
  for (const stage of stages) {
    if (stage.state !== "failed") continue;
    const detail = String(stage.detail || "").trim();
    messages.add(detail ? `${stage.label}: ${detail}` : `${stage.label} failed.`);
  }
  return Array.from(messages);
}

export function MobileRagProgressPanel({ job }: { job: Job }) {
  const stages = buildStages(job);
  const errors = collectErrors(job, stages);
  const completed = stages.filter((stage) => stage.state === "done");
  const failedStage = stages.find((stage) => stage.state === "failed");
  const runningStage = stages.find((stage) => stage.state === "running");
  const pendingStage = stages.find((stage) => stage.state === "pending");
  const current = failedStage || runningStage || pendingStage || stages[stages.length - 1];
  const isComplete = completed.length === stages.length;
  const currentPct = isComplete ? 100 : current?.pct ?? 0;

  return (
    <div className="space-y-4">
      <Card className="p-5">
        <div>
          <h3 className="text-sm font-bold text-ink-900">RAG Processing</h3>
          <p className="mt-1 text-xs text-ink-500">
            The selected directory is processed step-by-step. Only the process currently running is shown on the progress bar.
          </p>
        </div>

        <div className="mt-5 rounded-xl border border-ink-200 bg-white p-4">
          <div className="flex items-center justify-between gap-3">
            <div className="min-w-0">
              <p className="text-[11px] font-semibold uppercase tracking-wide text-ink-400">
                {isComplete ? "Completed" : failedStage ? "Stopped at" : "Current process"}
              </p>
              <div className="mt-1 flex items-center gap-2">
                {isComplete ? (
                  <CheckCircle2 className="h-5 w-5 shrink-0 text-emerald-600" />
                ) : failedStage ? (
                  <AlertCircle className="h-5 w-5 shrink-0 text-red-600" />
                ) : (
                  <LoaderCircle className="h-5 w-5 shrink-0 animate-spin text-brand-600" />
                )}
                <p className="truncate text-sm font-bold text-ink-900">
                  {isComplete ? "RAG ready" : current?.label || "Waiting to start"}
                </p>
              </div>
            </div>
            <span
              className={`shrink-0 text-sm font-bold ${
                isComplete ? "text-emerald-700" : failedStage ? "text-red-700" : "text-brand-700"
              }`}
            >
              {currentPct}%
            </span>
          </div>

          <div className="mt-3 h-2.5 overflow-hidden rounded-full bg-ink-100">
            <div
              className={`h-full rounded-full transition-all duration-300 ${
                isComplete ? "bg-emerald-500" : failedStage ? "bg-red-500" : "bg-brand-500"
              }`}
              style={{ width: `${currentPct}%` }}
            />
          </div>
          {current?.detail && !isComplete && !failedStage ? (
            <p className="mt-2 text-xs text-ink-500">{current.detail}</p>
          ) : null}
        </div>

        {completed.length ? (
          <div className="mt-4 flex flex-wrap gap-2">
            {completed.map((stage) => (
              <span
                key={stage.id}
                className="inline-flex items-center gap-1.5 rounded-full border border-emerald-200 bg-emerald-50 px-2.5 py-1 text-xs font-medium text-emerald-800"
              >
                <CheckCircle2 className="h-3.5 w-3.5" />
                {stage.label}
              </span>
            ))}
          </div>
        ) : null}
      </Card>

      {errors.length ? (
        <Card className="border-red-200 p-5">
          <div className="flex items-start gap-3">
            <AlertCircle className="mt-0.5 h-5 w-5 shrink-0 text-red-600" />
            <div className="min-w-0 flex-1">
              <h3 className="text-sm font-bold text-red-900">Exceptions / Errors</h3>
              <p className="mt-1 text-xs text-red-700">
                Processing exceptions are shown here separately from normal RAG progress.
              </p>
              <div className="mt-3 space-y-2">
                {errors.map((message, index) => (
                  <div
                    key={`${index}-${message}`}
                    className="whitespace-pre-wrap break-words rounded-lg border border-red-100 bg-red-50 px-3 py-2 font-mono text-xs text-red-900"
                  >
                    {message}
                  </div>
                ))}
              </div>
            </div>
          </div>
        </Card>
      ) : null}
    </div>
  );
}
