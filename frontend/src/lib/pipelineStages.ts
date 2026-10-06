import type { Job } from "./types/forensic";
import { orchestratedStages, computeOverallPipelinePct } from "./orchestrationStages";

export type PipelineStageId =
  | "virtual_disk"
  | "extraction"
  | "materialize"
  | "parse"
  | "rag_index"
  | "artifact_inventory"
  | "iosagent"
  | "androidagent"
  | "drive_mount_agent"
  | "download_agent"
  | "list_folder_agent"
  | "segments_agent"
  | "virtual_disk_agent"
  | "extraction_agent"
  | "materialize_agent"
  | "ocr_agent"
  | "parse_agent"
  | "chunk_agent"
  | "embed_agent"
  | "entity_agent"
  | "neo4j_agent"
  | "annotation_agent"
  | "ontology_agent"
  | "artifacts_agent"
  | "media_review_agent"
  | "recovery_agent"
  | "validation_agent";

export type PipelineStageState = "pending" | "running" | "done" | "failed";

export interface PipelineStageProgress {
  id: PipelineStageId;
  label: string;
  state: PipelineStageState;
  pct: number;
  indeterminate?: boolean;
  detail: string | null;
  /** Baseline phase complete while background enrichment continues. */
  baselineDone?: boolean;
}

/** Always the process-action agents — never the old 6-step fallback. */
export function getPipelineStages(job: Job): PipelineStageProgress[] {
  return orchestratedStages(job);
}

export function overallPipelinePct(stages: PipelineStageProgress[], job?: Job): number {
  if (job) return computeOverallPipelinePct(job, stages);
  if (stages.length === 0) return 0;
  const allDone = stages.every((s) => s.state === "done");
  if (allDone) return 100;
  const sum = stages.reduce((acc, s) => acc + (s.state === "done" ? 100 : s.pct), 0);
  return Math.min(99, Math.round(sum / stages.length));
}

export function isJobStale(updatedAt: string | undefined, active: boolean, thresholdMs = 60_000): boolean {
  if (!active || !updatedAt) return false;
  const ts = Date.parse(updatedAt);
  if (Number.isNaN(ts)) return false;
  return Date.now() - ts > thresholdMs;
}
