import type { ExtractCoverage, Job } from "./types/forensic";
import { orchestratedOverallPct, isPipelineFullyComplete } from "./orchestrationStages";

export function coverageProgressPct(cov: ExtractCoverage | null | undefined): number {
  if (!cov?.interesting_total) return 0;
  const pct = Math.round((100 * cov.extracted) / cov.interesting_total);
  if (cov.pending <= 0) return Math.min(100, pct);
  return Math.min(99, pct);
}

/** Overall job progress — extraction phase uses path coverage; indexing uses RAG artifact counts. */
export function effectiveJobProgressPct(job: Job): number {
  const cov = job.extract_coverage;
  const pp = job.pipeline_progress;
  const orchPct = orchestratedOverallPct(job);

  if (isPipelineFullyComplete(job)) {
    return 100;
  }

  if (orchPct != null && orchPct < 100) {
    return orchPct;
  }
  if (orchPct != null && orchPct >= 100) {
    return 99;
  }

  if (pp?.phase === "artifact_inventory" || pp?.phase === "axiom_artifacts") {
    if (pp.total && pp.total > 0) {
      const raw = Math.round((100 * (pp.completed ?? 0)) / pp.total);
      return Math.min(99, raw);
    }
  }

  if (["indexed", "ready", "completed", "classified", "report_ready"].includes(job.status)) {
    if (!isPipelineFullyComplete(job)) {
      const pp = job.pipeline_progress;
      if (pp?.phase === "artifact_inventory" || pp?.phase === "axiom_artifacts") {
        const total = pp.total ?? 0;
        const completed = pp.completed ?? 0;
        if (total > 0) return Math.min(99, Math.round((100 * completed) / total));
      }
      return Math.min(99, job.progress_pct ?? 85);
    }
    return 100;
  }

  if (job.status === "indexing" || job.status === "extracted") {
    if (pp?.total && pp.total > 0) {
      const raw = Math.round((100 * pp.completed) / pp.total);
      return Math.min(99, raw);
    }
    if ((job.progress_pct ?? 0) > 0) {
      return Math.min(99, job.progress_pct ?? 0);
    }
  }

  if (cov?.interesting_total) return coverageProgressPct(cov);

  // Phase 2 disk build: use file extraction counts when available
  if (["building_disk", "processing"].includes(job.status)) {
    const total = job.files_total ?? 0;
    const done = job.files_extracted ?? 0;
    if (total > 0 && done < total) return Math.min(99, Math.round((100 * done) / total));
    return Math.min(94, job.progress_pct ?? 2);
  }
  if (job.status === "disk_ready") {
    const total = job.files_total ?? 0;
    const done = job.files_extracted ?? 0;
    if (total > 0) return Math.min(99, Math.round((100 * done) / total));
  }

  return job.progress_pct ?? 0;
}

export function jobHasPendingPaths(job: Job | null | undefined): boolean {
  if ((job?.enrichment?.artifacts_pending ?? 0) > 0) return true;
  if (
    job &&
    (["indexed", "ready", "completed", "classified", "report_ready"].includes(job.status) ||
      job.pipeline_progress?.phase === "complete")
  ) {
    return false;
  }
  const cov = job?.extract_coverage;
  if (cov?.interesting_total && (cov.extracted ?? 0) >= cov.interesting_total) return false;
  return (cov?.pending ?? 0) > 0;
}
