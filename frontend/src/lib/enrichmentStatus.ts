import type { EnrichmentSnapshot, Job } from "./types/forensic";

export function jobEnrichment(job: Job | null | undefined): EnrichmentSnapshot | null {
  return job?.enrichment ?? null;
}

export function isBackgroundEnriching(job: Job | null | undefined): boolean {
  const e = jobEnrichment(job);
  const ragIndexing = Boolean(e?.rag_embedding_enabled && e?.rag_indexing);
  return Boolean(e?.enriching || ragIndexing);
}

export function isBaselineReady(job: Job | null | undefined): boolean {
  const e = jobEnrichment(job);
  return Boolean(e?.baseline_ready);
}

export function enrichmentParsePct(job: Job | null | undefined): number {
  const e = jobEnrichment(job);
  if (!e) return 0;
  if (e.parse_done || (e.artifacts_pending ?? 0) <= 0) return 100;
  const total = e.artifacts_total || 0;
  if (!total) return 0;
  const raw = Math.round((100 * (e.artifacts_parsed ?? 0)) / total);
  return Math.min(99, raw);
}

export function enrichmentRagPct(job: Job | null | undefined): number {
  const e = jobEnrichment(job);
  if (!e) return 0;
  const chunks = e.rag_chunks ?? 0;
  const pending = e.rag_pending ?? 0;
  if (pending <= 0 && (e.rag_done || chunks > 0)) return 100;
  if (pending <= 0 && chunks <= 0) return 0;
  const total = Math.max(e.rag_total ?? 0, chunks + pending, 1);
  return Math.min(99, Math.round((100 * chunks) / total));
}

export function enrichmentBannerTitle(job: Job | null | undefined): string | null {
  if (!isBackgroundEnriching(job)) return null;
  return "Baseline ready — Q&A available";
}

export function enrichmentBannerMessage(job: Job | null | undefined): string | null {
  const e = jobEnrichment(job);
  if (!e?.enriching) return null;
  const skipped =
    e.artifacts_skipped && e.files_registered
      ? ` (${e.artifacts_skipped.toLocaleString()} low-value files skipped)`
      : "";
  return (
    `${(e.rag_chunks ?? 0).toLocaleString()} evidence chunks searchable now. ` +
    `Forensic parse: ${(e.artifacts_parsed ?? 0).toLocaleString()} / ${(e.artifacts_total ?? 0).toLocaleString()} ` +
    `(+${(e.artifacts_pending ?? 0).toLocaleString()} pending)${skipped}.`
  );
}

export function enrichmentOverallLabel(job: Job | null | undefined): string | null {
  const e = jobEnrichment(job);
  if (!e?.enriching) return null;
  if ((e.artifacts_pending ?? 0) > 0) {
    return `Forensic parse ${(e.artifacts_parsed ?? 0).toLocaleString()} / ${(e.artifacts_total ?? 0).toLocaleString()}`;
  }
  if ((e.ocr_pending ?? 0) > 0) {
    return `OCR ${(e.ocr_done ?? 0).toLocaleString()} done / ${((e.ocr_done ?? 0) + (e.ocr_pending ?? 0)).toLocaleString()}`;
  }
  if (e.rag_embedding_enabled) {
    return `RAG embed ${(e.rag_chunks ?? 0).toLocaleString()} / ${Math.max(e.rag_total ?? 0, e.rag_chunks ?? 0).toLocaleString()} chunks`;
  }
  return null;
}
