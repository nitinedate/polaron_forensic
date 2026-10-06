import type { Job, PipelineProgress } from "./types/forensic";
import { shortenProgressLabel } from "./displayText";

export function extractCountsIncomplete(job?: {
  status?: string;
  files_extracted?: number;
  files_total?: number;
  extracted_disk_uri?: string | null;
} | null): boolean {
  if (!job) return false;
  if (["processing", "building_disk", "extracting"].includes(job.status || "")) return true;
  const filesTotal = job.files_total ?? 0;
  const filesDone = job.files_extracted ?? 0;
  return filesTotal > 0 && filesDone < filesTotal;
}

export function formatPipelineProgress(
  pp: PipelineProgress | null | undefined,
  job?: Job | null,
): string | null {
  if (extractCountsIncomplete(job)) {
    const filesTotal = job?.files_total ?? 0;
    const filesDone = job?.files_extracted ?? 0;
    if (filesTotal > 0) {
      const pct = Math.min(99, Math.round((100 * filesDone) / filesTotal));
      return `${filesDone.toLocaleString()} / ${filesTotal.toLocaleString()} extraction (${pct}%)`;
    }
  }
  if (!pp || pp.completed == null) return null;
  const label = shortenProgressLabel(pp.label, pp.phase);
  const completed = pp.completed.toLocaleString();
  if (pp.total != null && pp.total > 0) {
    const total = pp.total.toLocaleString();
    const pct = Math.min(100, Math.round((pp.completed / pp.total) * 100));
    return `${completed} / ${total} ${label} (${pct}%)`;
  }
  return `${completed} ${label}`;
}

export function parsePathProgressFromLog(message: string): PipelineProgress | null {
  const diskExtract = message.match(/Extracting files\s*[—–-]\s*([\d,]+)\s*\/\s*([\d,]+)/i);
  if (diskExtract) {
    return {
      phase: "extract",
      completed: parseInt(diskExtract[1].replace(/,/g, ""), 10),
      total: parseInt(diskExtract[2].replace(/,/g, ""), 10),
      label: "files extracted",
    };
  }
  const extract = message.match(/Extracting paths\s*[—–-]\s*([\d,]+)\s*\/\s*([\d,]+)/i);
  if (extract) {
    return {
      phase: "extract",
      completed: parseInt(extract[1].replace(/,/g, ""), 10),
      total: parseInt(extract[2].replace(/,/g, ""), 10),
      label: "paths extracted",
    };
  }
  const scanning = message.match(/Scanning\s+([\d,]+)\s+paths/i);
  if (scanning) {
    return {
      phase: "extract",
      completed: 0,
      total: parseInt(scanning[1].replace(/,/g, ""), 10),
      label: "paths extracted",
    };
  }
  const rag = message.match(/RAG progress\s+\[([\d,]+)\/([\d,]+)\]/i);
  if (rag) {
    return {
      phase: "rag",
      completed: parseInt(rag[1].replace(/,/g, ""), 10),
      total: parseInt(rag[2].replace(/,/g, ""), 10),
      label: "artifacts in shard",
    };
  }
  const indexed = message.match(/([\d,]+)\s+paths indexed/i);
  if (indexed) {
    return {
      phase: "index",
      completed: parseInt(indexed[1].replace(/,/g, ""), 10),
      total: null,
      label: "paths indexed",
    };
  }
  return null;
}
