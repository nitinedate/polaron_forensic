import clsx from "clsx";
import { Upload } from "lucide-react";
import { ExtractionLogConsole } from "./ExtractionLogConsole";
import type { ActivityLine, ExtractionLog, UploadProgressState } from "../../lib/types/forensic";

const LEVEL_TONE: Record<string, string> = {
  error: "text-red-400",
  warn: "text-amber-400",
  info: "text-emerald-400",
  success: "text-sky-400",
};

interface JobActivityPanelProps {
  jobId: string;
  uploadLines: ActivityLine[];
  uploadProgress: UploadProgressState | null;
  uploading: boolean;
  /** Only true for evidence that is being transferred from a client/browser. */
  showUploadActivity?: boolean;
  /** Explicit persisted/selected evidence transport. */
  sourceTransport?: "server" | "client" | "unknown";
  /** Preferred client-only flag; retained alongside showUploadActivity for compatibility. */
  showClientTransfer?: boolean;
  extractionLogs?: ExtractionLog[];
  extractionLogsLoading?: boolean;
  registering?: boolean;
  onRefreshLogs?: () => void;
  /** Match extraction log height to the upload panel (px). */
  panelHeight?: number;
}

function ActivityLines({ lines, emptyMessage }: { lines: ActivityLine[]; emptyMessage?: string }) {
  if (lines.length === 0) {
    return emptyMessage ? <p className="text-ink-500">{emptyMessage}</p> : null;
  }
  return (
    <>
      {lines.map((line) => (
        <div key={line.id} className="mb-1 flex gap-2">
          <span className="shrink-0 text-ink-600">
            {new Date(line.timestamp).toLocaleTimeString()}
          </span>
          <span className={clsx("shrink-0 uppercase", LEVEL_TONE[line.level] ?? "text-ink-400")}>
            {line.level}
          </span>
          <span className="text-ink-200">{line.message}</span>
        </div>
      ))}
    </>
  );
}

export function JobActivityPanel({
  jobId,
  uploadLines,
  uploadProgress,
  uploading,
  showUploadActivity = false,
  sourceTransport = "unknown",
  showClientTransfer = false,
  extractionLogs,
  extractionLogsLoading,
  registering = false,
  onRefreshLogs,
  panelHeight,
}: JobActivityPanelProps) {
  const clientTransferSelected =
    sourceTransport === "client" ||
    showClientTransfer ||
    (showUploadActivity && sourceTransport !== "server");
  const showUpload = clientTransferSelected && (uploading || uploadLines.length > 0 || uploadProgress !== null);
  const uploadExpanded = clientTransferSelected && (uploading || uploadLines.length > 0);
  const overallPct = uploadProgress
    ? Math.round(((uploadProgress.index + uploadProgress.filePct / 100) / uploadProgress.total) * 100)
    : 0;

  return (
    <div
      className={clsx(
        "flex min-h-0 flex-col gap-3 overflow-hidden",
        !panelHeight && "max-h-[520px]"
      )}
      style={panelHeight ? { height: panelHeight, maxHeight: panelHeight } : undefined}
    >
      {showUpload && uploadExpanded && (
        <div
          className={clsx(
            "flex shrink-0 flex-col overflow-hidden rounded-xl border border-ink-800 bg-ink-950",
            uploading ? "h-[180px]" : "max-h-[140px]"
          )}
        >
          <div className="flex items-center justify-between border-b border-ink-800 px-4 py-2">
            <div className="flex items-center gap-2 text-ink-300">
              <Upload className="h-4 w-4" />
              <span className="text-xs font-semibold uppercase tracking-wider">Evidence transfer activity</span>
              <span className="text-xs text-ink-500">{uploadLines.length} entries</span>
            </div>
            {uploading && uploadProgress && (
              <span className="text-xs text-ink-400">
                {uploadProgress.index + 1}/{uploadProgress.total} · {uploadProgress.filePct}%
              </span>
            )}
          </div>
          {uploadProgress && uploading && (
            <div className="border-b border-ink-800 px-4 py-2">
              <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                <div className="truncate text-xs text-ink-400">{uploadProgress.fileName}</div>
                <span className="rounded-full border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-amber-300">
                  Pipeline hold · extract / parse / OCR / RAG / report paused
                </span>
              </div>
              <div className="h-1.5 overflow-hidden rounded-full bg-ink-800">
                <div
                  className="h-full rounded-full bg-brand-500 transition-all duration-300"
                  style={{ width: `${overallPct}%` }}
                />
              </div>
              <p className="mt-1 text-xs text-ink-500">Overall {overallPct}%</p>
            </div>
          )}
          <div className="min-h-0 flex-1 overflow-y-auto p-3 font-mono text-xs leading-relaxed">
            <ActivityLines
              lines={uploadLines}
              emptyMessage={uploading ? "Preparing upload…" : undefined}
            />
          </div>
        </div>
      )}

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden">
        <ExtractionLogConsole
          jobId={jobId}
          controlledLogs={extractionLogs}
          controlledLoading={extractionLogsLoading}
          registering={registering}
              onManualRefresh={onRefreshLogs}
              pollIntervalMs={2000}
        />
      </div>
    </div>
  );
}
