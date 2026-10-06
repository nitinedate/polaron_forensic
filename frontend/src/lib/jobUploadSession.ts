import { ensureFreshAccessToken } from "./api";
import { forensicApi } from "./forensicApi";
import type { ActivityLine, UploadFileItem, UploadProgressState } from "./types/forensic";

const STORAGE_PREFIX = "iam.jobUpload.";

/** Concurrent E01/EWF segment copies from the client to the forensic server. */
export const DOWNLOAD_PARALLELISM = 5;

/** Sort key: E01/E02… or .001/.002… first, then plain names A→Z. */
function segmentSortKey(name: string): [number, string] {
  const base = name.split(/[/\\]/).pop() ?? name;
  const ewf = base.match(/\.e(\d{2})$/i);
  if (ewf) return [parseInt(ewf[1], 10), base.toLowerCase()];
  const raw = base.match(/\.(\d{3})$/i);
  if (raw) return [parseInt(raw[1], 10), base.toLowerCase()];
  return [Number.MAX_SAFE_INTEGER, base.toLowerCase()];
}

export function compareEvidenceFilenames(a: string, b: string): number {
  const [na, sa] = segmentSortKey(a);
  const [nb, sb] = segmentSortKey(b);
  if (na !== nb) return na - nb;
  return sa.localeCompare(sb);
}

function sortFilesAscending(files: File[]): File[] {
  return [...files].sort((a, b) => compareEvidenceFilenames(a.name, b.name));
}

function sortFileItemsAscending(items: UploadFileItem[]): UploadFileItem[] {
  return [...items].sort((a, b) => compareEvidenceFilenames(a.name, b.name));
}

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

export function makeActivityLine(level: ActivityLine["level"], message: string): ActivityLine {
  return {
    id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    timestamp: new Date().toISOString(),
    level,
    message,
  };
}

export interface JobUploadSnapshot {
  lines: ActivityLine[];
  progress: UploadProgressState | null;
  uploading: boolean;
  files: UploadFileItem[];
}

type Listener = () => void;

class JobUploadSessionStore {
  private sessions = new Map<string, JobUploadSnapshot>();
  private listeners = new Map<string, Set<Listener>>();
  private runners = new Map<string, Promise<void>>();
  private fileBlobs = new Map<string, Map<string, File>>();

  private readStorage(jobId: string): JobUploadSnapshot | null {
    try {
      const raw = sessionStorage.getItem(STORAGE_PREFIX + jobId);
      return raw ? (JSON.parse(raw) as JobUploadSnapshot) : null;
    } catch {
      return null;
    }
  }

  private writeStorage(jobId: string) {
    sessionStorage.setItem(STORAGE_PREFIX + jobId, JSON.stringify(this.get(jobId)));
  }

  get(jobId: string): JobUploadSnapshot {
    if (!this.sessions.has(jobId)) {
      const stored = this.readStorage(jobId);
      const snapshot: JobUploadSnapshot = stored
        ? { ...stored, files: stored.files ?? [] }
        : { lines: [], progress: null, uploading: false, files: [] };
      this.sessions.set(jobId, snapshot);
    }
    return this.sessions.get(jobId)!;
  }

  private blobs(jobId: string): Map<string, File> {
    if (!this.fileBlobs.has(jobId)) this.fileBlobs.set(jobId, new Map());
    return this.fileBlobs.get(jobId)!;
  }

  subscribe(jobId: string, listener: Listener): () => void {
    if (!this.listeners.has(jobId)) this.listeners.set(jobId, new Set());
    this.listeners.get(jobId)!.add(listener);
    return () => this.listeners.get(jobId)?.delete(listener);
  }

  private notify(jobId: string) {
    this.writeStorage(jobId);
    this.listeners.get(jobId)?.forEach((fn) => fn());
  }

  addLine(jobId: string, line: ActivityLine) {
    const session = this.get(jobId);
    session.lines = [...session.lines, line];
    this.notify(jobId);
  }

  setProgress(jobId: string, progress: UploadProgressState | null) {
    this.get(jobId).progress = progress;
    this.notify(jobId);
  }

  setUploading(jobId: string, uploading: boolean) {
    this.get(jobId).uploading = uploading;
    this.notify(jobId);
  }

  addQueuedFiles(jobId: string, incoming: File[]) {
    const session = this.get(jobId);
    const blobs = this.blobs(jobId);
    const items: UploadFileItem[] = sortFilesAscending(incoming).map((f) => {
      const id = `${Date.now()}-${Math.random().toString(36).slice(2, 9)}`;
      blobs.set(id, f);
      return {
        id,
        name: f.name,
        sizeBytes: f.size,
        status: "queued" as const,
      };
    });
    session.files = sortFileItemsAscending([...session.files, ...items]);
    this.notify(jobId);
  }

  removeFile(jobId: string, fileId: string) {
    const session = this.get(jobId);
    session.files = session.files.filter((f) => !(f.id === fileId && f.status === "queued"));
    this.blobs(jobId).delete(fileId);
    this.notify(jobId);
  }

  clearQueued(jobId: string) {
    const session = this.get(jobId);
    const blobs = this.blobs(jobId);
    for (const f of session.files) {
      if (f.status === "queued") blobs.delete(f.id);
    }
    session.files = session.files.filter((f) => f.status !== "queued");
    this.notify(jobId);
  }

  clearCompleted(jobId: string) {
    const session = this.get(jobId);
    session.files = session.files.filter((f) => f.status === "queued" || f.status === "uploading");
    this.notify(jobId);
  }

  private setFileStatus(jobId: string, fileId: string, status: UploadFileItem["status"]) {
    const session = this.get(jobId);
    session.files = session.files.map((f) => (f.id === fileId ? { ...f, status } : f));
    this.notify(jobId);
  }

  isRunning(jobId: string): boolean {
    return this.runners.has(jobId);
  }

  /**
   * Clear browser/client-transfer state when the examiner explicitly switches
   * to evidence that is already accessible from the forensic server.
   *
   * Server/local-network/removable evidence is processed in place and must not
   * retain an old Download Agent log/progress card from a previous client
   * upload attempt. Never clear a transfer that is genuinely still running.
   */
  resetForServerSource(jobId: string): boolean {
    if (this.runners.has(jobId)) return false;
    this.sessions.set(jobId, { lines: [], progress: null, uploading: false, files: [] });
    this.fileBlobs.delete(jobId);
    try {
      sessionStorage.removeItem(STORAGE_PREFIX + jobId);
    } catch {
      // sessionStorage can be unavailable in hardened/private browser contexts.
    }
    this.notify(jobId);
    return true;
  }


  /** Remove stale client-transfer state when switching to server evidence. */
  clearInactiveForServerSource(jobId: string): boolean {
    return this.resetForServerSource(jobId);
  }

  /**
   * Mark this job as server-local zero-copy in the browser session.
   * Download Agent was not started; stale client-transfer lines/progress are discarded.
   */
  markServerLocalZeroCopy(jobId: string): boolean {
    const ok = this.resetForServerSource(jobId);
    if (!ok) return false;
    return true;
  }

  /** Backward-compatible explicit reset for source switching. */
  reset(jobId: string): boolean {
    return this.resetForServerSource(jobId);
  }

  async startUpload(
    jobId: string,
    mode: "files" | "directory",
    onComplete?: () => void
  ): Promise<void> {
    if (this.runners.has(jobId)) {
      return this.runners.get(jobId)!;
    }

    const blobs = this.blobs(jobId);
    const fileEntries = this.get(jobId)
      .files.filter((f) => f.status === "queued")
      .map((f) => {
        const file = blobs.get(f.id);
        return file ? { id: f.id, file } : null;
      })
      .filter((e): e is { id: string; file: File } => e !== null)
      .sort((a, b) => compareEvidenceFilenames(a.file.name, b.file.name));

    if (fileEntries.length === 0) return;

    const run = this.runUpload(jobId, fileEntries, mode, onComplete);
    this.runners.set(jobId, run);
    try {
      await run;
    } finally {
      this.runners.delete(jobId);
    }
  }

  private async runUpload(
    jobId: string,
    fileEntries: { id: string; file: File }[],
    mode: "files" | "directory",
    onComplete?: () => void
  ) {
    const files = fileEntries.map((e) => e.file);
    const total = files.length;
    const totalBytes = files.reduce((sum, f) => sum + f.size, 0);

    this.setUploading(jobId, true);
    const slots = Math.min(DOWNLOAD_PARALLELISM, total);
    try {
      await forensicApi.beginClientUpload(jobId, total);
      this.addLine(
        jobId,
        makeActivityLine(
          "info",
          `Download Agent started — ${total} file(s) (${formatBytes(totalBytes)}). Copying ${slots} at a time. Extraction, parse, OCR, RAG and report remain held until all ${total} are verified on the server.`
        )
      );
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Could not start Download Agent";
      this.addLine(jobId, makeActivityLine("error", `Download Agent gate could not be opened safely: ${msg}`));
      this.setUploading(jobId, false);
      throw e instanceof Error ? e : new Error(msg);
    }

    let skippedCount = 0;
    let failedCount = 0;
    let cursor = 0;
    let completed = 0;
    const inflight = new Map<number, string>();

    const uploadOne = async (slot: number, fileId: string, file: File) => {
      const relPath =
        (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name;
      inflight.set(slot, file.name);
      this.setFileStatus(jobId, fileId, "uploading");
      this.setProgress(jobId, { index: completed, total, fileName: file.name, filePct: 0 });
      this.addLine(
        jobId,
        makeActivityLine(
          "info",
          `Download Agent slot ${slot + 1}/${slots} START ${file.name} (${formatBytes(file.size)}) — in-flight: ${[...inflight.values()].join(", ")}`
        )
      );

      try {
        await ensureFreshAccessToken();
        const opts = { register: false, auto_process: false, expected_total: total };
        const useDirectoryEndpoint = mode === "directory" && relPath.includes("/");
        const result = useDirectoryEndpoint
          ? await forensicApi.uploadDirectoryFile(jobId, file, relPath, (pct) =>
              this.setProgress(jobId, { index: completed, total, fileName: file.name, filePct: pct }), opts)
          : await forensicApi.uploadEvidenceFile(jobId, file, (pct) =>
              this.setProgress(jobId, { index: completed, total, fileName: file.name, filePct: pct }), opts);

        skippedCount += result.skipped.length;

        const wasSkipped =
          result.skipped.length > 0 &&
          result.skipped.some(
            (s) => s === file.name || s === relPath || s.endsWith(file.name)
          );
        if (wasSkipped) {
          this.setFileStatus(jobId, fileId, "skipped");
          this.addLine(jobId, makeActivityLine("warn", `Download Agent slot ${slot + 1}/${slots} SKIP ${file.name}`));
        } else if (result.accepted.length === 0 && result.skipped.length > 0) {
          this.setFileStatus(jobId, fileId, "skipped");
          this.addLine(jobId, makeActivityLine("warn", `Download Agent slot ${slot + 1}/${slots} SKIP ${file.name}`));
        } else {
          this.setFileStatus(jobId, fileId, "done");
          completed += 1;
          this.addLine(
            jobId,
            makeActivityLine(
              "success",
              `Download Agent slot ${slot + 1}/${slots} DONE ${file.name} — ${completed}/${total} received. In-flight: ${[...[...inflight.entries()].filter(([s]) => s !== slot).map(([, n]) => n)].join(", ") || "none"}`
            )
          );
        }
      } catch (e: unknown) {
        failedCount += 1;
        this.setFileStatus(jobId, fileId, "failed");
        const msg = e instanceof Error ? e.message : "Upload failed";
        this.addLine(jobId, makeActivityLine("error", `Download Agent slot ${slot + 1}/${slots} FAIL ${file.name}: ${msg}`));
      } finally {
        inflight.delete(slot);
      }
    };

    const worker = async (slot: number) => {
      while (true) {
        const index = cursor;
        cursor += 1;
        if (index >= fileEntries.length) return;
        const { id: fileId, file } = fileEntries[index];
        await uploadOne(slot, fileId, file);
      }
    };

    await Promise.all(Array.from({ length: slots }, (_, slot) => worker(slot)));

    this.setProgress(jobId, null);
    const copiedOk = this.get(jobId).files.filter((f) => f.status === "done").length;
    if (failedCount > 0) {
      const msg = `Upload incomplete: ${copiedOk} copied, ${skippedCount} skipped, ${failedCount} failed. The full forensic pipeline remains held; retry the failed segment(s).`;
      this.addLine(jobId, makeActivityLine("error", msg));
      this.setUploading(jobId, false);
      throw new Error(msg);
    }
    if (copiedOk <= 0 && skippedCount <= 0) {
      const msg = "Upload incomplete: no image file reached the server. The forensic pipeline remains held.";
      this.addLine(jobId, makeActivityLine("error", msg));
      this.setUploading(jobId, false);
      throw new Error(msg);
    }
    try {
      this.addLine(
        jobId,
        makeActivityLine(
          "info",
          `Transfer workers finished — asking the server to verify all ${total} declared file(s) before any other agent may start…`
        )
      );
      await forensicApi.completeClientUpload(jobId, false);
      this.addLine(
        jobId,
        makeActivityLine("success", `Download Agent signaled go — registered ${copiedOk} file(s)`)
      );
      onComplete?.();
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Register after upload failed";
      this.addLine(jobId, makeActivityLine("error", msg));
      this.setUploading(jobId, false);
      throw e instanceof Error ? e : new Error(msg);
    }
    this.setUploading(jobId, false);
  }
}

export const jobUploadSession = new JobUploadSessionStore();
