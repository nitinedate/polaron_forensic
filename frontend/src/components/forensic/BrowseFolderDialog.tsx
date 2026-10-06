import { useEffect, useRef, useState } from "react";
import { FolderOpen, HardDrive, X } from "lucide-react";

import { Button, Modal } from "../ui";
import {
  listOfficeServerDirectory,
  listOfficeServerDriveLetters,
  runHostDriveAgentRefresh,
  type HostDirectoryEntry,
  type HostDriveVolume,
} from "../../lib/hostDriveHelper";

const HIDDEN_DIR_RE = /^(?:\$recycle\.bin|system volume information|recovery|config\.msi)$/i;

const EMPTY_RECOMMENDED: string[] = [];

const SEGMENT_FILE_RE =
  /\.(?:E\d{2}|e\d{2}|001|002|003|004|005|006|007|008|009|dd|raw|aff|aff4|vmdk|vhdx|pas(?:\d+)?|ufd|ufdt|ufdx|zip)$/i;

const FILE_ROW_VISIBLE = 5;
const FILE_LIST_MAX_H = "11.25rem";

export type StagedEvidenceFile = {
  name: string;
  relativePath: string;
  size: number;
  isSegment: boolean;
};

export type StagedEvidenceFolder = {
  id: string;
  name: string;
  hostPath: string | null;
  files: StagedEvidenceFile[];
  /** Kept for compatibility with older intake code. Local-network browsing does not populate it. */
  fileBlobs?: File[];
  /** office means the path is already visible to the forensic host and is processed in place. */
  intake?: "browser" | "office";
};

function formatBytes(n: number) {
  if (!n || Number.isNaN(n)) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 * 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(2)} MB`;
  return `${(n / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

interface BrowseFolderDialogProps {
  open: boolean;
  helperOnline?: boolean | null;
  onClose: () => void;
  onConfirm: (folders: StagedEvidenceFolder[]) => void;
  onRefreshMounts?: () => void;
  onStartAgent?: () => void;
  refreshing?: boolean;
  startingAgent?: boolean;
  recommendedLetters?: string[];
}

function joinWindowsPath(base: string, name: string): string {
  const root = base.replace(/[\\/]+$/, "");
  return `${root}\\${name}`;
}

function recommendLetters(volumes: HostDriveVolume[], fromAgent: string[]): string[] {
  const fromMount = fromAgent.map((x) => x.replace(/:$/, "").toUpperCase()).filter(Boolean);
  if (fromMount.length) return fromMount;
  return volumes
    .filter((v) => v.drive_type === "removable" || v.mounted === false)
    .map((v) => v.letter.replace(/:$/, "").toUpperCase())
    .filter((letter) => letter && letter !== "C");
}

function sortVolumes(volumes: HostDriveVolume[], recommended: string[]): HostDriveVolume[] {
  const rec = new Set(recommended);
  return [...volumes].sort((a, b) => {
    const al = a.letter.replace(/:$/, "").toUpperCase();
    const bl = b.letter.replace(/:$/, "").toUpperCase();
    const ar = rec.has(al) || a.drive_type === "removable" ? 0 : 1;
    const br = rec.has(bl) || b.drive_type === "removable" ? 0 : 1;
    if (ar !== br) return ar - br;
    return al.localeCompare(bl);
  });
}

export function BrowseFolderDialog({
  open,
  helperOnline = null,
  onClose,
  onConfirm,
  onRefreshMounts,
  onStartAgent,
  startingAgent = false,
  recommendedLetters: recommendedLettersProp,
}: BrowseFolderDialogProps) {
  const recommendedLetters = recommendedLettersProp ?? EMPTY_RECOMMENDED;
  const recommendedLettersKey = recommendedLetters
    .map((x) => x.replace(/:$/, "").toUpperCase())
    .filter(Boolean)
    .sort()
    .join(",");
  const [folders, setFolders] = useState<StagedEvidenceFolder[]>([]);
  const [activeFolderId, setActiveFolderId] = useState<string | null>(null);
  const [windowsVolumes, setWindowsVolumes] = useState<HostDriveVolume[]>([]);
  const [browsePath, setBrowsePath] = useState<string | null>(null);
  const [browseEntries, setBrowseEntries] = useState<HostDirectoryEntry[]>([]);
  const [browseLoading, setBrowseLoading] = useState(false);
  const [browseError, setBrowseError] = useState<string | null>(null);
  const [drivesLoading, setDrivesLoading] = useState(false);
  const [agentLetters, setAgentLetters] = useState<string[]>([]);
  const [helperFromDrives, setHelperFromDrives] = useState<boolean | null>(null);
  const recommended = recommendLetters(windowsVolumes, agentLetters.length ? agentLetters : recommendedLetters);
  const recommendedKey = recommended.join(",");
  const helperKnownOnline = helperOnline === true || helperFromDrives === true;
  const loadSeq = useRef(0);

  async function loadDrives() {
    const seq = ++loadSeq.current;
    setDrivesLoading(true);
    setBrowseError(null);
    try {
      const host = await listOfficeServerDriveLetters(12000);
      if (seq !== loadSeq.current) return;
      if (typeof host?.helper_online === "boolean") {
        setHelperFromDrives(host.helper_online);
      }
      const volumes = (host?.volumes || []).filter((v) => v.drive_type !== "cdrom");
      if (volumes.length) {
        setWindowsVolumes(volumes);
        return;
      }
      const letters = host?.drives || [];
      if (letters.length) {
        setWindowsVolumes(letters.map((letter) => ({ letter, drive_type: "fixed" as const })));
        return;
      }
      setWindowsVolumes([]);
      setBrowseError(host?.message || host?.error || "No HDD, SSD, USB, pendrive or mapped drive was detected.");
    } finally {
      if (seq === loadSeq.current) setDrivesLoading(false);
    }
  }

  useEffect(() => {
    if (!open) {
      loadSeq.current += 1;
      setFolders([]);
      setActiveFolderId(null);
      setWindowsVolumes([]);
      setBrowsePath(null);
      setBrowseEntries([]);
      setBrowseError(null);
      setDrivesLoading(false);
      setAgentLetters([]);
      setHelperFromDrives(null);
      return;
    }
    setAgentLetters(recommendedLettersKey ? recommendedLettersKey.split(",") : []);
    void loadDrives();
    // Load once when the dialog opens. A new recommendedLetters array from the
    // parent poll must not restart detection — that was the flicker.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open]);

  async function openWindowsPath(path: string) {
    setBrowseLoading(true);
    setBrowseError(null);
    try {
      let listing = await listOfficeServerDirectory(path, 120_000);
      if (!listing?.ok) {
        await runHostDriveAgentRefresh(path, { syncAttached: true });
        onRefreshMounts?.();
        listing = await listOfficeServerDirectory(path, 120_000);
      }
      if (!listing?.ok) {
        setBrowseError(listing?.error || `Could not open ${path}`);
        setBrowsePath(path);
        setBrowseEntries([]);
        return;
      }
      setBrowsePath(listing.path || path);
      setBrowseEntries((listing.entries || []).filter((e) => !HIDDEN_DIR_RE.test(e.name)));
    } finally {
      setBrowseLoading(false);
    }
  }

  async function openWindowsLetter(letter: string) {
    await openWindowsPath(`${letter.replace(/:$/, "").toUpperCase()}:\\`);
  }

  useEffect(() => {
    if (!open || !windowsVolumes.length || browsePath) return;
    const pick = recommended.find((letter) => letter !== "C");
    if (!pick) return;
    void openWindowsLetter(pick);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [open, windowsVolumes, recommendedKey, browsePath]);

  async function openWindowsFolder(name: string) {
    if (!browsePath) return;
    await openWindowsPath(joinWindowsPath(browsePath, name));
  }

  function addFolder(next: StagedEvidenceFolder) {
    setFolders([next]);
    setActiveFolderId(next.id);
  }

  function useWindowsFolder() {
    if (!browsePath) return;
    const name = browsePath.replace(/[\\/]+$/, "").split(/[\\/]/).pop() || browsePath;
    const files = browseEntries
      .filter((e) => e.kind === "file")
      .map((e) => ({
        name: e.name,
        relativePath: e.name,
        size: e.size_bytes || 0,
        isSegment: SEGMENT_FILE_RE.test(e.name),
      }));
    addFolder({
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      name,
      hostPath: browsePath,
      files,
      intake: "office",
    });
  }

  function removeFolder(id: string) {
    setFolders((prev) => prev.filter((f) => f.id !== id));
    if (activeFolderId === id) setActiveFolderId(null);
  }

  const activeFolder = folders.find((f) => f.id === activeFolderId) || folders[0] || null;
  const allFiles = folders.flatMap((f) => f.files.map((file) => ({ ...file, folderId: f.id, folderName: f.name })));
  const segmentCount = allFiles.filter((f) => f.isSegment).length;

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Select evidence directory"
      size="lg"
      draggable
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>Cancel</Button>
          <Button variant="brand" disabled={!folders.length} onClick={() => onConfirm(folders)}>
            Start extraction
          </Button>
        </>
      }
    >
      <div className="space-y-4 text-sm text-ink-700">
        <div className="space-y-1">
          <p className="font-semibold text-ink-800">Choose the directory that contains the evidence.</p>
          <p className="text-ink-600">
            Select any HDD, SSD, USB/pendrive, external drive or mapped network drive available in this local environment.
            The selected directory is read in place; the source is not duplicated before processing.
          </p>
        </div>

        <div className="space-y-2 rounded-xl border border-ink-300 bg-white px-3 py-2.5">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <p className="text-[11px] font-semibold uppercase tracking-wide text-ink-500">
                Server drives — HDD / SSD / USB / network — process in place
              </p>
              <p className="mt-0.5 text-[11px] text-ink-500">
                Detection is read-only. Selecting a drive does not upload or copy evidence and does not restart Docker.
              </p>
              <p className="mt-0.5 text-[11px] text-ink-500">
                HostDrive helper: {helperKnownOnline ? "online" : helperOnline === false ? "offline" : "checking…"}
              </p>
            </div>
            <div className="flex flex-wrap gap-1.5">
              <Button
                variant="outline"
                className="h-7 text-xs"
                loading={drivesLoading}
                onClick={() => void loadDrives()}
              >
                Refresh server drives
              </Button>
              {!windowsVolumes.length && !helperKnownOnline && onStartAgent ? (
                <Button
                  variant="outline"
                  className="h-7 text-xs"
                  loading={startingAgent}
                  onClick={() => {
                    void Promise.resolve(onStartAgent()).then(() => loadDrives());
                  }}
                >
                  Start HostDrive helper
                </Button>
              ) : null}
            </div>
          </div>

          {drivesLoading && !windowsVolumes.length ? (
            <p className="text-xs text-ink-500">Detecting HDD / SSD / USB / mapped drives…</p>
          ) : null}

          {browseError ? (
            <div className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-900">
              {browseError}
            </div>
          ) : null}

          {windowsVolumes.length ? (
            <div className="flex flex-wrap gap-1.5">
              {sortVolumes(windowsVolumes, recommended).map((vol) => {
                const letter = vol.letter.toUpperCase();
                const active = Boolean(browsePath?.toUpperCase().startsWith(`${letter}:`));
                const suggested = recommended.includes(letter);
                return (
                  <button
                    key={letter}
                    type="button"
                    onClick={() => void openWindowsLetter(letter)}
                    className={`inline-flex items-center gap-1 rounded-full border px-2.5 py-1 text-xs ${
                      active
                        ? "border-brand-400 bg-brand-50 font-semibold text-brand-900"
                        : suggested
                          ? "border-brand-500 bg-brand-50 font-semibold text-brand-900"
                          : "border-ink-300 bg-white text-ink-700 hover:bg-brand-50/60"
                    }`}
                  >
                    <HardDrive className="h-3.5 w-3.5 text-brand-600" />
                    {letter}:{vol.label ? <span className="text-ink-500">{vol.label}</span> : null}
                    {suggested ? <span className="text-brand-800">new</span> : null}
                  </button>
                );
              })}
            </div>
          ) : null}

          {browsePath ? (
            <div className="space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="font-mono text-[11px] text-ink-800">{browsePath}</p>
                <div className="flex gap-1">
                  {/^[A-Za-z]:\\/.test(browsePath) && browsePath.replace(/[\\/]+$/, "").length > 3 ? (
                    <Button
                      variant="ghost"
                      className="h-7 text-xs"
                      onClick={() => {
                        const parent = browsePath.replace(/[\\/]+$/, "").replace(/[\\/][^\\/]+$/, "");
                        void openWindowsPath(parent.endsWith(":") ? `${parent}\\` : parent);
                      }}
                    >
                      Up
                    </Button>
                  ) : null}
                  <Button variant="brand" className="h-7 text-xs" onClick={useWindowsFolder}>
                    Use this directory
                  </Button>
                </div>
              </div>

              {browseLoading ? (
                <p className="text-xs text-ink-400">Reading directory…</p>
              ) : (
                <ul className="max-h-44 overflow-y-auto divide-y divide-ink-50 rounded-lg border border-ink-200">
                  {browseEntries.filter((e) => e.kind === "dir").map((entry) => (
                    <li key={`dir-${entry.name}`}>
                      <button
                        type="button"
                        className="flex w-full items-center gap-2 px-2.5 py-1.5 text-left text-xs hover:bg-brand-50/70"
                        onClick={() => void openWindowsFolder(entry.name)}
                      >
                        <FolderOpen className="h-3.5 w-3.5 text-amber-500" />
                        {entry.name}
                      </button>
                    </li>
                  ))}
                  {browseEntries.filter((e) => e.kind === "file").slice(0, 40).map((entry) => (
                    <li key={`file-${entry.name}`} className="flex items-center gap-2 px-2.5 py-1.5 text-xs text-ink-600">
                      <span className="truncate">{entry.name}</span>
                      {SEGMENT_FILE_RE.test(entry.name) ? (
                        <span className="rounded bg-brand-100 px-1 text-[10px] text-brand-800">evidence</span>
                      ) : null}
                    </li>
                  ))}
                  {!browseEntries.length ? (
                    <li className="px-2.5 py-2 text-xs text-ink-400">Directory is empty.</li>
                  ) : null}
                </ul>
              )}
            </div>
          ) : null}
        </div>

        <div className="space-y-3 rounded-xl border border-ink-300 bg-gradient-to-b from-white to-brand-50/40 p-3 shadow-panel">
          <p className="text-xs font-semibold uppercase tracking-wide text-ink-500">Selected directory</p>
          {!activeFolder ? (
            <div className="rounded-lg border border-dashed border-ink-300 bg-white px-4 py-6 text-center text-sm text-ink-500">
              Select a drive, open the required directory, then click <strong>Use this directory</strong>.
            </div>
          ) : (
            <>
              <div className="flex items-center justify-between gap-3 rounded-lg border border-brand-200 bg-brand-50/70 px-3 py-2">
                <div className="min-w-0">
                  <p className="truncate font-semibold text-brand-900">{activeFolder.name}</p>
                  <p className="truncate font-mono text-[11px] text-brand-800">{activeFolder.hostPath}</p>
                </div>
                <button type="button" onClick={() => removeFolder(activeFolder.id)} className="rounded p-1 text-ink-400 hover:bg-white hover:text-red-600" aria-label="Remove selected directory">
                  <X className="h-4 w-4" />
                </button>
              </div>

              <div>
                <div className="mb-1.5 flex flex-wrap items-center justify-between gap-2 text-xs text-ink-500">
                  <span>
                    Files: <span className="font-medium text-ink-700">{activeFolder.files.length.toLocaleString()}</span>
                    {segmentCount > 0 ? <span className="ml-2 text-brand-700">{segmentCount} evidence file(s)</span> : null}
                  </span>
                  <span className="text-[11px] text-ink-400">Showing {FILE_ROW_VISIBLE} rows — scroll for more</span>
                </div>
                <div className="overflow-auto rounded-xl border border-ink-300 bg-white/80" style={{ maxHeight: FILE_LIST_MAX_H }}>
                  <table className="w-full text-left text-xs">
                    <thead className="table-head sticky top-0 text-[10px] uppercase tracking-wide text-ink-700">
                      <tr>
                        <th className="px-2 py-1.5">Name</th>
                        <th className="px-2 py-1.5">Path</th>
                        <th className="px-2 py-1.5 text-right">Size</th>
                      </tr>
                    </thead>
                    <tbody>
                      {activeFolder.files.map((file) => (
                        <tr key={`${activeFolder.id}-${file.relativePath}`} className="border-t border-ink-100">
                          <td className="max-w-[10rem] truncate px-2 py-1.5 font-medium text-ink-800">{file.name}</td>
                          <td className="max-w-[14rem] truncate px-2 py-1.5 text-ink-500" title={file.relativePath}>{file.relativePath}</td>
                          <td className="whitespace-nowrap px-2 py-1.5 text-right text-ink-500">{formatBytes(file.size)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            </>
          )}
        </div>

        <p className="text-xs text-ink-500">
          Select the evidence directory from the available local drives. Processing starts from that directory without a separate download step.
        </p>
      </div>
    </Modal>
  );
}

interface ResolveFolderErrorDialogProps {
  open: boolean;
  message: string;
  segmentCount?: number;
  helperOnline?: boolean | null;
  onClose: () => void;
  onRefreshMounts?: () => void;
  onUsePastePath: () => void;
  refreshing?: boolean;
}

export function ResolveFolderErrorDialog({
  open,
  message,
  segmentCount,
  onClose,
  onUsePastePath,
}: ResolveFolderErrorDialogProps) {
  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Could not open that directory"
      size="lg"
      draggable
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>Close</Button>
          <Button variant="brand" onClick={onUsePastePath}>Choose directory again</Button>
        </>
      }
    >
      <div className="space-y-4 text-sm text-ink-700">
        <p>{message}</p>
        {segmentCount ? (
          <p className="text-ink-600">Detected <strong>{segmentCount}</strong> evidence file{segmentCount === 1 ? "" : "s"}.</p>
        ) : null}
        <p className="text-ink-600">
          Refresh the available drives, open the evidence directory again, and retry. The application will read the selected directory in place.
        </p>
      </div>
    </Modal>
  );
}
