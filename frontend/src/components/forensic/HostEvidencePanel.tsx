import { forwardRef, useCallback, useEffect, useImperativeHandle, useRef, useState } from "react";

import {
  AlertCircle,
  ChevronRight,
  Folder,
  FolderOpen,
  HardDrive,
  RefreshCw,
  Smartphone,
  Usb,
} from "lucide-react";

import { Button } from "../ui";
import { BrowseFolderDialog, ResolveFolderErrorDialog, type StagedEvidenceFolder } from "./BrowseFolderDialog";
import { forensicApi } from "../../lib/forensicApi";
import { jobUploadSession } from "../../lib/jobUploadSession";
import {
  ensureHostDriveHelper,
  ensureOfficePathMounted,
  friendlyMobileAcquireError,
  getCachedHelperOnline,
  helperOfflineRetryInMs,
  hostDriveHelperHealth,
  hostDriveHelperInstallHint,
  invalidateHelperHealthCache,
  listHostDriveLetters,
  listHostMobileDevices,
  mobileAttachHostLabel,
  mobileKindLabel,
  runHostDriveAgentRefresh,
  startHostDriveAgentFromBrowser,
  resolveFolderOnHost,
  startMobileAcquisition,
  type HostDriveVolume,
  type HostMobileDevice,
  listHostAcquisitionJobs,
  isUsbCollectionBusyError,
} from "../../lib/hostDriveHelper";
import { UsbCollectionBusyBanner } from "./StopUsbCollectionButton";
import { ApiError } from "../../lib/api";
import { useToast } from "../../lib/toast";

type HostSourceType = "disk" | "mobile" | "ios_backup" | "android_backup";

/** Light cleanup only — spelling / near-miss folder names are resolved on the API for any path. */
function normalizeEvidencePath(hostPath: string): string {
  return hostPath.trim().replace(/[/\\]+$/, "").replace(/[/\\]D$/i, "");
}

/** True when Docker likely needs a remount of a Windows drive that the helper can see. */
function isDockerMountError(message: string): boolean {
  return /not mounted|missing \/host|not found inside Docker|Drive [A-Za-z]: is visible|empty stub|not the Windows volume|could not read the selected path|Automatic Docker mount|Path not found:\s*[A-Za-z]:/i.test(
    message
  );
}

function isPlaceholderEvidencePath(hostPath: string): boolean {
  const n = normalizeEvidencePath(hostPath).replace(/\//g, "\\").toLowerCase();
  return (
    n === "d:\\evidence\\casename\\segments" ||
    n === "d:\\path\\to\\your\\e01-folder" ||
    n === "choose a folder — the path appears here" ||
    /\\casename\\/i.test(n) ||
    /\\path\\to\\your\\/i.test(n)
  );
}

function evidenceFolderStorageKey(jobId: string): string {
  return `polaron.evidenceFolder.${jobId}`;
}

function rememberEvidenceFolder(jobId: string, hostPath: string): void {
  const normalized = normalizeEvidencePath(hostPath);
  if (!normalized || isPlaceholderEvidencePath(normalized)) return;
  try {
    sessionStorage.setItem(evidenceFolderStorageKey(jobId), normalized);
  } catch {
    /* ignore quota / private mode */
  }
}

function recalledEvidenceFolder(jobId: string): string {
  try {
    return (sessionStorage.getItem(evidenceFolderStorageKey(jobId)) || "").trim();
  } catch {
    return "";
  }
}

interface BrowseEntry {
  name: string;
  kind: string;
  size_bytes: number | null;
  selectable: boolean;
  ios_backup: boolean;
  android_backup: boolean;
  segment_base: string | null;
  segment_part: number | null;
  segment_set: string[];
  segment_count: number;
  drive_key?: string | null;
  mounted?: boolean;
  volume_label?: string | null;
  drive_type?: string | null;
}

interface HostDrive {
  key: string;
  label: string;
  host_path: string;
  container_path: string;
}

interface HostBrowse {
  configured: boolean;
  host_evidence_path: string;
  host_root: string;
  drive_root: string;
  current_path: string;
  display_path: string;
  parent_path: string | null;
  entries: BrowseEntry[];
  folder_segment_count: number;
  folder_segments: string[];
  drives: HostDrive[];
  error: string | null;
  mount_hint: string | null;
}

interface HostEvidencePanelProps {
  jobId: string;
  onRegistered?: () => void;
  onProcessingStarted?: () => void;
  disabled?: boolean;
  autoProcess?: boolean;
  embedded?: boolean;
  highlightStart?: boolean;
  /** Force evidence source (hides chip switcher when set). */
  lockedSourceType?: HostSourceType;
  initialSourceType?: HostSourceType;
  /** Windows folder from a completed live acquire — pre-fill and allow auto-register. */
  initialEvidencePath?: string;
  /** Letters Drive Mount agent attached at Create job. */
  recommendedLetters?: string[];
  capabilityLabel?: string | null;
  mobileOsLabel?: string | null;
  /** Live USB-device acquisition belongs to the Device → Image workflow, not package import. */
  allowLiveMobileAcquisition?: boolean;
  onRegisterProgress?: (state: {
    active: boolean;
    pct: number;
    fileName: string;
    phase?: "idle" | "mounting" | "listing" | "registering";
  }) => void;
  onRegisterError?: (message: string) => void;
  onProcessingError?: (message: string) => void;
  onReceivingSegmentsStarted?: () => void;
  /** Explicit evidence transport boundary for the parent activity UI. */
  onSourceModeChange?: (mode: "server" | "client") => void;
  onSourceTransportChanged?: (mode: "server" | "client") => void;
  onEvidenceOriginChange?: (mode: "server" | "client") => void;
}

export type HostEvidencePanelHandle = {
  openEvidenceFolder: () => void;
  /** Remount and re-register the last folder, or open the picker if none is saved. */
  registerManualPath: () => void;
  /** Register an already-known host folder (live acquire working copy). */
  registerHostPath: (hostPath: string) => Promise<void>;
  focusPanel: () => void;
};

function formatBytes(bytes: number | null | undefined): string {
  if (bytes == null) return "—";
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 ** 2) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 ** 3) return `${(bytes / 1024 ** 2).toFixed(1)} MB`;
  return `${(bytes / 1024 ** 3).toFixed(2)} GB`;
}

function hostVolumeMap(volumes: HostDriveVolume[] = []): Map<string, HostDriveVolume> {
  return new Map(volumes.map((v) => [v.letter.toLowerCase(), v]));
}

function driveSortRank(key: string, vol?: HostDriveVolume): number {
  if (vol?.drive_type === "removable") return 0;
  if (key !== "c" && vol?.drive_type === "fixed") return 1;
  if (vol?.drive_type === "network") return 2;
  if (key === "c") return 4;
  return 3;
}

function driveTypeBadge(vol?: HostDriveVolume): string | null {
  if (!vol) return null;
  if (vol.drive_type === "removable") return "USB";
  if (vol.drive_type === "network") return "Network";
  if (vol.drive_type === "fixed" && vol.letter.toLowerCase() !== "c") return "External SSD/HDD";
  return null;
}

function driveDisplayLabel(entry: BrowseEntry, vol?: HostDriveVolume): string {
  const label = vol?.label?.trim();
  if (label) return `${entry.name} · ${label}`;
  return entry.name;
}

function enrichDriveEntry(entry: BrowseEntry, vol?: HostDriveVolume): BrowseEntry {
  return {
    ...entry,
    volume_label: vol?.label?.trim() || null,
    drive_type: vol?.drive_type || null,
  };
}

function mergeHostDrivesIntoBrowse(
  res: HostBrowse,
  hostLetters: string[],
  volumes: HostDriveVolume[] = []
): HostBrowse {
  if (res.drive_root || res.current_path) return res;
  const volMap = hostVolumeMap(volumes);
  const byKey = new Map(
    res.entries
      .filter((e) => e.kind === "drive")
      .map((e) => [(e.drive_key ?? e.name.replace(/:$/, "")).toLowerCase(), e])
  );
  const driveEntries: BrowseEntry[] = hostLetters.map((letter) => {
    const key = letter.replace(":", "").toLowerCase();
    const vol = volMap.get(key);
    const existing = byKey.get(key);
    const base: BrowseEntry =
      existing ??
      ({
        name: `${key.toUpperCase()}:`,
        kind: "drive",
        size_bytes: vol?.size_bytes ?? null,
        selectable: false,
        ios_backup: false,
        android_backup: false,
        segment_base: null,
        segment_part: null,
        segment_set: [],
        segment_count: 0,
        drive_key: key,
        mounted: false,
      } as BrowseEntry);
    return enrichDriveEntry(
      { ...base, size_bytes: base.size_bytes ?? vol?.size_bytes ?? null },
      vol
    );
  });
  driveEntries.sort((a, b) => {
    const ak = (a.drive_key ?? a.name.replace(/:$/, "")).toLowerCase();
    const bk = (b.drive_key ?? b.name.replace(/:$/, "")).toLowerCase();
    return driveSortRank(ak, volMap.get(ak)) - driveSortRank(bk, volMap.get(bk));
  });
  const other = res.entries.filter((e) => e.kind !== "drive");
  return {
    ...res,
    entries: [...driveEntries, ...other],
  };
}

function isBrowseRoot(opts?: { drive?: string; path?: string; hostPath?: string }) {
  return !opts?.hostPath && !(opts?.drive ?? "").trim() && !(opts?.path ?? "").trim();
}

function joinPath(base: string, name: string): string {
  return base ? `${base}/${name}` : name;
}

function isWholeDriveLabel(label: string): boolean {
  const trimmed = label.replace(/\\/g, "").trim();
  return /^[A-Za-z]:?$/.test(trimmed);
}

function isAbsoluteEvidencePath(raw: string | null | undefined): boolean {
  const t = (raw || "").trim();
  if (!t || isPlaceholderEvidencePath(t)) return false;
  if (/^[A-Za-z]:[\\/]/.test(t)) return true;
  if (t.startsWith("\\\\") || t.startsWith("//")) return true;
  return t.startsWith("/") && t.length > 1;
}

const SEGMENT_FILE_RE =
  /\.(?:E\d{2}|e\d{2}|001|002|003|004|005|006|007|008|009|dd|raw|aff|aff4|vmdk|vhdx|pas(?:\d+)?|ufd|ufdt|ufdx|zip)$/i;

function isHostSegmentSource(sourceType: HostSourceType): boolean {
  return sourceType === "disk" || sourceType === "mobile";
}

function isSegmentFilename(name: string): boolean {
  return SEGMENT_FILE_RE.test(name);
}

function shouldRefuseBrowserCopy(files: Array<{ name: string; size?: number }>, sourceType: HostSourceType): boolean {
  // Client upload is the default path (LAN or internet). Never block disk images.
  void files;
  void sourceType;
  return false;
}

function isWorkstationPath(value: string): boolean {
  const trimmed = value.trim();
  return trimmed.length > 0 && trimmed !== "This PC";
}

export const HostEvidencePanel = forwardRef<HostEvidencePanelHandle, HostEvidencePanelProps>(
  function HostEvidencePanel(
    {
      jobId,
      onRegistered,
      onProcessingStarted,
      disabled,
      autoProcess = false,
      embedded = false,
      highlightStart = false,
      lockedSourceType,
      initialSourceType,
      initialEvidencePath,
      recommendedLetters,
      capabilityLabel,
      mobileOsLabel,
      allowLiveMobileAcquisition = false,
      onRegisterProgress,
      onRegisterError,
      onProcessingError,
      onReceivingSegmentsStarted,
      onSourceModeChange,
      onSourceTransportChanged,
      onEvidenceOriginChange,
    },
    ref
  ) {
  const toast = useToast();
  const toastRef = useRef(toast);
  toastRef.current = toast;

  const emitSourceMode = useCallback((mode: "server" | "client") => {
    if (mode === "server") {
      onSourceModeChange?.("server");
      onSourceTransportChanged?.("server");
      onEvidenceOriginChange?.("server");
    } else {
      onSourceModeChange?.("client");
      onSourceTransportChanged?.("client");
      onEvidenceOriginChange?.("client");
    }
  }, [onEvidenceOriginChange, onSourceModeChange, onSourceTransportChanged]);
  const panelRef = useRef<HTMLDivElement>(null);
  const browserRef = useRef<HTMLDivElement>(null);
  const [loading, setLoading] = useState(false);
  const [registering, setRegistering] = useState(false);
  const [remounting, setRemounting] = useState(false);
  const remountingRef = useRef(false);
  const [startingAgent, setStartingAgent] = useState(false);
  const [helperOnline, setHelperOnline] = useState<boolean | null>(null);
  const [manualPath, setManualPath] = useState((initialEvidencePath || "").trim());
  const lastRegisteredPathRef = useRef((initialEvidencePath || "").trim());

  useEffect(() => {
    const next = (initialEvidencePath || "").trim();
    if (!next || isPlaceholderEvidencePath(next)) return;
    lastRegisteredPathRef.current = lastRegisteredPathRef.current || next;
    setManualPath((prev) => prev || next);
    rememberEvidenceFolder(jobId, next);
  }, [initialEvidencePath, jobId]);
  const [mobileDevices, setMobileDevices] = useState<HostMobileDevice[]>([]);
  const [mobileDevicesLoading, setMobileDevicesLoading] = useState(false);
  const [selectedMobileDevice, setSelectedMobileDevice] = useState<HostMobileDevice | null>(null);
  const [acquiring, setAcquiring] = useState(false);
  const [usbBusy, setUsbBusy] = useState(false);
  const [sourceType, setSourceType] = useState<HostSourceType>(
    lockedSourceType || initialSourceType || "disk"
  );
  // Imported mobile packages also use sourceType="mobile". Keep them separate
  // from live USB acquisition so package import always gets the server drive
  // folder browser instead of a Windows file Open dialog or connected-device UI.
  const isLiveMobileSource = sourceType === "mobile" && allowLiveMobileAcquisition;
  const isMobileEvidenceSource = sourceType !== "disk";

  useEffect(() => {
    if (lockedSourceType) {
      setSourceType(lockedSourceType);
    }
  }, [lockedSourceType]);

  useEffect(() => {
    let cancelled = false;
    async function tick() {
      const jobs = await listHostAcquisitionJobs();
      if (cancelled) return;
      if (jobs.some((j) => String(j.status || "").toLowerCase() === "running")) {
        setUsbBusy(true);
      }
    }
    void tick();
    const id = window.setInterval(() => void tick(), 8000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, []);
  const [browse, setBrowse] = useState<HostBrowse | null>(null);
  const [currentDrive, setCurrentDrive] = useState("");
  const [browsePath, setBrowsePath] = useState("");
  const [selectedSegments, setSelectedSegments] = useState<Set<string>>(new Set());
  const [selectionLabel, setSelectionLabel] = useState<string | null>(null);
  const [browseDialogOpen, setBrowseDialogOpen] = useState(false);
  const [resolveError, setResolveError] = useState<{
    open: boolean;
    message: string;
    segmentCount: number;
  }>({ open: false, message: "", segmentCount: 0 });

  const lastHostDrivesRef = useRef("");
  const lastAutoRemountRef = useRef("");
  const lastDriveMountErrorRef = useRef<string | null>(null);
  const syncInFlightRef = useRef(false);
  const pendingResolveRef = useRef<{
    filenames: string[];
    folderHint?: string | null;
    relativePaths?: string[];
  } | null>(null);

  const fetchBrowse = useCallback(
    async (opts?: {
      drive?: string;
      path?: string;
      hostPath?: string;
      timeoutMs?: number;
    }): Promise<HostBrowse> => {
      return forensicApi.browseHostEvidence(
        jobId,
        {
          drive: opts?.drive ?? "",
          path: opts?.path ?? "",
          host_path: opts?.hostPath,
          source_type: sourceType,
        },
        { timeoutMs: opts?.timeoutMs }
      ) as Promise<HostBrowse>;
    },
    [jobId, sourceType]
  );

  const applyBrowse = useCallback((res: HostBrowse, opts?: { keepSelection?: boolean }) => {
    setBrowse(res);
    setCurrentDrive(res.drive_root || "");
    setBrowsePath(res.current_path);
    if (isWorkstationPath(res.display_path)) {
      setManualPath(res.display_path);
    } else if (res.drive_root && res.current_path) {
      setManualPath(`${res.drive_root.toUpperCase()}:\\${res.current_path.replace(/\//g, "\\")}`);
    } else if (res.drive_root && !res.current_path) {
      setManualPath(`${res.drive_root.toUpperCase()}:\\`);
    }
    if (!opts?.keepSelection) {
      setSelectedSegments(new Set());
      setSelectionLabel(null);
    }
  }, []);

  const loadBrowse = useCallback(
    async (opts?: {
      drive?: string;
      path?: string;
      hostPath?: string;
      keepSelection?: boolean;
      silent?: boolean;
      timeoutMs?: number;
    }) => {
      if (disabled) return null;
      setLoading(true);
      setBrowse((prev) =>
        prev ? { ...prev, error: null, mount_hint: null } : prev
      );
      try {
        let res = await fetchBrowse(opts);
        if (res.error) {
          if (!opts?.silent) {
            toastRef.current.error(res.error);
          }
          setBrowse(res);
          return null;
        }
        if (isBrowseRoot(opts)) {
          // Server-attached HDD/SSD/USB/network drives are discovered through
          // /api/hostdrive first. Do not gate this on the browser PC's localhost
          // helper: a remote LAN browser usually has no helper, while the office
          // forensic server still does.
          const host = await listHostDriveLetters();
          if (host?.drives?.length) {
            res = mergeHostDrivesIntoBrowse(res, host.drives, host.volumes ?? []);
          } else {
            // The container-side catalog has placeholders for A:..Z:. Without
            // the server helper inventory, show only letters that are actually
            // readable instead of 26 false drives.
            res = {
              ...res,
              entries: res.entries.filter((entry) => entry.kind !== "drive" || entry.mounted !== false),
            };
          }
        }
        if (
          !opts?.hostPath &&
          !(opts?.drive ?? "").trim() &&
          res.entries.length === 1 &&
          res.entries[0].kind === "drive" &&
          res.entries[0].drive_key &&
          !isWholeDriveLabel(res.entries[0].name)
        ) {
          const nested = await fetchBrowse({ drive: res.entries[0].drive_key, path: "" });
          applyBrowse(nested, { keepSelection: opts?.keepSelection });
          return nested;
        }
        applyBrowse(res, { keepSelection: opts?.keepSelection });
        return res;
      } catch (e: unknown) {
        setBrowse(null);
        if (!opts?.silent) {
          toastRef.current.error(e instanceof Error ? e.message : "Could not browse host evidence");
        }
        return null;
      } finally {
        setLoading(false);
      }
    },
    [applyBrowse, disabled, fetchBrowse]
  );

  const waitForBrowse = useCallback(
    async (opts?: { drive?: string; path?: string }, attempts = 20) => {
      for (let i = 0; i < attempts; i += 1) {
        // Short timeout so remount waits cannot block Register for minutes.
        const res = await loadBrowse({ ...opts, silent: true, timeoutMs: 12_000 });
        if (res) return res;
        await new Promise((resolve) => setTimeout(resolve, 1500));
      }
      toastRef.current.error("API did not come back after refreshing drive mounts. Try again in a moment.");
      return null;
    },
    [loadBrowse]
  );

  const startHostDriveAgent = useCallback(async () => {
    setStartingAgent(true);
    try {
      toastRef.current.info("Starting HostDrive agent…");
      const health = await startHostDriveAgentFromBrowser(25_000);
      setHelperOnline(Boolean(health?.ok));
      if (health?.ok) {
        toastRef.current.success("HostDrive agent is online");
        return true;
      }
      toastRef.current.error(
        `HostDrive agent still offline. Install once: ${hostDriveHelperInstallHint()}`
      );
      return false;
    } finally {
      setStartingAgent(false);
    }
  }, []);

  const refreshDriveMountsOnHost = useCallback(
    async (driveKey?: string, opts?: { light?: boolean; requiredPath?: string }) => {
      remountingRef.current = true;
      setRemounting(true);
      setHelperOnline(true);
      try {
        invalidateHelperHealthCache();
        toastRef.current.info(
          "HostDrive agent: detecting drives and refreshing Docker mounts…"
        );
        const result = await runHostDriveAgentRefresh(
          opts?.requiredPath,
          { syncAttached: !opts?.requiredPath }
        );
        if (!result.ok) {
          lastDriveMountErrorRef.current = result.error ?? "Drive mount refresh failed";
          // The helper can be healthy while Docker Desktop refuses a particular drive.
          // Keep helper health separate from mount status so the UI does not report it offline.
          setHelperOnline(true);
          toastRef.current.error(result.error ?? "Drive mount refresh failed");
          return false;
        }
        setHelperOnline(true);
        lastDriveMountErrorRef.current = null;
        toastRef.current.success(result.message ?? "Drive mounts refreshed");
        const host = await listHostDriveLetters();
        if (host?.drives?.length) {
          lastHostDrivesRef.current = host.drives.join(",");
        } else if (result.drives?.length) {
          lastHostDrivesRef.current = result.drives.join(",");
        }
        // Light mode (Register & start): runHostDriveAgentRefresh(requiredPath) only
        // returns ok after the refresh job has recreated the forensic services,
        // waited for API health, and verified the exact selected Windows path
        // inside the API container. Do NOT perform a second root browse here:
        // root browsing can fail because of an unrelated drive and previously
        // produced a false "Docker could not mount" error even when the selected
        // evidence path was already mounted correctly.
        if (opts?.light) {
          return true;
        }
        const refreshed = await waitForBrowse({ drive: "", path: "" }, 40);
        if (!refreshed) return false;
        if (driveKey) {
          setCurrentDrive(driveKey);
          const opened = await waitForBrowse({ drive: driveKey, path: "" }, 20);
          if (!opened) return false;
        }
        return true;
      } finally {
        remountingRef.current = false;
        setRemounting(false);
        void hostDriveHelperHealth(1500, { force: true }).then((h) =>
          setHelperOnline(Boolean(h?.ok))
        );
      }
    },
    [waitForBrowse]
  );

  const syncDriveMountsIfNeeded = useCallback(async () => {
    if (syncInFlightRef.current || remounting || disabled) return false;
    const host = await listHostDriveLetters();
    if (!host?.drives?.length) return false;
    const hostKey = (host.volumes?.length
      ? host.volumes.map((v) => `${String(v.letter || "").toUpperCase()}:${v.mounted === false ? "0" : "1"}`).join(",")
      : host.drives.join(","));

    const snapshot = await fetchBrowse({ drive: "", path: "" });
    const mounted = new Set(
      snapshot.entries
        .filter((e) => e.kind === "drive" && e.mounted !== false)
        .map((e) => (e.drive_key ?? e.name.replace(/:$/, "")).toLowerCase())
    );
    const missing = host.drives.filter(
      (letter) => !mounted.has(letter.replace(":", "").toLowerCase())
    );
    if (!missing.length) {
      lastHostDrivesRef.current = hostKey;
      lastAutoRemountRef.current = "";
      return false;
    }

    // Avoid restarting the forensic containers on every poll when Docker
    // Desktop refuses one specific removable volume. A newly changed drive
    // inventory gets one automatic remount attempt; the Refresh button remains
    // available for an explicit retry.
    if (lastAutoRemountRef.current === hostKey) return false;
    lastAutoRemountRef.current = hostKey;

    syncInFlightRef.current = true;
    try {
      toastRef.current.info(
        `Server drive(s) ${missing.join(", ")} detected — mounting read-only into forensic workers…`
      );
      const ok = await refreshDriveMountsOnHost();
      if (ok) {
        const refreshed = await loadBrowse({ drive: "", path: "", silent: true });
        if (refreshed) lastHostDrivesRef.current = hostKey;
      }
      return ok;
    } finally {
      syncInFlightRef.current = false;
    }
  }, [disabled, fetchBrowse, loadBrowse, refreshDriveMountsOnHost, remounting]);

  const prepareForFolderSelect = useCallback(async (opts?: { force?: boolean }) => {
    const health = await ensureHostDriveHelper(
      opts?.force ? 8_000 : 2_000,
      1_500,
      { force: opts?.force }
    );
    setHelperOnline(Boolean(health?.ok));
    if (health?.ok) {
      await syncDriveMountsIfNeeded();
    }
    return Boolean(health?.ok);
  }, [syncDriveMountsIfNeeded]);

  const refreshMobileDevices = useCallback(async () => {
    if (!isLiveMobileSource || disabled) {
      setMobileDevices([]);
      return [];
    }
    setMobileDevicesLoading(true);
    try {
      const health = await hostDriveHelperHealth(1500, { force: true });
      setHelperOnline(Boolean(health?.ok));
      const dedicated = await listHostMobileDevices(8_000);
      let devices = dedicated?.mobile_devices ?? [];
      if (!devices.length) {
        const fromDrives = await listHostDriveLetters();
        devices = fromDrives?.mobile_devices ?? [];
      }
      setMobileDevices(devices);
      return devices;
    } finally {
      setMobileDevicesLoading(false);
    }
  }, [disabled, isLiveMobileSource]);

  const onSelectConnectedMobileDevice = useCallback((device: HostMobileDevice) => {
    const os = mobileKindLabel(device.os_hint);
    const where = mobileAttachHostLabel(device.attach_host);
    setSelectedMobileDevice(device);
    setSelectionLabel(`${device.name} (${os}, ${where})`);
    toastRef.current.info(
      device.os_hint === "ios"
        ? `${device.name} selected. Unlock, enter passcode when prompted, Trust This Computer — then Start extraction for a full iOS backup image (UFED Advanced Logical equivalent).`
        : `${device.name} selected. Click Start extraction to create a logical image under forensic-mobile-acquisitions\\{job_id}.`
    );
  }, []);

  useEffect(() => {
    if (!isLiveMobileSource || !mobileDevices.length) return;
    if (selectedMobileDevice) {
      const stillThere = mobileDevices.some((d) => d.id === selectedMobileDevice.id);
      if (stillThere) return;
    }
    onSelectConnectedMobileDevice(mobileDevices[0]);
  }, [isLiveMobileSource, mobileDevices, selectedMobileDevice, onSelectConnectedMobileDevice]);

  useEffect(() => {
    if (!embedded || !autoProcess) return;
    void hostDriveHelperHealth(1200).then((health) => setHelperOnline(Boolean(health?.ok)));
  }, [embedded, autoProcess, jobId]);

  useEffect(() => {
    if (!isLiveMobileSource || disabled) return;
    void refreshMobileDevices();
    const id = window.setInterval(() => void refreshMobileDevices(), 8_000);
    return () => window.clearInterval(id);
  }, [isLiveMobileSource, disabled, jobId, refreshMobileDevices]);

  useEffect(() => {
    // Only live phone acquisition can use the compact auto-process view. Disk
    // and backup evidence must still expose the forensic server's HDD/SSD/USB
    // browser even when JobDetail embeds this panel with autoProcess enabled.
    if (embedded && autoProcess && isLiveMobileSource) return;
    void (async () => {
      const health = await hostDriveHelperHealth(1200);
      const online = Boolean(health?.ok);
      setHelperOnline(online);
      if (!isLiveMobileSource) {
        // The folder browser reads the forensic server's mounted/removable/network
        // drives through /api/hostdrive. It must be available even when this UI
        // is opened from another workstation on the server-side LAN.
        await loadBrowse({ drive: "", path: "", silent: true });
        await syncDriveMountsIfNeeded();
      }
    })();
  }, [jobId, sourceType, loadBrowse, embedded, autoProcess, isLiveMobileSource, syncDriveMountsIfNeeded]);

  useEffect(() => {
    let cancelled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;

    const schedule = () => {
      const waitMs =
        getCachedHelperOnline() === true
          ? 120_000
          : Math.max(helperOfflineRetryInMs(), 60_000);
      timer = setTimeout(async () => {
        if (cancelled) return;
        // Don't flip Health down while docker compose remounts drives.
        if (remountingRef.current) {
          if (!cancelled) schedule();
          return;
        }
        const health = await hostDriveHelperHealth(1200);
        if (!cancelled) {
          setHelperOnline(Boolean(health?.ok));
        }
        if (!cancelled) schedule();
      }, waitMs);
    };

    schedule();

    return () => {
      cancelled = true;
      if (timer) clearTimeout(timer);
    };
  }, [jobId]);

  useEffect(() => {
    if (disabled || isLiveMobileSource) return;
    let cancelled = false;
    const pollExternalDrives = async () => {
      if (cancelled) return;
      // listHostDriveLetters() checks the office/server API before localhost, so
      // remote examiner browsers can detect a newly attached server HDD too.
      await syncDriveMountsIfNeeded();
    };
    const id = window.setInterval(() => void pollExternalDrives(), 30_000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [disabled, syncDriveMountsIfNeeded, isLiveMobileSource]);

  const scrollToBrowser = useCallback(() => {
    browserRef.current?.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }, []);

  const beginReceivingSegments = useCallback(() => {
    onReceivingSegmentsStarted?.();
  }, [onReceivingSegmentsStarted]);

  const uploadClientFiles = useCallback(
    async (incoming: File[]) => {
      if (!incoming.length) return;
      if (shouldRefuseBrowserCopy(incoming, sourceType)) {
        const msg =
          "Could not upload that folder from this browser. Choose the image folder on this computer and try again.";
        onRegisterError?.(msg);
        toastRef.current.error(msg);
        return;
      }
      const segmentFiles = incoming.filter((f) => isSegmentFilename(f.name));
      const toUpload =
        isHostSegmentSource(sourceType) && segmentFiles.length ? segmentFiles : incoming;
      // Browser/File API evidence is the client-transfer path. Only this path
      // may expose Download Agent / Upload Activity.
      emitSourceMode("client");
      // jobUploadSession starts the server-side Download Agent gate before the
      // first byte. If that gate cannot be established, the upload fails closed
      // and no extraction/RAG/report action is allowed to start.
      beginReceivingSegments();
      setRegistering(true);
      onRegisterProgress?.({
        active: true,
        pct: 5,
        fileName: incoming[0]?.name || "upload",
        phase: "registering",
      });
      const totalBytes = toUpload.reduce((sum, f) => sum + (f.size || 0), 0);
      if (totalBytes >= 8 * 1024 * 1024 * 1024) {
        toastRef.current.info(
          `Uploading ${(totalBytes / (1024 * 1024 * 1024)).toFixed(1)} GB from this computer…`
        );
      }
      toastRef.current.info(
        `Download Agent copying ${toUpload.length} file(s), 5 at a time. Other agents wait until this finishes.`
      );
      try {
        jobUploadSession.addQueuedFiles(jobId, toUpload);
        const progressTick = window.setInterval(() => {
          const snap = jobUploadSession.get(jobId);
          const p = snap.progress;
          if (!p) return;
          const pct = Math.round(
            ((p.index + p.filePct / 100) / Math.max(p.total, 1)) * 90
          );
          onRegisterProgress?.({
            active: true,
            pct,
            fileName: p.fileName,
            phase: "registering",
          });
        }, 500);
        try {
          await jobUploadSession.startUpload(jobId, "directory", () => {
            onRegistered?.();
          });
        } finally {
          window.clearInterval(progressTick);
        }
        const snap = jobUploadSession.get(jobId);
        const done = snap.files.filter((f) => f.status === "done").length;
        if (!done) {
          const msg =
            "Upload finished but no evidence was registered. Include .pas / .ufd / .ufdx / .zip or .E01 segments.";
          onRegisterError?.(msg);
          toastRef.current.error(msg);
          return;
        }
        if (autoProcess) {
          onRegisterProgress?.({
            active: true,
            pct: 90,
            fileName: "Starting extract…",
            phase: "registering",
          });
          await forensicApi.processJob(jobId);
          onProcessingStarted?.();
        }
        toastRef.current.success(
          `Verified complete client intake — ${done} file(s) registered; pipeline released`
        );
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : "Upload failed";
        onRegisterError?.(msg);
        toastRef.current.error(msg);
      } finally {
        setRegistering(false);
        onRegisterProgress?.({ active: false, pct: 100, fileName: "", phase: "idle" });
      }
    },
    [
      autoProcess,
      beginReceivingSegments,
      jobId,
      onProcessingStarted,
      onRegisterError,
      onRegisterProgress,
      onRegistered,
      onSourceModeChange,
      sourceType,
    ]
  );

  const resolveFolderFromFilenames = useCallback(
    async (
      filenames: string[],
      opts?: { folderHint?: string | null; relativePaths?: string[] }
    ) => {
      const segments = filenames.filter((name) => isSegmentFilename(name));
      const folderHint = opts?.folderHint?.trim() || undefined;
      if (!filenames.length && !folderHint) {
        toastRef.current.error("That folder has no files to register.");
        return null;
      }
      setLoading(true);
      toastRef.current.info(
        segments.length
          ? `Locating folder from ${segments.length} segment file(s)…`
          : "Locating folder on mounted drives…"
      );
      try {
        const payload = {
          filenames: segments.length ? segments : filenames,
          folder_hint: folderHint,
          relative_paths: opts?.relativePaths,
        };

        const finishResolvedPath = async (resolvedPath: string) => {
          setManualPath(resolvedPath);
          if (autoProcess && isHostSegmentSource(sourceType)) {
            await ingestAtResolvedPath(resolvedPath);
            return resolvedPath;
          }
          let res = await loadBrowse({ hostPath: resolvedPath });
          if (!res) {
            const remounted = await refreshDriveMountsOnHost();
            if (remounted) {
              res = await loadBrowse({ hostPath: resolvedPath });
            }
          }
          scrollToBrowser();
          if (res && isHostSegmentSource(sourceType) && res.folder_segment_count > 0) {
            await registerFolderAt(res);
            return resolvedPath;
          }
          if (res?.folder_segment_count) {
            toastRef.current.success(
              `Selected folder — ${resolvedPath} (${res.folder_segment_count} segments)`
            );
          } else if (res) {
            toastRef.current.success(`Selected folder — ${resolvedPath}`);
          } else {
            await openHostPath(resolvedPath);
          }
          return resolvedPath;
        };

        // Absolute Windows path — skip slow resolve-folder entirely.
        const absWin =
          folderHint && /^[A-Za-z]:[\\/]/.test(folderHint)
            ? folderHint.replace(/\//g, "\\")
            : null;
        if (absWin) {
          await prepareForFolderSelect({ force: true });
          return finishResolvedPath(absWin);
        }

        // Prefer an already-known absolute manual path over deep search.
        const manualAbs = manualPath.trim();
        if (manualAbs && /^[A-Za-z]:[\\/]/.test(manualAbs) && segments.length) {
          await prepareForFolderSelect({ force: true });
          return finishResolvedPath(manualAbs.replace(/\//g, "\\"));
        }

        await prepareForFolderSelect({ force: true });

        const tryResolve = async (): Promise<{ path: string | null; helperMiss?: string }> => {
          try {
            const resolved = await forensicApi.resolveHostFolder(jobId, payload);
            if (resolved.path) return { path: resolved.path };
            if (resolved.error) {
              return { path: null, helperMiss: resolved.error };
            }
          } catch {
            /* office API missed — try localhost helper only when sitting at the host */
          }
          const hostResolved = await resolveFolderOnHost(payload);
          if (hostResolved?.path) return { path: hostResolved.path };
          return {
            path: null,
            helperMiss:
              hostResolved?.error ||
              "Could not locate that folder on the office forensic server. Open an office drive letter in Choose folder.",
          };
        };

        let resolved = await tryResolve();
        if (!resolved.path && !resolved.helperMiss) {
          toastRef.current.info("Refreshing drive mounts and retrying folder location…");
          const remounted = await refreshDriveMountsOnHost();
          if (remounted) {
            resolved = await tryResolve();
          }
        }
        if (resolved.path) {
          return finishResolvedPath(resolved.path);
        }

        pendingResolveRef.current = {
          filenames: segments,
          folderHint,
          relativePaths: opts?.relativePaths,
        };
        const missMsg =
          resolved.helperMiss ||
          "Could not locate that folder on the office forensic server. Open a drive letter in Choose folder (office HostDrive), then Use this folder. Disk images are never copied from this browser.";
        toastRef.current.error(missMsg);
        setResolveError({
          open: true,
          message: missMsg,
          segmentCount: segments.length,
        });
        onRegisterError?.(missMsg);
        return null;
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : "Could not resolve folder path";
        onRegisterError?.(msg);
        toastRef.current.error(msg);
        return null;
      } finally {
        setLoading(false);
      }
    },
    [jobId, loadBrowse, scrollToBrowser, sourceType, autoProcess, prepareForFolderSelect, refreshDriveMountsOnHost, onRegisterError, manualPath]
  );

  const openNativeFolderPicker = useCallback(async () => {
    if (disabled || registering || acquiring) return;
    setBrowseDialogOpen(true);
  }, [acquiring, disabled, registering]);

  const confirmStagedBrowseFolders = useCallback(
    async (folders: StagedEvidenceFolder[]) => {
      setBrowseDialogOpen(false);
      if (!folders.length) return;
      // Do not open the pipeline modal yet. registerPickedFolder ->
      // ingestAtResolvedPath first verifies the exact selected path in Docker.
      for (const folder of folders) {
        await registerPickedFolder(folder);
      }
    },
    []
  );


  async function resolveServerLocalDiskSelection(folder: StagedEvidenceFolder): Promise<boolean> {
    if (sourceType !== "disk") return false;
    const segmentFiles = folder.files.filter((f) => isSegmentFilename(f.name));
    if (!segmentFiles.length) return false;
    const fileSizes = Object.fromEntries(segmentFiles.map((f) => [f.name, f.size]));
    const relativePaths = segmentFiles.map((f) => f.relativePath);
    const payload = {
      filenames: segmentFiles.map((f) => f.name),
      folder_hint: folder.hostPath || folder.name || undefined,
      relative_paths: relativePaths,
      file_sizes: fileSizes,
    };

    toastRef.current.info(
      "Checking the attached/local drives for this evidence before processing starts…"
    );
    try {
      let resolved = await forensicApi.resolveHostFolder(jobId, payload);
      if (!resolved.path) {
        const refreshed = await refreshDriveMountsOnHost();
        if (refreshed) resolved = await forensicApi.resolveHostFolder(jobId, payload);
      }
      if (!resolved.path || !isAbsoluteEvidencePath(resolved.path)) return false;

      if (!jobUploadSession.markServerLocalZeroCopy(jobId)) {
        const msg = "Another evidence transfer is already running for this job. Stop it before selecting a local directory.";
        onRegisterError?.(msg);
        toastRef.current.error(msg);
        return true;
      }
      // Compatibility calls intentionally share the same authoritative event.
      emitSourceMode("server");
      onSourceTransportChanged?.("server");
      onEvidenceOriginChange?.("server");
      jobUploadSession.clearInactiveForServerSource(jobId);
      jobUploadSession.reset(jobId);
      setManualPath(resolved.path);
      toastRef.current.success(
        `Evidence matched by filename and exact size. Processing directly from the selected drive: ${resolved.path}`
      );
      await ingestAtResolvedPath(resolved.path, true);
      return true;
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Server disk lookup failed";
      console.warn("server-local disk resolution failed", msg);
      return false;
    }
  }

  async function registerPickedFolder(folder: StagedEvidenceFolder) {
    if (folder.intake === "office" && folder.hostPath) setManualPath(folder.hostPath);
    else if (folder.name) setManualPath(folder.name);

    const fromThisComputer = folder.intake !== "office";
    if (fromThisComputer) {
      // Disk-image picker can be running on the forensic server itself. Before
      // opening Download Agent, prove whether this exact filename+size set is
      // already present on a server-visible HDD/SSD/USB and process it in place.
      if (sourceType === "disk" && await resolveServerLocalDiskSelection(folder)) return;

      const hostName = typeof window !== "undefined" ? window.location.hostname.toLowerCase() : "";
      const consoleIsOnForensicServer = ["localhost", "127.0.0.1", "::1"].includes(hostName);
      if (sourceType === "disk" && consoleIsOnForensicServer) {
        const msg =
          "Select the evidence directory from the attached/local HDD, SSD, USB or mapped drive. The application processes it in place.";
        onRegisterError?.(msg);
        toastRef.current.error(msg);
        return;
      }

      if (!folder.fileBlobs?.length) {
        const msg =
          "Could not read the selected evidence directory. Choose the folder again and retry.";
        onRegisterError?.(msg);
        toastRef.current.error(msg);
        return;
      }
      emitSourceMode("client");
      onSourceTransportChanged?.("client");
      onEvidenceOriginChange?.("client");
      toastRef.current.info("Preparing the selected evidence directory…");
      await uploadClientFiles(folder.fileBlobs);
      return;
    }

    emitSourceMode("server");
    onSourceTransportChanged?.("server");
    onEvidenceOriginChange?.("server");
    jobUploadSession.clearInactiveForServerSource(jobId);

    const filenames = folder.files.map((f) => f.name);
    const relativePaths = folder.files.map((f) => f.relativePath);
    const segments = filenames.filter((name) => isSegmentFilename(name));
    let resolvedPath = isAbsoluteEvidencePath(folder.hostPath) ? folder.hostPath!.trim() : null;

    if (!resolvedPath) {
      const payload = {
        filenames: segments.length ? segments : filenames,
        folder_hint: folder.hostPath || folder.name || undefined,
        relative_paths: relativePaths,
        file_sizes: Object.fromEntries(folder.files.map((f) => [f.name, f.size])),
      };
      toastRef.current.info("Locating the selected evidence directory…");
      try {
        const apiResolved = await forensicApi.resolveHostFolder(jobId, payload);
        if (apiResolved.path && isAbsoluteEvidencePath(apiResolved.path)) {
          resolvedPath = apiResolved.path;
        }
      } catch {
        /* office resolve missed */
      }
      if (!resolvedPath) {
        const hostResolved = await resolveFolderOnHost(payload);
        if (hostResolved?.path && isAbsoluteEvidencePath(hostResolved.path)) {
          resolvedPath = hostResolved.path;
        }
      }
    }

    if (resolvedPath) {
      setManualPath(resolvedPath);
      toastRef.current.info(`Registering in place from ${resolvedPath} — no copy.`);
      try {
        await ingestAtResolvedPath(resolvedPath, true);
      } catch {
        // ingestAtResolvedPath remounts and retries. Never copy E01s through the browser.
      }
      return;
    }

    toastRef.current.info("Remounting the selected office drive, then locating that folder…");
    await refreshDriveMountsOnHost(undefined, { light: true, requiredPath: folder.hostPath || undefined });
    const retryPayload = {
      filenames: segments.length ? segments : filenames,
      folder_hint: folder.hostPath || folder.name || undefined,
      relative_paths: relativePaths,
    };
    try {
      const apiResolved = await forensicApi.resolveHostFolder(jobId, retryPayload);
      if (apiResolved.path && isAbsoluteEvidencePath(apiResolved.path)) {
        setManualPath(apiResolved.path);
        await ingestAtResolvedPath(apiResolved.path, true);
        return;
      }
    } catch {
      /* fall through */
    }
    const retryHost = await resolveFolderOnHost(retryPayload);
    if (retryHost?.path && isAbsoluteEvidencePath(retryHost.path)) {
      setManualPath(retryHost.path);
      toastRef.current.info(`Registering in place from ${retryHost.path} — no copy.`);
      try {
        await ingestAtResolvedPath(retryHost.path, true);
      } catch {
        /* already surfaced */
      }
      return;
    }

    // The folder originated from the forensic server/office HostDrive source.
    // Never silently convert that source into a browser upload: doing so duplicates
    // E01/EWF segments on the server and violates zero-copy evidence residency.
    const msg =
      "The selected evidence directory is visible on the host but could not be resolved inside the processing container. Refresh drive mounts and retry.";
    onRegisterError?.(msg);
    toastRef.current.error(msg);
  }

  const openEvidenceFolderBrowse = useCallback(async () => {
    await openNativeFolderPicker();
  }, [openNativeFolderPicker]);

  const ingestHostPathRef = useRef<(hostPath: string, allowMountRetry?: boolean) => Promise<void>>(
    async () => undefined,
  );

  useImperativeHandle(ref, () => ({
    openEvidenceFolder: () => {
      void openEvidenceFolderBrowse();
    },
    registerManualPath: () => {
      const saved = (
        lastRegisteredPathRef.current
        || manualPath
        || recalledEvidenceFolder(jobId)
        || ""
      ).trim();
      if (saved && !isPlaceholderEvidencePath(saved)) {
        setManualPath(saved);
        void ingestHostPathRef.current(saved, true).catch(() => undefined);
        return;
      }
      void openEvidenceFolderBrowse();
    },
    registerHostPath: async (hostPath: string) => {
      setManualPath(hostPath);
      await ingestHostPathRef.current(hostPath);
    },
    focusPanel: () => {
      panelRef.current?.scrollIntoView({ behavior: "smooth", block: "start" });
    },
  }), [openEvidenceFolderBrowse, manualPath, jobId]);

  async function ingestAtResolvedPath(hostPath: string, allowMountRetry = true) {
    const normalized = normalizeEvidencePath(hostPath);
    lastRegisteredPathRef.current = normalized;
    rememberEvidenceFolder(jobId, normalized);
    if (normalized !== hostPath.trim()) {
      setManualPath(normalized);
      toastRef.current.info(`Auto-corrected path spelling → ${normalized}`);
    }
    if (isPlaceholderEvidencePath(normalized)) {
      const msg =
        "That path is only an example placeholder. Choose the real folder that contains your .E01 / .E02 segments so it can be registered in place.";
      onRegisterError?.(msg);
      toastRef.current.error(msg);
      return;
    }
    const dumpPath = normalized.replace(/\\/g, "/");
    const looksLikeClientDump =
      /(?:^|\/)(?:data\/)?uploads\//i.test(dumpPath) || dumpPath.includes("/app/data/uploads/");
    if (looksLikeClientDump) {
      emitSourceMode("client");
      setRegistering(true);
      beginReceivingSegments();
      try {
        toastRef.current.info("Registering the client upload dump on the forensic server…");
        const ingest = await forensicApi.completeClientUpload(jobId, false);
        onRegistered?.();
        if (autoProcess && ingest.accepted?.length) {
          await forensicApi.processJob(jobId);
          onProcessingStarted?.();
        }
        toastRef.current.success(
          ingest.accepted?.length
            ? `Registered ${ingest.accepted.length} file(s) from the server dump`
            : "Client upload dump registered"
        );
      } catch (e: unknown) {
        const msg = e instanceof Error ? e.message : "Could not register the client upload dump";
        onRegisterError?.(msg);
        toastRef.current.error(msg);
      } finally {
        setRegistering(false);
        onRegisterProgress?.({ active: false, pct: 0, fileName: "", phase: "idle" });
      }
      return;
    }
    // Explicit server-side boundary: this path is already visible to the
    // forensic server (local disk, removable disk, or server-accessible network
    // drive). Never retain or display an old browser Download Agent session.
    if (!jobUploadSession.markServerLocalZeroCopy(jobId)) {
      const msg = "A client upload is still running for this job. Finish or stop that transfer before switching to server-side evidence.";
      onRegisterError?.(msg);
      toastRef.current.error(msg);
      return;
    }
    emitSourceMode("server");

    // Keep the local button busy while checking Docker, but do not open the
    // pipeline modal yet. The user should only see List folder / Receiving
    // segments after the exact selected Windows path is confirmed in Docker.
    setRegistering(true);
    try {
      // A Docker container cannot see a Windows drive that was attached after the
      // container was created. Verify the exact selected path before opening the
      // Receiving segments modal; the helper dynamically adds any current A:/.../Z: drive and
      // recreates only the four forensic services when a mount is missing/stale.
      const driveMatch = normalized.match(/^([A-Za-z]):[\\/]/);
      if (driveMatch) {
        onRegisterProgress?.({
          active: true,
          pct: 2,
          fileName: normalized,
          phase: "mounting",
        });
        toastRef.current.info(`Mounting office ${driveMatch[1].toUpperCase()}: so Docker can read it…`);
        const mount = await ensureOfficePathMounted(normalized);
        const mountReady = Boolean(mount.ok);
        if (!mountReady) {
          lastDriveMountErrorRef.current = mount.error ?? "Drive mount refresh failed";
          const detail = lastDriveMountErrorRef.current;
          const msg = detail
            ? `The office server can see ${normalized}. Automatic Docker mount recovery failed: ${detail}`
            : `The office server can see ${normalized}, but Docker could not read the selected path.`;
          onRegisterError?.(msg);
          toastRef.current.error(msg);
          return;
        }
        lastDriveMountErrorRef.current = null;
      }

      beginReceivingSegments();
      onRegisterProgress?.({
        active: true,
        pct: 5,
        fileName: normalized,
        phase: "listing",
      });

      // Step 1: list every file into extraction logs before Get segments.
      // Case-layout runs list inline; deep walks run in the background on the
      // API and we poll — the request never sits for a multi-hour walk.
      toastRef.current.info(`Listing folder contents: ${normalized}…`);
      let listing = await forensicApi.listHostFolder(jobId, { path: normalized });
      if (listing.status === "running") {
        const pollStart = Date.now();
        // Up to 6 h of polling; the API caps the walk itself (LIST_FOLDER_MAX_SECONDS).
        while (Date.now() - pollStart < 6 * 60 * 60 * 1000) {
          await new Promise((r) => setTimeout(r, 3000));
          const status = await forensicApi.listHostFolderStatus(jobId);
          if (status.status === "done") {
            listing = status;
            break;
          }
          if (status.status === "idle") {
            // API restarted mid-walk — restart the listing once.
            listing = await forensicApi.listHostFolder(jobId, { path: normalized });
            if (listing.status !== "running") break;
            continue;
          }
          const elapsed = status.elapsed_sec ?? Math.round((Date.now() - pollStart) / 1000);
          onRegisterProgress?.({
            active: true,
            pct: Math.min(24, 5 + Math.floor(elapsed / 30)),
            fileName: `${normalized} — listing ${elapsed}s`,
            phase: "listing",
          });
        }
        if (listing.status === "running") {
          throw new Error(
            "List folder is still running on the forensic server. Leave this page open or Try again later — the walk continues in the background."
          );
        }
      }
      onRegisterProgress?.({
        active: true,
        pct: 25,
        fileName: normalized,
        phase: "listing",
      });
      toastRef.current.info(
        `Listed ${listing.count} item(s) (${listing.segment_count} segment file(s)) — registering…`
      );

      onRegisterProgress?.({
        active: true,
        pct: 35,
        fileName: normalized,
        phase: "registering",
      });
      // Step 2: register segments (listing already written to extraction log).
      toastRef.current.info(`Registering segments in place from ${normalized} — no copy.`);
      const ingest = await forensicApi.ingestHostPath(jobId, {
        path: normalized,
        source_type: sourceType,
        auto_process: autoProcess,
        skip_folder_list: true,
      });
      onRegisterProgress?.({
        active: true,
        pct: 70,
        fileName: normalized,
        phase: "registering",
      });
      if (ingest.processing_queued) {
        toast.success("Disk folder selected — pipeline started automatically");
        onProcessingStarted?.();
      } else if (autoProcess && ingest.accepted?.length) {
        try {
          await forensicApi.processJob(jobId);
          toast.success("Disk folder selected — pipeline started automatically");
          onProcessingStarted?.();
        } catch (procErr: unknown) {
          const msg =
            procErr instanceof Error
              ? procErr.message
              : "Segments registered but processing could not start — retrying automatically";
          onProcessingError?.(msg);
          toast.error(msg);
          if (allowMountRetry && (isDockerMountError(msg) || /no disk segments/i.test(msg))) {
            const remounted = await refreshDriveMountsOnHost(undefined, {
              light: true,
              requiredPath: normalized,
            });
            if (remounted) {
              await ingestAtResolvedPath(normalized, false);
              return;
            }
          }
        }
      } else if (!ingest.accepted?.length) {
        const msg =
          "List folder succeeded but no segments were registered. The drive may have unmounted. Try again.";
        onRegisterError?.(msg);
        toast.error(msg);
        return;
      } else {
        toast.success(`${ingest.accepted.length} segment(s) registered in place`);
      }
      if (ingest.accepted?.length) {
        setSelectionLabel(`${normalized} — ${ingest.accepted.length} segments`);
      }
      onRegistered?.();
    } catch (e: unknown) {
      const errMsg = e instanceof Error ? e.message : "Host registration failed";
      const mountRelated = isDockerMountError(errMsg);
      const transient =
        e instanceof ApiError && (e.code === "timeout" || e.code === "network_error");
      // Remount only for Docker mount gaps — not for missing folders (Path not found),
      // which previously spun Refresh for minutes and then blamed HostDrive.
      if (allowMountRetry && (mountRelated || transient)) {
        const remounted = await refreshDriveMountsOnHost(
          normalized.match(/^([A-Za-z]):/)?.[1]?.toLowerCase(),
          { light: true, requiredPath: normalized }
        );
        if (remounted) {
          await ingestAtResolvedPath(normalized, false);
          return;
        }
      }
      if (e instanceof ApiError && e.code === "timeout") {
        try {
          const job = await forensicApi.getJob(jobId);
          const hasSegments = Boolean(
            job.segment_readiness?.has_disk_segments || (job.evidence_count ?? 0) > 0
          );
          const started = ["processing", "building_disk", "disk_ready", "extracting"].includes(job.status);
          if (started || (job.status === "registered" && hasSegments)) {
            if (job.status === "registered" && autoProcess) {
              try {
                await forensicApi.processJob(jobId);
              } catch {
                /* process_job re-registers from the saved folder; surface later if it still fails */
              }
            }
            toast.success(
              started
                ? "Processing started — disk build is running in the background"
                : "Segments registered — starting pipeline…"
            );
            onProcessingStarted?.();
            onRegistered?.();
            return;
          }
        } catch {
          /* fall through */
        }
        const timeoutMsg =
          "Registration timed out before the API responded. Confirm the folder path exists on this PC and contains .E01 segments, then Try again.";
        onRegisterError?.(timeoutMsg);
        toast.error(timeoutMsg);
      } else {
        onRegisterError?.(errMsg);
        toast.error(errMsg);
      }
      throw e;
    } finally {
      setRegistering(false);
      onRegisterProgress?.({ active: false, pct: 0, fileName: "", phase: "idle" });
    }
  }
  ingestHostPathRef.current = ingestAtResolvedPath;

  async function startLiveExtraction() {
    const device = selectedMobileDevice || mobileDevices[0] || null;
    if (!device) {
      toast.error("No phone detected — plug it into this PC or the office server and wait a few seconds");
      return;
    }
    setAcquiring(true);
    beginReceivingSegments();
    onRegisterProgress?.({
      active: true,
      pct: 5,
      fileName: `Acquiring ${device.name}…`,
    });
    try {
      const online = await ensureHostDriveHelper(8_000, 1_500, { force: true });
      if (!online?.ok) {
        throw new Error(
          `HostDrive agent is not running. Install once: ${hostDriveHelperInstallHint()}`
        );
      }
      setHelperOnline(true);
      toast.info(
        device.os_hint === "ios"
          ? `Creating iOS backup image for ${device.name}. Keep the phone awake and USB trusted. A passcode being set is normal — only unlock again if the tool reports Error 208. This can take a long time…`
          : `Starting logical extraction for ${device.name} into forensic-mobile-acquisitions\\${jobId}…`
      );
      const result = await startMobileAcquisition({
        job_id: jobId,
        device_id: device.id,
        device_name: device.name,
        os_hint: device.os_hint || "other",
        instance_id: device.instance_id,
      });
      if (!result.ok || !result.output_path) {
        if (result.busy || isUsbCollectionBusyError(result.error)) setUsbBusy(true);
        const raw = result.error || result.message || "Mobile acquisition failed";
        throw new Error(friendlyMobileAcquireError(raw));
      }
      const registerPath = result.backup_path || result.output_path;
      setManualPath(registerPath);
      setSelectionLabel(
        `${device.name} → ${registerPath} (${result.primary_method || "logical"}, ${result.files_copied ?? 0} files)`
      );
      onRegisterProgress?.({
        active: true,
        pct: 55,
        fileName: result.backup_path || result.zip_name || result.output_path,
      });
      toast.success(
        result.message ||
          `Extraction package created (${result.zip_name || "logical.zip"}). Registering and building image…`
      );
      if (result.warnings?.length) {
        toast.info(`Acquisition notes: ${result.warnings.slice(0, 3).join("; ")}`);
      }
      await ingestAtResolvedPath(registerPath);
    } catch (e: unknown) {
      const raw = e instanceof Error ? e.message : "Mobile extraction failed";
      const msg = friendlyMobileAcquireError(raw);
      if (isUsbCollectionBusyError(raw) || isUsbCollectionBusyError(msg)) setUsbBusy(true);
      onRegisterError?.(msg);
      toast.error(msg);
    } finally {
      setAcquiring(false);
      onRegisterProgress?.({ active: false, pct: 0, fileName: "" });
    }
  }

  async function registerFromBrowse(res: HostBrowse, segments: string[]) {
    if (!jobUploadSession.markServerLocalZeroCopy(jobId)) {
      const msg = "A client upload is still running for this job. Finish or stop that transfer before switching to server-side evidence.";
      onRegisterError?.(msg);
      toastRef.current.error(msg);
      return;
    }
    emitSourceMode("server");
    setRegistering(true);
    const label = res.display_path || `${segments.length} segment(s)`;
    try {
      // A browse result can have been obtained before a newly attached/removable
      // drive is actually readable by Docker.  Gate the pipeline modal on the
      // exact Windows folder, just like ingestAtResolvedPath does.
      const exactPath = res.display_path && isAbsoluteEvidencePath(res.display_path)
        ? normalizeEvidencePath(res.display_path)
        : res.drive_root
          ? `${res.drive_root.toUpperCase()}:\\${(res.current_path || "").replace(/\//g, "\\")}`
          : "";
      const driveMatch = exactPath.match(/^([A-Za-z]):[\\/]/);
      if (driveMatch) {
        toastRef.current.info(`Checking Docker access to office ${driveMatch[1].toUpperCase()}:…`);
        const mount = await ensureOfficePathMounted(exactPath);
        const mountReady = Boolean(mount.ok);
        if (!mountReady) {
          lastDriveMountErrorRef.current = mount.error ?? "Drive mount refresh failed";
          const detail = lastDriveMountErrorRef.current;
          const msg = detail
            ? `Windows can see ${exactPath}. Automatic Docker mount recovery failed: ${detail}`
            : `Windows can see ${exactPath}, but Docker could not read the selected path.`;
          onRegisterError?.(msg);
          toastRef.current.error(msg);
          return;
        }
      }

      beginReceivingSegments();
      onRegisterProgress?.({
        active: true,
        pct: 5,
        fileName: label,
        phase: "listing",
      });
      const listPayload = res.display_path
        ? { path: res.display_path }
        : { drive: res.drive_root || currentDrive, browse_path: res.current_path };
      const listing = await forensicApi.listHostFolder(jobId, listPayload);
      toastRef.current.info(
        `Listed ${listing.count} item(s) (${listing.segment_count} segment file(s)) — registering…`
      );
      onRegisterProgress?.({
        active: true,
        pct: 35,
        fileName: label,
        phase: "registering",
      });
      const ingest = await forensicApi.ingestHostPath(jobId, {
        path: res.display_path,
        drive: res.drive_root || currentDrive,
        browse_path: res.current_path,
        source_type: sourceType,
        selected_names: isHostSegmentSource(sourceType) ? segments : undefined,
        auto_process: autoProcess,
        skip_folder_list: true,
      });
      if (ingest.processing_queued) {
        toast.success("Disk folder selected — virtual disk build started automatically");
        onProcessingStarted?.();
      } else if (autoProcess && ingest.accepted?.length) {
        try {
          await forensicApi.processJob(jobId);
          toast.success("Disk folder selected — virtual disk build started automatically");
          onProcessingStarted?.();
        } catch (procErr: unknown) {
          const msg =
            procErr instanceof Error
              ? procErr.message
              : "Segments registered but processing could not start — try Resume";
          onProcessingError?.(msg);
          toast.error(msg);
        }
      } else if (!ingest.accepted?.length) {
        const msg =
          "List folder succeeded but no segments were registered. The drive may have unmounted. Try again.";
        onRegisterError?.(msg);
        toast.error(msg);
        return;
      } else {
        toast.success(`${ingest.accepted.length} segment(s) registered in place`);
      }
      onRegistered?.();
    } catch (e: unknown) {
      if (e instanceof ApiError && e.code === "timeout") {
        try {
          const job = await forensicApi.getJob(jobId);
          if (["processing", "building_disk", "disk_ready", "extracting"].includes(job.status)) {
            toast.success("Processing started — disk build is running in the background");
            onProcessingStarted?.();
            onRegistered?.();
            return;
          }
        } catch {
          /* fall through */
        }
        toast.error(
          "Request timed out, but registration may have completed — refresh the page to check job status."
        );
      } else {
        const msg = e instanceof Error ? e.message : "Host registration failed";
        onRegisterError?.(msg);
        toast.error(msg);
      }
      throw e;
    } finally {
      setRegistering(false);
      onRegisterProgress?.({ active: false, pct: 0, fileName: "", phase: "idle" });
    }
  }

  async function registerFolderAt(res: HostBrowse) {
    if (isWorkstationPath(res.display_path)) {
      setManualPath(res.display_path);
    } else if (res.drive_root && res.current_path) {
      setManualPath(`${res.drive_root.toUpperCase()}:\\${res.current_path.replace(/\//g, "\\")}`);
    } else if (res.drive_root) {
      setManualPath(`${res.drive_root.toUpperCase()}:\\`);
    }
    if (isHostSegmentSource(sourceType)) {
      if (!res.folder_segments.length) {
        const msg =
          res.error ??
          (sourceType === "mobile"
            ? "No mobile segments (.pas, .ufd, .ufdx, …) in this folder"
            : "No disk segments (.E01, .E02, …) in this folder");
        onRegisterError?.(msg);
        toast.error(msg);
        return;
      }
      const segments = res.folder_segments;
      setSelectedSegments(new Set(segments));
      setSelectionLabel(`${res.display_path} — ${res.folder_segment_count} segments`);
      await registerFromBrowse(res, segments);
      return;
    }
    toast.success("Folder opened — select a backup below, then Register");
  }

  async function openHostPath(hostPath: string) {
    const trimmed = hostPath.trim();
    if (!trimmed) {
      toast.error(
        sourceType === "mobile"
          ? "Enter the folder path that contains your mobile segments"
          : "Enter the folder path that contains your disk segments"
      );
      return;
    }
    const normalized = normalizeEvidencePath(trimmed);
    if (normalized !== trimmed) {
      toast.info(`Auto-corrected path spelling → ${normalized}`);
      setManualPath(normalized);
    }
    if (isPlaceholderEvidencePath(normalized)) {
      const msg =
        "That path is only an example placeholder. Choose the real folder that contains your segments so it can be registered in place.";
      onRegisterError?.(msg);
      toast.error(msg);
      return;
    }
    const res = await loadBrowse({ hostPath: normalized });
    if (!res) return;
    scrollToBrowser();
    if (isHostSegmentSource(sourceType)) {
      await registerFolderAt(res);
    }
  }

  async function enterDrive(key: string, mounted = true) {
    if (!mounted) {
      const ok = await refreshDriveMountsOnHost(key);
      if (!ok) return;
      return;
    }
    setCurrentDrive(key);
    void loadBrowse({ drive: key, path: "" });
  }

  function enterFolder(name: string) {
    void loadBrowse({ drive: currentDrive, path: joinPath(browsePath, name) });
  }

  function goUp() {
    if (!currentDrive) return;
    if (browse?.parent_path === "") {
      setCurrentDrive("");
      void loadBrowse({ drive: "", path: "" });
      return;
    }
    if (browse?.parent_path != null) {
      void loadBrowse({ drive: currentDrive, path: browse.parent_path });
    }
  }

  async function useCurrentFolder() {
    if (!browse) return;
    await registerFolderAt(browse);
  }

  async function selectDiskImage(entry: BrowseEntry) {
    if (!browse || !entry.segment_set.length) return;
    setSelectedSegments(new Set(entry.segment_set));
    setSelectionLabel(
      `${entry.segment_base ?? entry.name} — ${entry.segment_count} segment${entry.segment_count === 1 ? "" : "s"}`
    );
    if (isHostSegmentSource(sourceType)) {
      await registerFromBrowse(browse, entry.segment_set);
    }
  }

  function selectBackupFolder(name: string) {
    setBrowsePath(joinPath(browsePath, name));
    setSelectionLabel(name);
  }

  function selectAndroidFile(entry: BrowseEntry) {
    setSelectedSegments(new Set([entry.name]));
    setSelectionLabel(entry.name);
  }

  async function registerHost() {
    if (!browse || registering || disabled) return;
    if (isHostSegmentSource(sourceType) && selectedSegments.size === 0) {
      toast.error(
        sourceType === "mobile" ? "Select a folder with mobile segments first" : "Select a folder or disk image first"
      );
      return;
    }
    if (!isHostSegmentSource(sourceType) && !selectionLabel) {
      toast.error("Select a backup folder or .ab file");
      return;
    }
    await registerFromBrowse(browse, Array.from(selectedSegments));
  }

  const busy = loading || registering || remounting || acquiring;
  const canRegister =
    browse?.configured &&
    !browse.error &&
    sourceType !== "disk" &&
    Boolean(selectionLabel);

  const pathParts = browsePath ? browsePath.split("/").filter(Boolean) : [];
  const atDriveList = !currentDrive;
  const driveLabel = browse?.display_path || "This PC";

  function navigateTo(index: number) {
    if (index < 0) {
      setCurrentDrive("");
      void loadBrowse({ drive: "", path: "" });
      return;
    }
    void loadBrowse({ drive: currentDrive, path: pathParts.slice(0, index + 1).join("/") });
  }

  const fullyAutomated = embedded && autoProcess && isLiveMobileSource;

  if (fullyAutomated) {
    return (
      <div ref={panelRef} className="space-y-4">
        {isLiveMobileSource ? (
          <div className="rounded-lg border border-sky-200 bg-sky-50/90 px-3 py-2.5 text-xs text-sky-950">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <p className="font-semibold">Connected mobile devices</p>
              <Button
                variant="outline"
                className="h-7 border-sky-300 bg-white px-2 text-[11px] text-sky-900"
                disabled={busy || disabled || mobileDevicesLoading}
                loading={mobileDevicesLoading}
                onClick={() => void refreshMobileDevices()}
              >
                <RefreshCw className="mr-1 h-3 w-3" />
                Rescan USB
              </Button>
            </div>
            <UsbCollectionBusyBanner
              show={usbBusy}
              className="mt-2"
              onStopped={() => setUsbBusy(false)}
            />
            {mobileDevices.length ? (
              <ul className="mt-2 space-y-1.5">
                {mobileDevices.map((device) => {
                  const os = mobileKindLabel(device.os_hint);
                  return (
                    <li key={device.id}>
                      <button
                        type="button"
                        disabled={busy || disabled}
                        onClick={() => onSelectConnectedMobileDevice(device)}
                        className="flex w-full items-center gap-2 rounded-md border border-sky-200 bg-white px-2.5 py-2 text-left hover:border-sky-400 hover:bg-sky-50"
                      >
                        <Smartphone className="h-4 w-4 shrink-0 text-sky-700" />
                        <span className="min-w-0 flex-1">
                          <span className="block truncate font-semibold text-ink-800">{device.name}</span>
                          <span className="block text-[10px] text-ink-500">
                            {os} · {mobileAttachHostLabel(device.attach_host)}
                          </span>
                        </span>
                        <span className="shrink-0 rounded bg-amber-50 px-1.5 py-0.5 text-[10px] font-medium text-amber-800">
                          {os}
                        </span>
                      </button>
                    </li>
                  );
                })}
              </ul>
            ) : (
              <p className="mt-2 text-sky-900/80">
                {helperOnline === false
                  ? "Host drive helper offline — start it to detect phones over USB."
                  : "Watching for a phone on this PC or the office server. Plug it in with a data cable and unlock — iPhone and Android are classified automatically. No extra adapter is required."}
              </p>
            )}
            <p className="mt-2 text-[11px] text-sky-900/80">
              <strong>Live extract</strong> uses the UFED-aligned Python orchestrator on this PC (case layout, seals,
              hashes). Prefer{" "}
              <a href="/forensic/mobile/acquire" className="font-medium text-brand-700 underline">
                Acquire from device
              </a>{" "}
              for full Device Wizard (legal authority, method selection, live progress).{" "}
              <strong>iPhone:</strong> unlock, passcode, Trust This Computer. For proprietary Full File System / unlock,
              import a UFED .pas/.ufd export below. Android: ADB logical/backup; rooted devices may offer physical .raw.
            </p>
            {mobileDevices.length ? (
              <Button
                variant="brand"
                className="mt-3 w-full animate-pulse ring-2 ring-brand-400 ring-offset-2 sm:w-auto"
                disabled={busy || disabled || helperOnline === false}
                loading={acquiring || registering}
                onClick={() => void startLiveExtraction()}
              >
                <Smartphone className="mr-2 h-4 w-4" />
                {acquiring
                  ? "Extracting from phone…"
                  : registering
                    ? "Registering & building image…"
                    : "Start extraction & create image"}
              </Button>
            ) : null}
          </div>
        ) : null}
        {highlightStart && !(isLiveMobileSource && mobileDevices.length) ? (
          <div className="rounded-lg border-2 border-brand-400 bg-brand-50 px-4 py-3 text-sm text-brand-950 shadow-sm">
            <p className="font-semibold">One click to start</p>
            <p className="mt-1 text-brand-900">
              {isMobileEvidenceSource
                ? "Choose the extraction directory that contains the .pas / .ufd / .ufdx / .zip files. The application will process the files inside that directory."
                : "Choose the directory that contains the .E01/.E02 image set. The application will process the files inside that directory."}
            </p>
          </div>
        ) : !isLiveMobileSource || !mobileDevices.length ? (
          <p className="text-sm text-ink-600">
            {isMobileEvidenceSource
              ? "Choose the extraction directory from the available drive and process the files inside it."
              : "Choose the disk-image directory from the available drive. Extraction starts from the files inside that directory."}
          </p>
        ) : null}
        {isLiveMobileSource && helperOnline === false ? (
          <div className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-900">
            <p>
              HostDrive agent is only needed for live USB phone extract. Choose the extraction directory from the available drive.
            </p>
          </div>
        ) : null}
        <Button
          variant={isLiveMobileSource && mobileDevices.length ? "outline" : "brand"}
          className={`w-full sm:w-auto ${highlightStart && !(isLiveMobileSource && mobileDevices.length) ? "animate-pulse ring-2 ring-brand-400 ring-offset-2" : ""}`}
          disabled={registering || acquiring || disabled || remounting}
          loading={(registering && !acquiring) || remounting}
          onClick={() => void openNativeFolderPicker()}
        >
          <FolderOpen className="mr-2 h-4 w-4" />
          {remounting
            ? "Mounting attached drives…"
            : registering
              ? "Registering segments…"
              : isMobileEvidenceSource
                ? "Select extraction directory…"
                : "Select evidence directory…"}
        </Button>
        <BrowseFolderDialog
          open={browseDialogOpen}
          helperOnline={helperOnline}
          refreshing={remounting}
          startingAgent={startingAgent}
          recommendedLetters={recommendedLetters}
          onClose={() => setBrowseDialogOpen(false)}
          onConfirm={(folders) => void confirmStagedBrowseFolders(folders)}
          onRefreshMounts={() => void refreshDriveMountsOnHost()}
          onStartAgent={() => void startHostDriveAgent()}
        />
        {selectionLabel ? (
          <div className="rounded-md border border-brand-200 bg-brand-50/60 px-3 py-2 text-xs text-ink-700">
            <span className="font-semibold text-brand-800">Selected:</span> {selectionLabel}
          </div>
        ) : null}
        <ResolveFolderErrorDialog
          open={resolveError.open}
          message={resolveError.message}
          segmentCount={resolveError.segmentCount}
          helperOnline={helperOnline}
          refreshing={remounting}
          onClose={() => setResolveError((prev) => ({ ...prev, open: false }))}
          onRefreshMounts={() => {
            void refreshDriveMountsOnHost().then(async (ok) => {
              if (!ok) return;
              setResolveError((prev) => ({ ...prev, open: false }));
              const pending = pendingResolveRef.current;
              if (pending) {
                await resolveFolderFromFilenames(pending.filenames, {
                  folderHint: pending.folderHint,
                  relativePaths: pending.relativePaths,
                });
              }
            });
          }}
          onUsePastePath={() => {
            setResolveError((prev) => ({ ...prev, open: false }));
            void openNativeFolderPicker();
          }}
        />
      </div>
    );
  }

  return (
    <div
      ref={panelRef}
      className={embedded ? "space-y-3" : "rounded-lg border border-ink-100 bg-ink-50/40 p-4"}
    >
      {!embedded ? (
        <div className="mb-3 flex items-center gap-2">
          <HardDrive className="h-4 w-4 text-brand-600" />
          <h4 className="text-sm font-bold text-ink-800">Select evidence location</h4>
        </div>
      ) : null}

      {!isLiveMobileSource ? (
        <div className="mb-3 rounded-lg border-2 border-brand-300 bg-brand-50/70 px-3 py-3 text-xs text-brand-950">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0 flex-1">
              <p className="font-semibold">Select evidence directory</p>
              <p className="mt-1 text-brand-900">
                Choose the folder from any available HDD, SSD, USB/pendrive, external drive or mapped network drive.
                The application reads the selected directory in place and starts processing without a separate download step.
              </p>
            </div>
            <Button
              variant="brand"
              className="shrink-0"
              disabled={busy || disabled}
              loading={loading || remounting}
              onClick={() => void openNativeFolderPicker()}
            >
              <HardDrive className="mr-1 h-3.5 w-3.5" />
              Browse drives
            </Button>
          </div>
        </div>
      ) : null}

      <p className="mb-3 text-xs text-ink-500">
        Open the required drive, select the evidence directory, and start extraction. Evidence stays at the selected path while the pipeline runs.
      </p>

      {lockedSourceType ? (
        <div className="mb-3 space-y-2">
          <div className="flex flex-wrap items-center gap-2 text-xs">
            <span className="rounded-md bg-brand-600 px-3 py-1 font-semibold text-white">Mobile extraction</span>
            {mobileOsLabel ? (
              <span className="rounded-md border border-ink-200 bg-white px-3 py-1 font-medium text-ink-700">
                OS: {mobileOsLabel}
              </span>
            ) : null}
            {capabilityLabel ? (
              <span className="rounded-md border border-emerald-200 bg-emerald-50 px-3 py-1 font-medium text-emerald-800">
                {capabilityLabel}
              </span>
            ) : null}
            <Button
              variant="outline"
              className="h-7 px-2 text-[11px]"
              disabled={busy || disabled || mobileDevicesLoading}
              loading={mobileDevicesLoading}
              onClick={() => void refreshMobileDevices()}
            >
              <RefreshCw className="mr-1 h-3 w-3" />
              Rescan USB phones
            </Button>
          </div>
          <UsbCollectionBusyBanner
            show={usbBusy}
            className="mb-2"
            onStopped={() => setUsbBusy(false)}
          />
          {mobileDevices.length ? (
            <div className="space-y-2">
              <ul className="space-y-1">
                {mobileDevices.map((device) => (
                  <li key={device.id}>
                    <button
                      type="button"
                      disabled={busy || disabled}
                      onClick={() => onSelectConnectedMobileDevice(device)}
                      className={`flex w-full items-center gap-2 rounded-md border px-2.5 py-1.5 text-left text-xs hover:border-sky-400 ${
                        selectedMobileDevice?.id === device.id
                          ? "border-sky-400 bg-sky-100"
                          : "border-sky-200 bg-sky-50"
                      }`}
                    >
                      <Smartphone className="h-3.5 w-3.5 text-sky-700" />
                      <span className="font-semibold text-ink-800">{device.name}</span>
                      <span className="text-ink-500">
                        {mobileKindLabel(device.os_hint)} · {mobileAttachHostLabel(device.attach_host)}
                      </span>
                    </button>
                  </li>
                ))}
              </ul>
              <Button
                variant="brand"
                className="w-full sm:w-auto"
                disabled={busy || disabled || helperOnline === false}
                loading={acquiring || registering}
                onClick={() => void startLiveExtraction()}
              >
                <Smartphone className="mr-2 h-4 w-4" />
                {acquiring ? "Extracting from phone…" : "Start extraction & create image"}
              </Button>
            </div>
          ) : (
            <p className="text-[11px] text-ink-500">
              No phone detected yet. Plug it into this PC or the office server — detection is automatic, no extra adapter.
            </p>
          )}
        </div>
      ) : (
        <div className="mb-3 flex flex-wrap gap-2">
          {(
            [
              ["disk", "Disk image"],
              ["mobile", "Mobile extraction"],
              ["ios_backup", "iOS backup"],
              ["android_backup", "Android backup"],
            ] as const
          ).map(([value, label]) => (
            <button
              key={value}
              type="button"
              disabled={busy || disabled}
              onClick={() => setSourceType(value)}
              className={
                sourceType === value
                  ? "rounded-md bg-brand-600 px-3 py-1 text-xs font-semibold text-white"
                  : "rounded-md border border-ink-200 bg-white px-3 py-1 text-xs font-medium text-ink-600"
              }
            >
              {label}
            </button>
          ))}
        </div>
      )}

      {!helperOnline && isLiveMobileSource ? (
        <div className="mb-3 rounded-md border border-amber-300 bg-amber-50 px-3 py-2 text-xs text-amber-950">
          <p className="font-semibold">Local HostDrive helper is offline (port 9876)</p>
          <p className="mt-1">
            Attached/removable/network drives are browsed from the local forensic environment and processed in place.
            Install the HostDrive helper only when live USB phone acquisition requires it:
          </p>
          <code className="mt-2 block rounded bg-white px-2 py-1 text-[11px] text-ink-800">
            {hostDriveHelperInstallHint()}
          </code>
          <div className="mt-2 flex flex-wrap gap-2">
            <Button
              variant="outline"
              className="border-amber-300 bg-white text-[11px]"
              loading={startingAgent}
              onClick={() => void startHostDriveAgent()}
            >
              Start HostDrive agent
            </Button>
            <Button
              variant="outline"
              className="border-amber-300 bg-white text-[11px]"
              loading={remounting}
              onClick={() => void refreshDriveMountsOnHost()}
            >
              <RefreshCw className="mr-1 h-3 w-3" />
              Refresh drive mounts
            </Button>
          </div>
        </div>
      ) : null}

      {!isLiveMobileSource && browse?.error && !browse.entries.length ? (
        <div className="mb-3 flex gap-2 rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-900">
          <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />
          <div className="min-w-0 flex-1">
            <p>{browse.error}</p>
            {browse.mount_hint ? <p className="mt-1 text-amber-800">{browse.mount_hint}</p> : null}
            <Button
              variant="outline"
              className="mt-2 border-amber-300 bg-white text-[11px] text-amber-900 hover:bg-amber-100"
              loading={remounting}
              disabled={busy || disabled}
              onClick={() => void refreshDriveMountsOnHost()}
            >
              <RefreshCw className="mr-1 h-3 w-3" />
              Refresh drive mounts
            </Button>
          </div>
        </div>
      ) : null}

      {!isLiveMobileSource ? (
      <div
        ref={browserRef}
        className="mb-3 rounded-md border border-brand-200 bg-white ring-1 ring-brand-100/80"
      >
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-brand-100 bg-brand-50/40 px-3 py-2 text-xs font-semibold text-brand-800">
          <span>
            Server evidence browser — zero-copy
            {!atDriveList && browse?.display_path ? (
              <span className="ml-2 font-normal text-ink-500">— {browse.display_path}</span>
            ) : null}
          </span>
          <div className="flex flex-wrap items-center gap-2">
            <span className="text-[10px] font-normal text-emerald-700">Forensic server drives · process in place</span>
            <Button
              variant="outline"
              className="h-7 border-brand-200 bg-white px-2 py-0 text-[10px] text-brand-800 hover:bg-brand-50"
              loading={remounting}
              disabled={busy || disabled}
              title="HostDrive agent: detect attached disks and refresh Docker mounts"
              onClick={() => void refreshDriveMountsOnHost()}
            >
              <RefreshCw className="mr-1 h-3 w-3" />
              Refresh drive mounts
            </Button>
          </div>
        </div>
        <div className="flex flex-wrap items-center gap-1 border-b border-ink-100 px-3 py-2 text-xs text-ink-600">
          <button
            type="button"
            className="font-medium hover:text-brand-600"
            disabled={busy || disabled || atDriveList}
            onClick={() => navigateTo(-1)}
          >
            This PC
          </button>
          {!atDriveList ? (
            <>
              <ChevronRight className="h-3 w-3 text-ink-300" />
              <button
                type="button"
                className="font-medium hover:text-brand-600"
                disabled={busy || disabled || !browsePath}
                onClick={() => void loadBrowse({ drive: currentDrive, path: "" })}
              >
                {driveLabel.split("\\")[0] || currentDrive.toUpperCase() + ":"}
              </button>
            </>
          ) : null}
          {pathParts.map((part, i) => (
            <span key={`${part}-${i}`} className="flex items-center gap-1">
              <ChevronRight className="h-3 w-3 text-ink-300" />
              <button
                type="button"
                className="font-medium hover:text-brand-600"
                disabled={busy || disabled || i === pathParts.length - 1}
                onClick={() => navigateTo(i)}
              >
                {part}
              </button>
            </span>
          ))}
          {!atDriveList ? (
            <button type="button" className="ml-auto text-brand-600 hover:underline" disabled={busy || disabled} onClick={goUp}>
              Up
            </button>
          ) : null}
        </div>

        {loading ? (
          <p className="px-3 py-4 text-xs text-ink-400">Loading…</p>
        ) : browse && browse.entries.length === 0 ? (
          <div className="px-3 py-4 text-xs">
            {atDriveList ? (
              <p className="text-ink-400">No drives mounted — check Docker volume settings.</p>
            ) : (
              <div className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-amber-900">
                <p className="font-semibold">This folder is empty</p>
                <p className="mt-1 text-amber-800">
                  Choose the folder that contains your <code className="rounded bg-white/80 px-1">.E01</code>{" "}
                  files with <strong>Browse folder…</strong> so they can be registered in place.
                </p>
              </div>
            )}
          </div>
        ) : (
          <ul className="max-h-56 overflow-y-auto divide-y divide-ink-50">
            {browse?.entries.map((entry) => {
              if (entry.kind === "drive") {
                const driveMounted = entry.mounted !== false;
                const vol: HostDriveVolume | undefined = entry.drive_key
                  ? {
                      letter: entry.drive_key,
                      label: entry.volume_label ?? undefined,
                      drive_type: (entry.drive_type as HostDriveVolume["drive_type"]) ?? undefined,
                      size_bytes: entry.size_bytes ?? undefined,
                    }
                  : undefined;
                const badge = driveTypeBadge(vol);
                const DriveIcon = vol?.drive_type === "removable" ? Usb : HardDrive;
                return (
                  <li key={`drive-${entry.drive_key ?? entry.name}`}>
                    <button
                      type="button"
                      disabled={busy || disabled}
                      onClick={() => enterDrive(entry.drive_key ?? entry.name.charAt(0).toLowerCase(), driveMounted)}
                      className={
                        driveMounted
                          ? "flex w-full items-center gap-2 px-3 py-2 text-xs hover:bg-ink-50/60"
                          : "flex w-full items-center gap-2 px-3 py-2 text-xs text-ink-400"
                      }
                      title={
                        driveMounted
                          ? badge
                            ? `${badge} drive — open to select image folder`
                            : undefined
                          : "Server drive is not mounted in Docker — refresh server drive mounts. Do not upload a server-side image just to work around a mount issue."
                      }
                    >
                      <DriveIcon className={`h-4 w-4 shrink-0 ${driveMounted ? "text-brand-600" : "text-ink-300"}`} />
                      <span className={driveMounted ? "font-semibold text-ink-800" : "font-medium"}>
                        {driveDisplayLabel(entry, vol)}
                      </span>
                      {badge ? (
                        <span className="rounded bg-brand-100 px-1.5 py-0.5 text-[10px] font-semibold text-brand-800">
                          {badge}
                        </span>
                      ) : null}
                      {!driveMounted ? (
                        <span className="ml-auto text-[10px] text-ink-400">not mounted</span>
                      ) : vol?.size_bytes ? (
                        <span className="ml-auto text-[10px] text-ink-400">{formatBytes(vol.size_bytes)}</span>
                      ) : null}
                    </button>
                  </li>
                );
              }

              if (entry.kind === "dir") {
                return (
                  <li key={`dir-${entry.name}`}>
                    <div className="flex items-center gap-2 px-3 py-2 text-xs hover:bg-ink-50/60">
                      <button
                        type="button"
                        className="flex min-w-0 flex-1 items-center gap-2 text-left"
                        disabled={busy || disabled}
                        onClick={() => enterFolder(entry.name)}
                      >
                        <Folder className="h-4 w-4 shrink-0 text-amber-500" />
                        <span className="truncate font-medium text-ink-800">{entry.name}</span>
                        {entry.ios_backup ? (
                          <span className="rounded bg-blue-100 px-1.5 py-0.5 text-[10px] font-semibold text-blue-700">iOS backup</span>
                        ) : null}
                        {entry.android_backup ? (
                          <span className="rounded bg-green-100 px-1.5 py-0.5 text-[10px] font-semibold text-green-700">Android</span>
                        ) : null}
                      </button>
                      {isHostSegmentSource(sourceType) ? (
                        <Button
                          variant="outline"
                          className="shrink-0 px-2 py-1 text-[10px]"
                          disabled={busy || disabled}
                          onClick={async () => {
                            await loadBrowse({ drive: currentDrive, path: joinPath(browsePath, entry.name) });
                            const next = await fetchBrowse({ drive: currentDrive, path: joinPath(browsePath, entry.name) });
                            applyBrowse(next);
                            await registerFolderAt(next);
                          }}
                        >
                          Open
                        </Button>
                      ) : null}
                      {sourceType === "ios_backup" && entry.ios_backup ? (
                        <Button variant="outline" className="shrink-0 px-2 py-1 text-[10px]" disabled={busy || disabled} onClick={() => selectBackupFolder(entry.name)}>
                          Use backup
                        </Button>
                      ) : null}
                      {sourceType === "android_backup" && entry.android_backup ? (
                        <Button variant="outline" className="shrink-0 px-2 py-1 text-[10px]" disabled={busy || disabled} onClick={() => selectBackupFolder(entry.name)}>
                          Use folder
                        </Button>
                      ) : null}
                    </div>
                  </li>
                );
              }

              const segmentSelected =
                isHostSegmentSource(sourceType) && entry.segment_set.every((n) => selectedSegments.has(n));

              return (
                <li key={`file-${entry.name}`}>
                  <button
                    type="button"
                    disabled={busy || disabled || !entry.selectable}
                    onClick={() => {
                      if (isHostSegmentSource(sourceType)) void selectDiskImage(entry);
                      else if (sourceType === "android_backup") selectAndroidFile(entry);
                    }}
                    className={
                      segmentSelected
                        ? "flex w-full items-center gap-2 bg-brand-50 px-3 py-2 text-left text-xs"
                        : "flex w-full items-center gap-2 px-3 py-2 text-left text-xs hover:bg-ink-50/60"
                    }
                  >
                    <FolderOpen className="h-4 w-4 shrink-0 text-brand-500" />
                    <span className="min-w-0 flex-1 truncate font-mono text-ink-800">{entry.name}</span>
                    {entry.segment_count > 1 ? (
                      <span className="shrink-0 text-[10px] text-ink-400">{entry.segment_count} parts</span>
                    ) : null}
                    <span className="shrink-0 text-ink-400">{formatBytes(entry.size_bytes)}</span>
                  </button>
                </li>
              );
            })}
          </ul>
        )}
      </div>
      ) : (
        <div ref={browserRef} />
      )}

      {!isLiveMobileSource && isHostSegmentSource(sourceType) && !atDriveList && (browse?.folder_segment_count ?? 0) > 0 ? (
        <div className="mb-3">
          <Button
            variant="brand"
            className="text-xs"
            loading={registering}
            disabled={busy || disabled}
            onClick={() => void useCurrentFolder()}
          >
            Use this folder ({browse?.folder_segment_count} segments)
          </Button>
        </div>
      ) : null}

      {selectionLabel ? (
        <div className="mb-3 rounded-md border border-brand-200 bg-brand-50/50 px-3 py-2 text-xs text-ink-700">
          Selected: <span className="font-semibold">{selectionLabel}</span>
        </div>
      ) : null}

      {sourceType !== "disk" ? (
        <Button variant="outline" loading={registering} disabled={disabled || loading || !canRegister} onClick={() => void registerHost()}>
          Register selected folder
        </Button>
      ) : null}

      <BrowseFolderDialog
        open={browseDialogOpen}
        helperOnline={helperOnline}
        refreshing={remounting}
        startingAgent={startingAgent}
        recommendedLetters={recommendedLetters}
        onClose={() => setBrowseDialogOpen(false)}
        onConfirm={(folders) => void confirmStagedBrowseFolders(folders)}
        onRefreshMounts={() => void refreshDriveMountsOnHost()}
        onStartAgent={() => void startHostDriveAgent()}
      />

      <ResolveFolderErrorDialog
        open={resolveError.open}
        message={resolveError.message}
        segmentCount={resolveError.segmentCount}
        helperOnline={helperOnline}
        refreshing={remounting}
        onClose={() => setResolveError((prev) => ({ ...prev, open: false }))}
        onRefreshMounts={() => {
          void refreshDriveMountsOnHost().then((ok) => {
            if (ok) setResolveError((prev) => ({ ...prev, open: false }));
          });
        }}
        onUsePastePath={() => {
          setResolveError((prev) => ({ ...prev, open: false }));
          void openNativeFolderPicker();
        }}
      />
    </div>
  );
});
