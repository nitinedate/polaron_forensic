const HELPER_BASE =
  (import.meta.env.VITE_HOST_DRIVE_HELPER_URL as string | undefined)?.replace(/\/$/, "") ??
  "http://127.0.0.1:9876";

const HELPER_TOKEN = (import.meta.env.VITE_HOST_DRIVE_HELPER_TOKEN as string | undefined) ?? "";

/** How long a successful health check is reused (avoids hammering localhost). */
const ONLINE_CACHE_MS = 30_000;
/** After helper is offline, do not probe again until this backoff elapses. */
const OFFLINE_BACKOFF_BASE_MS = 90_000;
const OFFLINE_BACKOFF_MAX_MS = 300_000;

type HelperReachability = "unknown" | "online" | "offline";

let reachability: HelperReachability = "unknown";
let onlineUntilMs = 0;
let offlineUntilMs = 0;
let offlineStreak = 0;
let probeInFlight: Promise<HostDriveHelperHealth | null> | null = null;

function helperHeaders(): Record<string, string> {
  const headers: Record<string, string> = { Accept: "application/json" };
  if (HELPER_TOKEN) headers["X-Host-Helper-Token"] = HELPER_TOKEN;
  return headers;
}

export type HostDriveHelperHealth = {
  ok: boolean;
  service?: string;
  port?: number;
  busy?: boolean;
};

export type RefreshDriveMountsResult = {
  ok: boolean;
  drives?: string[];
  windows_letters?: string[];
  missing?: string[];
  newly_attached?: string[];
  mounted?: string[];
  message?: string;
  error?: string;
  log?: string;
  unchanged?: boolean;
  started?: boolean;
  status?: "idle" | "running" | "done" | "error" | string;
  mount_mode?: string | null;
  mount_source?: string | null;
  wsl_distro?: string | null;
  skipped_drives?: string[];
  compose_base?: string | null;
};

export type RefreshDriveMountsStatus = {
  status: "idle" | "running" | "done" | "error" | string;
  ok?: boolean | null;
  message?: string;
  drives?: string[];
  error?: string | null;
  log?: string;
  unchanged?: boolean;
  busy?: boolean;
  required_path?: string | null;
  mount_mode?: string | null;
  mount_source?: string | null;
  wsl_distro?: string | null;
  skipped_drives?: string[];
  compose_base?: string | null;
};

export type ResolveFolderOnHostResult = {
  ok: boolean;
  path?: string | null;
  segment_count?: number;
  error?: string;
  /** True when helper responded (including not-found) so API deep-scan can be skipped. */
  helperResponded?: boolean;
};

export type HostDriveVolume = {
  letter: string;
  label?: string;
  drive_type?: "removable" | "fixed" | "network" | "cdrom" | "other";
  size_bytes?: number;
  free_bytes?: number;
  filesystem?: string;
  mounted?: boolean;
};

export type MobileAttachHost = "office_server" | "this_pc";

export type HostMobileDevice = {
  id: string;
  name: string;
  device_class?: string;
  connection?: string;
  os_hint?: "ios" | "android" | "other" | string;
  instance_id?: string;
  has_drive_letter?: boolean;
  live_acquire?: boolean;
  capability_label?: string;
  guidance?: string;
  ios_backup_roots?: string[];
  attach_host?: MobileAttachHost | string;
};

export function mobileKindLabel(os?: string | null): string {
  const value = String(os || "").toLowerCase();
  if (value === "ios" || value.includes("iphone") || value.includes("ipad") || value.includes("ipod")) {
    return "iPhone / iPad";
  }
  if (value === "android") return "Android";
  return "Unknown";
}

export function mobileAttachHostLabel(host?: string | null): string {
  return host === "office_server" ? "office server" : "this PC";
}

export type HostDriveLettersResult = {
  ok: boolean;
  drives?: string[];
  volumes?: HostDriveVolume[];
  count?: number;
  mounted?: string[];
  helper_online?: boolean;
  source?: string;
  mobile_devices?: HostMobileDevice[];
  mobile_count?: number;
  error?: string;
  message?: string;
};

export type HostMobileDevicesResult = {
  ok: boolean;
  mobile_devices?: HostMobileDevice[];
  count?: number;
  ios_backup_roots?: string[];
  error?: string;
};

/** Cached helper status for UI — null means unknown / not checked yet. */
export function getCachedHelperOnline(): boolean | null {
  if (reachability === "unknown") return null;
  return reachability === "online";
}

/** Clear cache after mount refresh or when user explicitly retries. */
export function invalidateHelperHealthCache(): void {
  reachability = "unknown";
  onlineUntilMs = 0;
  offlineUntilMs = 0;
  offlineStreak = 0;
  probeInFlight = null;
}

function markOnline(health: HostDriveHelperHealth): HostDriveHelperHealth {
  reachability = "online";
  offlineStreak = 0;
  offlineUntilMs = 0;
  onlineUntilMs = Date.now() + ONLINE_CACHE_MS;
  return health;
}

function markOffline(): null {
  reachability = "offline";
  onlineUntilMs = 0;
  offlineStreak += 1;
  const backoff = Math.min(
    OFFLINE_BACKOFF_BASE_MS * 1.4 ** Math.max(offlineStreak - 1, 0),
    OFFLINE_BACKOFF_MAX_MS
  );
  offlineUntilMs = Date.now() + backoff;
  return null;
}

async function probeHelperHealth(timeoutMs: number): Promise<HostDriveHelperHealth | null> {
  try {
    const res = await fetch(`${HELPER_BASE}/health`, {
      method: "GET",
      headers: helperHeaders(),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) return markOffline();
    const health = (await res.json()) as HostDriveHelperHealth;
    if (!health?.ok) return markOffline();
    return markOnline(health);
  } catch {
    return markOffline();
  }
}

/** True when this browser is the office gateway on loopback — not a remote client PC. */
export function isBrowserOnOfficeHost(): boolean {
  if (typeof window === "undefined") return false;
  const host = window.location.hostname.toLowerCase();
  return host === "localhost" || host === "127.0.0.1" || host === "::1" || host === "[::1]";
}

/**
 * Check helper health with caching + offline backoff so the browser does not spam
 * ERR_CONNECTION_REFUSED on every poll when the helper is not running.
 */
export async function hostDriveHelperHealth(
  timeoutMs = 800,
  opts?: { force?: boolean }
): Promise<HostDriveHelperHealth | null> {
  const now = Date.now();
  const force = Boolean(opts?.force);

  if (!force) {
    if (reachability === "online" && now < onlineUntilMs) {
      return { ok: true, service: "host-drive-helper" };
    }
    if (reachability === "offline" && now < offlineUntilMs) {
      return null;
    }
  }

  if (probeInFlight) {
    return probeInFlight;
  }

  probeInFlight = probeHelperHealth(timeoutMs).finally(() => {
    probeInFlight = null;
  });
  return probeInFlight;
}

/**
 * Wait briefly for helper on user-initiated actions only (browse / refresh mounts).
 * Respects offline backoff unless force=true.
 */
export async function ensureHostDriveHelper(
  maxWaitMs = 8_000,
  pollMs = 1_500,
  opts?: { force?: boolean }
): Promise<HostDriveHelperHealth | null> {
  const force = Boolean(opts?.force);
  const first = await hostDriveHelperHealth(Math.min(pollMs, 2000), { force: true });
  if (first?.ok) return first;

  if (!force && reachability === "offline" && Date.now() < offlineUntilMs) {
    return null;
  }

  const deadline = Date.now() + maxWaitMs;
  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, pollMs));
    const health = await hostDriveHelperHealth(Math.min(pollMs + 500, 2500), { force: true });
    if (health?.ok) return health;
  }
  return hostDriveHelperHealth(1500, { force: true });
}


export type HostAcquisitionAdapter = {
  name: string;
  os_family: string;
  available: boolean;
  reason?: string;
  via?: string;
};

export type HostAcquisitionDevice = {
  adapter: string;
  device_id: string;
  label?: string;
  status?: string;
  os_family: string;
  connection?: string;
  instance_id?: string;
  attach_host?: MobileAttachHost | string;
};

export function hostMobileToAcquisitionDevice(
  device: HostMobileDevice,
  attachHost?: MobileAttachHost | string,
): HostAcquisitionDevice {
  const os = device.os_hint === "ios" ? "ios" : device.os_hint === "android" ? "android" : "other";
  return {
    adapter: os === "ios" ? "ios_lockdown" : "android_mtp",
    device_id: device.id,
    label: device.name,
    status: device.connection || "usb",
    os_family: os,
    connection: device.connection,
    instance_id: device.instance_id,
    attach_host: attachHost || device.attach_host,
  };
}

function tagAttachHost<T extends { attach_host?: string }>(
  items: T[],
  attachHost: MobileAttachHost,
): T[] {
  return items.map((item) => (item.attach_host ? item : { ...item, attach_host: attachHost }));
}

function mergeAcquisitionDevices(...lists: HostAcquisitionDevice[][]): HostAcquisitionDevice[] {
  const out = new Map<string, HostAcquisitionDevice>();
  for (const list of lists) {
    for (const device of list) {
      if (!device.device_id) continue;
      const key = `${device.adapter}:${device.device_id}`;
      if (!out.has(key)) out.set(key, device);
    }
  }
  return [...out.values()];
}

function mergeMobileDevices(...lists: HostMobileDevice[][]): HostMobileDevice[] {
  const out = new Map<string, HostMobileDevice>();
  for (const list of lists) {
    for (const device of list) {
      if (!device.id) continue;
      const key = `${device.os_hint || ""}|${device.id}|${device.name}`;
      if (!out.has(key)) out.set(key, device);
    }
  }
  return [...out.values()];
}

/** Direct browser -> Windows helper adapter probe. Useful even before Docker bridge is healthy. */
export async function getHostAcquisitionAdapters(timeoutMs = 10_000): Promise<{
  ok: boolean;
  adapters: HostAcquisitionAdapter[];
  error?: string;
}> {
  const health = await hostDriveHelperHealth(2_000, { force: true });
  if (!health?.ok) return { ok: false, adapters: [], error: "Host drive helper is offline" };
  try {
    const res = await fetch(`${HELPER_BASE}/acquisition/adapters`, {
      method: "GET",
      headers: helperHeaders(),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const data = (await res.json()) as { ok?: boolean; adapters?: HostAcquisitionAdapter[]; error?: string };
    return { ok: Boolean(res.ok && data.ok !== false), adapters: data.adapters ?? [], error: data.error };
  } catch (e: unknown) {
    return { ok: false, adapters: [], error: e instanceof Error ? e.message : "Host adapter probe failed" };
  }
}

async function fromOfficeApiAcquisitionDevices(timeoutMs: number): Promise<{
  ok: boolean;
  devices: HostAcquisitionDevice[];
  warnings: string[];
  error?: string;
} | null> {
  try {
    const { api } = await import("./api");
    const data = await api.get<{
      ok?: boolean;
      devices?: HostAcquisitionDevice[];
      warnings?: string[];
      error?: string;
    }>("/api/hostdrive/acquisition/devices", undefined, { timeoutMs });
    if (!data) return null;
    return {
      ok: Boolean(data.ok !== false),
      devices: tagAttachHost(data.devices ?? [], "office_server"),
      warnings: data.warnings ?? [],
      error: data.error,
    };
  } catch {
    return null;
  }
}

async function fromLocalHelperAcquisitionDevices(timeoutMs: number): Promise<{
  ok: boolean;
  devices: HostAcquisitionDevice[];
  warnings: string[];
  error?: string;
}> {
  const health = await hostDriveHelperHealth(2_000, { force: true });
  if (!health?.ok) return { ok: false, devices: [], warnings: [], error: "Host drive helper is offline" };
  try {
    const res = await fetch(`${HELPER_BASE}/acquisition/devices`, {
      method: "GET",
      headers: helperHeaders(),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const data = (await res.json()) as {
      ok?: boolean;
      devices?: HostAcquisitionDevice[];
      warnings?: string[];
      error?: string;
    };
    return {
      ok: Boolean(res.ok && data.ok !== false),
      devices: tagAttachHost(data.devices ?? [], "this_pc"),
      warnings: data.warnings ?? [],
      error: data.error,
    };
  } catch (e: unknown) {
    return { ok: false, devices: [], warnings: [], error: e instanceof Error ? e.message : "Host device scan failed" };
  }
}

/** Office-server + this-PC USB scan (WPD/MTP/ADB/usbmux). No extra adapter required. */
export async function getHostAcquisitionDevices(timeoutMs = 20_000): Promise<{
  ok: boolean;
  devices: HostAcquisitionDevice[];
  warnings: string[];
  error?: string;
}> {
  const [office, local] = await Promise.all([
    fromOfficeApiAcquisitionDevices(timeoutMs),
    fromLocalHelperAcquisitionDevices(timeoutMs),
  ]);
  const devices = mergeAcquisitionDevices(office?.devices ?? [], local.devices);
  const warnings = [...(office?.warnings ?? []), ...local.warnings];
  const ok = Boolean(devices.length || office?.ok || local.ok);
  return {
    ok,
    devices,
    warnings,
    error: ok ? undefined : local.error || office?.error,
  };
}

/** Direct host preview fallback when the API container cannot yet reach host.docker.internal. */
export async function getHostAcquisitionPreview<T = unknown>(
  adapter: string,
  deviceId: string,
  timeoutMs = 20_000,
  label?: string,
): Promise<T | null> {
  const health = await hostDriveHelperHealth(2_000, { force: true });
  if (!health?.ok) return null;
  try {
    const res = await fetch(`${HELPER_BASE}/acquisition/preview`, {
      method: "POST",
      headers: { ...helperHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ adapter, device_id: deviceId, label: label || undefined }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const data = (await res.json()) as T & { ok?: boolean; error?: string };
    if (!res.ok || data?.ok === false) return null;
    return data;
  } catch {
    return null;
  }
}

export async function startHostAcquisitionRun(
  payload: Record<string, unknown>,
  timeoutMs = 30_000,
): Promise<{ ok: boolean; job_id?: string; async?: boolean; error?: string; busy?: boolean } | null> {
  const health = await hostDriveHelperHealth(2_000, { force: true });
  if (!health?.ok) return null;
  try {
    const adapter = String(payload.adapter || "");
    const qs = /mtp/i.test(adapter) ? "?native=mtp" : /ios/i.test(adapter) ? "?native=ios" : "";
    const res = await fetch(`${HELPER_BASE}/acquisition/run${qs}`, {
      method: "POST",
      headers: { ...helperHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const data = (await res.json()) as {
      ok: boolean;
      job_id?: string;
      async?: boolean;
      error?: string;
      busy?: boolean;
    };
    if (data?.ok === false && (res.status === 409 || data.busy || isUsbCollectionBusyError(data.error))) {
      return {
        ok: false,
        busy: true,
        error: data.error || "Another USB collection is already running.",
      };
    }
    return data;
  } catch (e: unknown) {
    return { ok: false, error: e instanceof Error ? e.message : "Host acquire start failed" };
  }
}

let jobPollOfflineUntilMs = 0;

export async function getHostAcquisitionJob(
  jobId: string,
  timeoutMs = 12_000,
): Promise<{ ok?: boolean; status?: string; result?: unknown; error?: string } | null> {
  if (Date.now() < jobPollOfflineUntilMs) return null;
  try {
    const res = await fetch(`${HELPER_BASE}/acquisition/job/${encodeURIComponent(jobId)}`, {
      method: "GET",
      headers: helperHeaders(),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) return null;
    jobPollOfflineUntilMs = 0;
    return (await res.json()) as { ok?: boolean; status?: string; result?: unknown; error?: string };
  } catch {
    // Do not black out polling for long — ZIP seal completion is missed if we skip ticks.
    jobPollOfflineUntilMs = Date.now() + 1_500;
    return null;
  }
}

export type HostAcquisitionJobSummary = {
  job_id: string;
  status?: string;
  run_name?: string;
  case_id?: string;
  detail?: string;
  files_seen?: number;
  bytes_done?: number;
};

export async function listHostAcquisitionJobs(
  timeoutMs = 8_000,
): Promise<HostAcquisitionJobSummary[]> {
  try {
    const res = await fetch(`${HELPER_BASE}/acquisition/jobs`, {
      method: "GET",
      headers: helperHeaders(),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) return [];
    const data = (await res.json()) as { ok?: boolean; jobs?: HostAcquisitionJobSummary[] };
    return Array.isArray(data.jobs) ? data.jobs : [];
  } catch {
    return [];
  }
}

/** Host helper job ids are Guid N (32 hex). Docker registry ids are 16 hex. */
export function isHostAcquisitionJobId(id: string | undefined | null): boolean {
  return /^[0-9a-f]{32}$/i.test(String(id || "").trim());
}

export async function cancelHostAcquisitionJob(
  jobId?: string | null,
  timeoutMs = 20_000,
): Promise<{ ok?: boolean; message?: string; error?: string; cancelled?: string[] } | null> {
  try {
    const payload: Record<string, string> = {};
    const id = String(jobId || "").trim();
    if (id) payload.job_id = id;
    const res = await fetch(`${HELPER_BASE}/acquisition/cancel`, {
      method: "POST",
      headers: { ...helperHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(timeoutMs),
    });
    return (await res.json()) as {
      ok?: boolean;
      message?: string;
      error?: string;
      cancelled?: string[];
    };
  } catch {
    return null;
  }
}

/** Stop every in-progress helper USB collection (no job id required). */
export async function stopAnyUsbAcquisition(timeoutMs = 20_000) {
  return cancelHostAcquisitionJob("", timeoutMs);
}

export async function removeHostAcquisitionJob(
  jobId: string,
  extras?: {
    run_name?: string;
    case_id?: string;
    progress_file?: string;
    paths?: Record<string, string>;
  },
  timeoutMs = 60_000,
): Promise<{ ok?: boolean; message?: string; error?: string; removed?: string[] } | null> {
  try {
    const res = await fetch(`${HELPER_BASE}/acquisition/remove`, {
      method: "POST",
      headers: { ...helperHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ job_id: jobId, ...(extras || {}) }),
      signal: AbortSignal.timeout(timeoutMs),
    });
    return (await res.json()) as {
      ok?: boolean;
      message?: string;
      error?: string;
      removed?: string[];
    };
  } catch {
    return null;
  }
}

export async function resolveFolderOnHost(
  body: { filenames: string[]; folder_hint?: string; relative_paths?: string[] },
  timeoutMs = 90_000
): Promise<ResolveFolderOnHostResult | null> {
  const online = await hostDriveHelperHealth(1500);
  if (!online?.ok) {
    return null;
  }
  try {
    const res = await fetch(`${HELPER_BASE}/resolve-folder`, {
      method: "POST",
      headers: { ...helperHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const data = (await res.json()) as ResolveFolderOnHostResult;
    markOnline({ ok: true });
    // Return structured failure so callers can skip the slow API deep-scan fallback.
    if (!res.ok || !data.ok || !data.path) {
      return {
        ok: false,
        path: null,
        error: data.error || "Folder not found on this PC",
        segment_count: data.segment_count,
        helperResponded: true,
      };
    }
    return { ...data, helperResponded: true };
  } catch {
    // Long resolve must not flip Health to down — probe before marking offline.
    const health = await hostDriveHelperHealth(1500, { force: true });
    if (!health?.ok) {
      markOffline();
    }
    return null;
  }
}

export type HostDirectoryEntry = {
  name: string;
  kind: "dir" | "file";
  size_bytes?: number | null;
};

export type HostDirectoryResult = {
  ok: boolean;
  path?: string | null;
  count?: number;
  entries?: HostDirectoryEntry[];
  error?: string;
  source?: string;
  healed?: boolean;
};

async function listOfficeHostDriveLettersDirect(timeoutMs: number): Promise<HostDriveLettersResult | null> {
  if (!isBrowserOnOfficeHost()) return null;
  const health = await hostDriveHelperHealth(Math.min(timeoutMs, 1500));
  if (!health?.ok) return null;
  try {
    const res = await fetch(`${HELPER_BASE}/drives`, {
      method: "GET",
      headers: helperHeaders(),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const data = (await res.json()) as HostDriveLettersResult;
    if (!res.ok || !data?.ok) return null;
    return data;
  } catch {
    return null;
  }
}

export async function listOfficeServerDriveLetters(timeoutMs = 8000): Promise<HostDriveLettersResult | null> {
  const direct = await listOfficeHostDriveLettersDirect(timeoutMs);
  if (direct?.ok && (direct.volumes?.length || direct.drives?.length)) {
    return { ...direct, helper_online: true, source: direct.source || "office_host_helper" };
  }
  try {
    const { api } = await import("./api");
    const data = await api.get<HostDriveLettersResult>("/api/hostdrive/drives", undefined, {
      timeoutMs,
    });
    if (data?.ok && (data.volumes?.length || data.drives?.length)) {
      return data;
    }
    return data?.ok ? data : direct;
  } catch {
    return direct;
  }
}

export async function listOfficeServerDirectory(path: string, timeoutMs = 120_000): Promise<HostDirectoryResult | null> {
  try {
    const { api } = await import("./api");
    const data = await api.post<HostDirectoryResult>(
      "/api/hostdrive/list-dir",
      { path },
      { timeoutMs }
    );
    if (data?.ok) return data;
    return data?.error ? data : null;
  } catch {
    return null;
  }
}

export async function listHostDirectory(
  path: string,
  timeoutMs = 120_000
): Promise<HostDirectoryResult | null> {
  const office = await listOfficeServerDirectory(path, timeoutMs);
  if (office) return office;
  const online = await hostDriveHelperHealth(1500);
  if (!online?.ok) return null;
  try {
    const res = await fetch(`${HELPER_BASE}/list-dir`, {
      method: "POST",
      headers: { ...helperHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify({ path }),
      signal: AbortSignal.timeout(Math.min(timeoutMs, 8_000)),
    });
    const data = (await res.json()) as HostDirectoryResult;
    if (!res.ok || !data.ok) {
      return data?.error ? data : null;
    }
    return data;
  } catch {
    return null;
  }
}

export async function listHostDriveLetters(timeoutMs = 8000): Promise<HostDriveLettersResult | null> {
  const office = await listOfficeServerDriveLetters(timeoutMs);
  if (office?.volumes?.length || office?.drives?.length) {
    return office;
  }
  const online = await hostDriveHelperHealth(1500);
  if (!online?.ok) {
    return office;
  }
  try {
    const res = await fetch(`${HELPER_BASE}/drives`, {
      method: "GET",
      headers: helperHeaders(),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const data = (await res.json()) as HostDriveLettersResult;
    if (!res.ok || !data.ok) {
      return office;
    }
    return data;
  } catch {
    markOffline();
    return office;
  }
}

async function fromOfficeApiMobileDevices(timeoutMs: number): Promise<HostMobileDevicesResult | null> {
  try {
    const { api } = await import("./api");
    const data = await api.get<HostMobileDevicesResult>("/api/hostdrive/mobile-devices", undefined, {
      timeoutMs,
    });
    if (!data) return null;
    return {
      ...data,
      mobile_devices: tagAttachHost(data.mobile_devices ?? [], "office_server"),
    };
  } catch {
    return null;
  }
}

export async function listHostMobileDevices(timeoutMs = 4000): Promise<HostMobileDevicesResult | null> {
  const office = await fromOfficeApiMobileDevices(timeoutMs);
  const online = await hostDriveHelperHealth(1500);
  let local: HostMobileDevicesResult | null = null;
  if (online?.ok) {
    try {
      const res = await fetch(`${HELPER_BASE}/mobile-devices`, {
        method: "GET",
        headers: helperHeaders(),
        signal: AbortSignal.timeout(timeoutMs),
      });
      const data = (await res.json()) as HostMobileDevicesResult;
      if (res.ok && data.ok) {
        local = {
          ...data,
          mobile_devices: tagAttachHost(data.mobile_devices ?? [], "this_pc"),
        };
      }
    } catch {
      markOffline();
    }
  }
  const mobile_devices = mergeMobileDevices(office?.mobile_devices ?? [], local?.mobile_devices ?? []);
  if (!mobile_devices.length && !office && !local) return office ?? local;
  return {
    ok: true,
    mobile_devices,
    count: mobile_devices.length,
    ios_backup_roots: [...(office?.ios_backup_roots ?? []), ...(local?.ios_backup_roots ?? [])],
  };
}

export type MobileAcquireResult = {
  ok: boolean;
  job_id?: string;
  mobile_job_id?: string;
  output_path?: string;
  acquisition_dir?: string;
  backup_path?: string;
  zip_path?: string;
  zip_name?: string;
  zip_bytes?: number;
  files_copied?: number;
  primary_method?: string;
  methods?: string[];
  warnings?: string[];
  message?: string;
  error?: string;
  log_path?: string;
  busy?: boolean;
};

export function isUsbCollectionBusyError(raw: string | undefined | null): boolean {
  const lower = String(raw || "").toLowerCase();
  return (
    lower.includes("another usb collection") ||
    lower.includes("already being acquired") ||
    (lower.includes("usb") && lower.includes("already running"))
  );
}

/** Map host-helper error codes to examiner-facing text. */
export function friendlyMobileAcquireError(raw: string): string {
  const code = (raw || "").trim();
  const lower = code.toLowerCase();
  if (isUsbCollectionBusyError(lower)) {
    return "A USB collection is already running. Click Stop USB collection, then start again, or register an existing backup folder (Manifest.db or Manifest.plist).";
  }
  if (
    lower.includes("ios_backup_device_locked") ||
    lower.includes("errorcode 208") ||
    lower.includes("mberrordomain/208")
  ) {
    return "iPhone reported Error 208 (screen locked). Unlock the phone, keep the screen awake, then click Try again. Or register an existing backup folder (Manifest.db or Manifest.plist).";
  }
  if (lower.includes("ios_pair_needs_passcode") || lower.includes("ios_pair_needs_trust")) {
    return "Unlock the iPhone, enter the passcode when prompted, tap Trust This Computer, then retry.";
  }
  if (lower.includes("apple_mobile_device_support_missing")) {
    return "Apple Mobile Device Support is not installed. Run: winget install Apple.AppleMobileDeviceSupport";
  }
  if (lower.includes("ios_device_not_visible")) {
    return "iPhone not visible over USB. Unlock, Trust This Computer, and ensure Apple Mobile Device Service is running.";
  }
  if (lower.includes("idevicebackup2_not_found")) {
    return "iOS backup tools missing under tools\\libimobiledevice. Restart the host drive helper after installing them.";
  }
  if (lower.includes("path_too_long") || lower.includes("snapshot") && lower.includes("no such file")) {
    return "The iPhone backup path was too long for Windows. Unlock the phone and retry — iOS Agent now writes to a short staging folder first.";
  }
  if (
    lower.includes("ios_backup_not_enough_disk_space") ||
    lower.includes("notenoughdiskspace") ||
    lower.includes("not enough disk")
  ) {
    return "The iPhone backup volume ran out of space. The phone does not need to be unlocked again. Retry Advanced Logical — iOS Agent will write to a drive with free space. Photos already pulled over AFC are kept.";
  }
  if (
    lower.includes("mobile_export_insufficient_space") ||
    lower.includes("not enough free space for the complete mobile evidence zip")
  ) {
    return `The complete evidence ZIP cannot fit on the available export volumes. Aetheris has kept the acquired source unchanged and will not substitute a tiny metadata ZIP. Free space or set AETHERIS_EXPORT_ROOT to another drive, then retry Export. ${code}`;
  }
  if (lower.includes("ios_afc_not_enough_disk_space")) {
    return "There is not enough free space to collect the iPhone AFC/shared-media stage. Free space or choose a larger acquisition drive, then retry; the collection will not be marked complete without this stage.";
  }
  if (lower.includes("ios_afc_collected_but_itunes_backup_incomplete")) {
    return "Shared photos and WhatsApp container files were collected, but the iTunes-style backup did not finish. Retry Advanced Logical so chats and hashed backup files can be written to a drive with free space.";
  }
  if (
    lower.includes("ios_backup_usb_connection_dropped") ||
    lower.includes("connectionterminated") ||
    lower.includes("connection terminated")
  ) {
    return "USB backup session dropped before the iPhone finished writing Manifest.db. Unlock the phone, keep the screen awake, leave the cable seated, then retry. iOS Agent will resume into a short staging folder.";
  }
  if (
    lower.includes("ios_backup_incomplete") ||
    lower.includes("ios_backup_missing_manifest")
  ) {
    return "iPhone backup did not finish writing Manifest.db. If the phone is already unlocked and trusted, this is not a lock-screen problem — retry Advanced Logical so iOS Agent can resume on a drive with free space.";
  }
  return code.replace(/_/g, " ");
}

/**
 * Live mobile acquire for a forensic job panel.
 *
 * Prefers the UFED-aligned Python CollectionOrchestrator via the host drive
 * helper (`POST /acquire` → `python -m app.services.mobile_acquire.cli`).
 * For full Device Wizard (authority, method override, SSE), use
 * `/forensic/mobile/acquire` + `acquisitionApi` instead.
 */
export async function startMobileAcquisition(
  body: {
    job_id: string;
    device_id?: string;
    device_name?: string;
    os_hint?: string;
    instance_id?: string;
    output_root?: string;
  },
  timeoutMs = 7 * 24 * 60 * 60 * 1000
): Promise<MobileAcquireResult> {
  invalidateHelperHealthCache();
  const online = await hostDriveHelperHealth(2000, { force: true });
  if (!online?.ok) {
    return { ok: false, error: "Host drive helper is offline (port 9876)" };
  }
  try {
    const res = await fetch(`${HELPER_BASE}/acquire`, {
      method: "POST",
      headers: { ...helperHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
    const data = (await res.json()) as MobileAcquireResult;
    if (res.status === 409 || (data.ok === false && (data.busy || isUsbCollectionBusyError(data.error)))) {
      markOnline({ ok: true, busy: true });
      return {
        ok: false,
        busy: true,
        error:
          data.error ??
          "Another USB collection is already running. Click Stop USB collection, then start again, or register an existing backup folder.",
      };
    }
    if (!res.ok) {
      if (res.status >= 500) {
        const health = await hostDriveHelperHealth(1500, { force: true });
        if (!health?.ok) markOffline();
      }
      return { ok: false, error: data.error ?? res.statusText };
    }
    if (data.ok) {
      markOnline({ ok: true });
    }
    return data;
  } catch (e: unknown) {
    markOffline();
    const message = e instanceof Error ? e.message : "Mobile acquisition failed";
    return { ok: false, error: message };
  }
}

async function getRefreshDriveMountsStatus(timeoutMs = 5_000): Promise<RefreshDriveMountsStatus | null> {
  try {
    const res = await fetch(`${HELPER_BASE}/refresh-drive-mounts`, {
      method: "GET",
      headers: helperHeaders(),
      signal: AbortSignal.timeout(timeoutMs),
    });
    if (!res.ok) return null;
    return (await res.json()) as RefreshDriveMountsStatus;
  } catch {
    return null;
  }
}

async function waitForDriveMountRefresh(
  timeoutMs: number,
  initialMessage = "Refreshing drive mounts…"
): Promise<RefreshDriveMountsResult> {
  const deadline = Date.now() + timeoutMs;
  let lastMessage = initialMessage;
  while (Date.now() < deadline) {
    await new Promise((resolve) => setTimeout(resolve, 1500));
    const status = await getRefreshDriveMountsStatus();
    if (!status) continue;
    if (status.message) lastMessage = status.message;
    if (status.status === "done") {
      markOnline({ ok: true });
      return {
        ok: Boolean(status.ok ?? true),
        drives: status.drives,
        message: status.message ?? lastMessage,
        log: status.log,
        unchanged: status.unchanged,
        status: status.status,
        mount_mode: status.mount_mode,
        mount_source: status.mount_source,
        wsl_distro: status.wsl_distro,
        skipped_drives: status.skipped_drives,
        compose_base: status.compose_base,
      };
    }
    if (status.status === "error") {
      markOnline({ ok: true });
      return {
        ok: false,
        error: status.error ?? status.message ?? "Drive mount refresh failed",
        log: status.log,
        status: status.status,
        mount_mode: status.mount_mode,
        mount_source: status.mount_source,
        wsl_distro: status.wsl_distro,
        skipped_drives: status.skipped_drives,
        compose_base: status.compose_base,
      };
    }
  }
  markOnline({ ok: true });
  return {
    ok: false,
    error:
      "Drive mount refresh is still running. Wait for Health to stay green, then try registering segments again.",
    message: lastMessage,
    status: "running",
  };
}

/**
 * Start drive-mount refresh and poll until done.
 * Helper stays responsive (/health) while docker compose runs in a background job.
 * Does not mark the helper offline for transient API/container restart blips.
 */
export async function refreshDriveMounts(
  timeoutMs = 300_000,
  requiredPath?: string,
  retryAfterBusy = true
): Promise<RefreshDriveMountsResult> {
  invalidateHelperHealthCache();
  markOnline({ ok: true, busy: true });
  try {
    const res = await fetch(`${HELPER_BASE}/refresh-drive-mounts`, {
      method: "POST",
      headers: { ...helperHeaders(), "Content-Type": "application/json" },
      body: JSON.stringify(requiredPath ? { required_path: requiredPath } : {}),
      signal: AbortSignal.timeout(30_000),
    });
    const data = (await res.json()) as RefreshDriveMountsResult;
    if (!res.ok && res.status !== 202 && res.status !== 409) {
      // Only mark offline if helper itself is unreachable — not for job conflicts.
      if (res.status >= 500) {
        const health = await hostDriveHelperHealth(1500, { force: true });
        if (!health?.ok) markOffline();
      }
      return { ok: false, error: data.error ?? res.statusText };
    }

    // Another automatic/user refresh can already be running when a new drive is
    // plugged in. Join that job instead of failing the registration with HTTP 409.
    if (res.status === 409) {
      const joined = await waitForDriveMountRefresh(
        timeoutMs,
        data.message ?? data.error ?? "A drive refresh is already running…"
      );
      // If this request carried an exact selected path, do one final no-op/verify
      // refresh after the existing job. This guarantees RequiredPath validation.
      if (joined.ok && requiredPath && retryAfterBusy) {
        return refreshDriveMounts(timeoutMs, requiredPath, false);
      }
      return joined;
    }

    // Legacy sync helper: POST already finished the work.
    if (data.ok && !data.started && data.status !== "running") {
      markOnline({ ok: true });
      return data;
    }

    return waitForDriveMountRefresh(timeoutMs, data.message ?? "Refreshing drive mounts…");
  } catch (e: unknown) {
    const health = await hostDriveHelperHealth(2000, { force: true });
    if (!health?.ok) {
      markOffline();
    } else {
      markOnline(health);
    }
    const message = e instanceof Error ? e.message : "Host drive helper unreachable";
    return { ok: false, error: message };
  }
}

export function hostDriveHelperStartHint(): string {
  return "powershell -ExecutionPolicy Bypass -File scripts\\hostdrive-agent.ps1 -RefreshNow -Once";
}

export function hostDriveHelperInstallHint(): string {
  return "powershell -ExecutionPolicy Bypass -File scripts\\install-hostdrive-agent.ps1";
}

/** @deprecated Custom URL schemes are not used. Kept for older error strings. */
export function hostDriveAgentProtocolUrl(_action: "ensure" | "refresh" = "refresh"): string {
  return hostDriveHelperInstallHint();
}

/** Ask Windows to start the helper via the registered aetheris-hostdrive: handler. */
export function requestHostDriveHelperStart(): void {
  if (typeof document === "undefined") return;
  if (document.getElementById("aetheris-hostdrive-launch")) return;
  const iframe = document.createElement("iframe");
  iframe.id = "aetheris-hostdrive-launch";
  iframe.style.display = "none";
  iframe.src = "aetheris-hostdrive:ensure";
  document.body.appendChild(iframe);
  window.setTimeout(() => iframe.remove(), 5000);
}

/** Wait for the localhost helper, launching it via the registered protocol if needed. */
export async function startHostDriveAgentFromBrowser(
  maxWaitMs = 20_000
): Promise<HostDriveHelperHealth | null> {
  invalidateHelperHealthCache();
  const first = await hostDriveHelperHealth(1500, { force: true });
  if (first?.ok) return first;
  requestHostDriveHelperStart();
  return ensureHostDriveHelper(maxWaitMs, 1_500, { force: true });
}

export async function ensureOfficePathMounted(
  requiredPath: string
): Promise<RefreshDriveMountsResult & { path_ready?: boolean; mounted?: string[] }> {
  try {
    const { api } = await import("./api");
    const ensured = await api.post<{
      ok?: boolean;
      path_ready?: boolean;
      mounted?: string[];
      missing?: string[];
      message?: string;
      required_letter?: string | null;
      refresh_error?: string | null;
    }>("/api/hostdrive/ensure-path", { required_path: requiredPath }, { timeoutMs: 180_000 });
    // Exact evidence readability is authoritative. A mounted G: root can be a
    // stale bind left from a previously attached removable disk.
    if (ensured.ok !== false && ensured.path_ready === true) {
      return {
        ok: true,
        path_ready: true,
        mounted: ensured.mounted,
        message: ensured.message || `Docker can read ${requiredPath}`,
        drives: ensured.mounted,
      };
    }
    return {
      ok: false,
      path_ready: Boolean(ensured.path_ready),
      mounted: ensured.mounted,
      error:
        ensured.refresh_error ||
        ensured.message ||
        `Office Docker could not read ${requiredPath}` +
          (ensured.missing?.length ? ` (missing ${ensured.missing.join(", ")})` : ""),
    };
  } catch (e: unknown) {
    return {
      ok: false,
      error: e instanceof Error ? e.message : "Could not remount the selected office path",
    };
  }
}

/**
 * HostDrive agent entry: ensure helper online, refresh mounts, return drive letters.
 * Call this from Create job (syncAttached) and "Refresh drive mounts".
 */
export async function runHostDriveAgentRefresh(
  requiredPath?: string,
  opts?: { syncAttached?: boolean }
): Promise<RefreshDriveMountsResult & { drives?: string[] }> {
  invalidateHelperHealthCache();
  if (requiredPath) {
    const ensured = await ensureOfficePathMounted(requiredPath);
    return {
      ok: Boolean(ensured.ok),
      message: ensured.message,
      drives: ensured.drives || ensured.mounted,
      error: ensured.error,
    };
  }
  try {
    const { api } = await import("./api");
    const ensured = await api.post<{
      ok?: boolean;
      mounted?: string[];
      drives?: string[];
      windows_letters?: string[];
      missing?: string[];
      newly_attached?: string[];
      message?: string;
      helper_online?: boolean;
      start_hint?: string;
      path_ready?: boolean;
      refresh?: { error?: string };
    }>(
      "/api/hostdrive/ensure-all",
      { sync_attached: Boolean(opts?.syncAttached) },
      { timeoutMs: 180_000 }
    );
    const windowsLetters = ensured.windows_letters?.length
      ? ensured.windows_letters
      : ensured.drives?.length
        ? ensured.drives
        : ensured.mounted || [];
    const mounted = ensured.mounted || [];
    const extra = ensured.newly_attached?.length ? ensured.newly_attached : ensured.missing || [];
    if (ensured.ok && mounted.length) {
      return {
        ok: true,
        message: ensured.message || "Drive Mount Agent remounted attached drives",
        drives: windowsLetters.length ? windowsLetters : mounted,
        windows_letters: windowsLetters,
        mounted,
        missing: ensured.missing,
        newly_attached: extra,
      };
    }
    if ((ensured.missing || []).length && !mounted.length) {
      return {
        ok: false,
        message: ensured.message,
        drives: windowsLetters,
        error:
          ensured.message ||
          `Windows has ${windowsLetters.join(", ") || "drives"} but Docker is missing ${(ensured.missing || []).join(", ")}`,
      };
    }
    if (!requiredPath && ensured.helper_online === false && !mounted.length) {
      return {
        ok: false,
        error:
          ensured.start_hint ||
          `HostDrive agent is offline. Run once: ${hostDriveHelperInstallHint()}`,
      };
    }
  } catch {
    // Fall through to the helper-side refresh.
  }
  let health = await hostDriveHelperHealth(2000, { force: true });
  if (!health?.ok) {
    health = await startHostDriveAgentFromBrowser(25_000);
  }
  if (!health?.ok) {
    // Fall back: API can still see host.docker.internal from the server side.
    try {
      const { api } = await import("./api");
      const proxy = await api.post<{
        ok?: boolean;
        started?: boolean;
        error?: string;
        message?: string;
        drives?: string[];
        start_hint?: string;
        protocol?: string;
        joined_existing?: boolean;
      }>(
        "/api/hostdrive/refresh",
        requiredPath ? { required_path: requiredPath } : {},
        { timeoutMs: 45_000 }
      );
      if (proxy.ok || proxy.started) {
        // Wait for helper to become reachable from the browser after host refresh.
        health = await ensureHostDriveHelper(60_000, 2_000, { force: true });
        if (health?.ok) {
          // The API fallback already POSTed /refresh-drive-mounts on the helper.
          // Do not POST a second time (that races the first job and returns 409).
          // Poll the existing background refresh until it completes.
          const joined = await waitForDriveMountRefresh(
            300_000,
            proxy.message ?? "HostDrive refresh started via API"
          );
          if (joined.ok && requiredPath && proxy.joined_existing) {
            // Existing watcher refresh did not carry this exact path. Verify it
            // now that the helper is reachable and the first job is complete.
            return refreshDriveMounts(300_000, requiredPath, false);
          }
          return joined;
        }
        return {
          ok: Boolean(proxy.ok || proxy.started),
          message: proxy.message ?? "HostDrive refresh started via API",
          drives: proxy.drives,
          error: proxy.ok ? undefined : proxy.error,
        };
      }
      return {
        ok: false,
        error:
          proxy.error ||
          `HostDrive agent is offline. Start it with: ${hostDriveHelperInstallHint()}`,
      };
    } catch {
      return {
        ok: false,
        error: `HostDrive agent is offline. Run once: ${hostDriveHelperInstallHint()}`,
      };
    }
  }
  return refreshDriveMounts(300_000, requiredPath);
}

/** Milliseconds until next health probe is allowed (0 = can probe now). */
export function helperOfflineRetryInMs(): number {
  if (reachability !== "offline") return 0;
  return Math.max(0, offlineUntilMs - Date.now());
}
