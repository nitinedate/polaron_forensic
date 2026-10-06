import { aetherisService } from "./serviceMode";

export type ApiService = "forensic" | "mobile-android" | "mobile-ios" | "mobile-extract" | "vuln";

const VULN_PREFIXES = [
  "/api/vuln", "/api/scanners", "/api/scanner-agent", "/api/scan-jobs", "/api/scan-policies",
  "/api/assets", "/api/remediation-tasks",
];

const JOB_ID_RE = /\/api\/(?:jobs|reports)\/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})/;
const JOB_SERVICE_LS = "aetheris.jobApiService.v2";
const JOB_SERVICE_CAP = 300;
const memoryJobService = new Map<string, ApiService>();
const goneJobIds = new Set<string>();

function isJobApiService(value: unknown): value is ApiService {
  return value === "forensic" || value === "mobile-android" || value === "mobile-ios" || value === "mobile-extract" || value === "vuln";
}

function pathIsVuln(path: string): boolean {
  if (VULN_PREFIXES.some((p) => path === p || path.startsWith(`${p}/`) || path.startsWith(`${p}?`))) return true;
  return /\/api\/cases\/[^/]+\/(scan-jobs|vulnerabilities|pci-readiness|asv|pentest|gap-|vuln-report)/.test(path);
}

function configuredMobileService(): ApiService | null {
  const mode = aetherisService();
  if (mode === "mobile-android" || mode === "mobile-ios" || mode === "mobile-extract") return mode;
  return null;
}

function browserRouteService(): ApiService | null {
  const configured = configuredMobileService();
  if (configured) return configured;
  if (typeof window === "undefined") return null;
  const route = window.location.pathname;
  if (route.startsWith("/mobile/android") || route.startsWith("/android-mobile")) return "mobile-android";
  if (route.startsWith("/mobile/ios") || route.startsWith("/ios-mobile")) return "mobile-ios";
  if (route.startsWith("/forensic/mobile")) return "mobile-extract";
  if (route.startsWith("/vuln")) return "vuln";
  return null;
}

export function jobIdFromApiPath(path: string): string | null {
  return path.match(JOB_ID_RE)?.[1] ?? null;
}

function readPersistedJobServices(): Record<string, ApiService> {
  if (typeof window === "undefined") return {};
  try {
    const parsed = JSON.parse(window.localStorage.getItem(JOB_SERVICE_LS) || "{}") as Record<string, unknown>;
    const clean: Record<string, ApiService> = {};
    for (const [id, svc] of Object.entries(parsed || {})) if (isJobApiService(svc)) clean[id] = svc;
    return clean;
  } catch { return {}; }
}

function persistJobServices(): void {
  if (typeof window === "undefined") return;
  const stored = readPersistedJobServices();
  for (const [id, svc] of memoryJobService) stored[id] = svc;
  const ids = Object.keys(stored);
  if (ids.length > JOB_SERVICE_CAP) for (const id of ids.slice(0, ids.length - JOB_SERVICE_CAP)) delete stored[id];
  try { window.localStorage.setItem(JOB_SERVICE_LS, JSON.stringify(stored)); } catch { /* ignore */ }
}

export function rememberJobService(jobId: string, service: ApiService): void {
  if (!jobId || service === "vuln") return;
  memoryJobService.set(jobId, service);
  persistJobServices();
}

export function lookupJobService(jobId: string): ApiService | undefined {
  if (!jobId) return undefined;
  const live = memoryJobService.get(jobId);
  if (live) return live;
  const stored = readPersistedJobServices()[jobId];
  if (stored) { memoryJobService.set(jobId, stored); return stored; }
  return undefined;
}

export function markJobGone(jobId: string): void {
  if (!jobId) return;
  goneJobIds.add(jobId); memoryJobService.delete(jobId);
  if (typeof window === "undefined") return;
  try {
    const stored = readPersistedJobServices(); delete stored[jobId];
    window.localStorage.setItem(JOB_SERVICE_LS, JSON.stringify(stored));
  } catch { /* ignore */ }
}
export function isJobGone(jobId: string): boolean { return Boolean(jobId) && goneJobIds.has(jobId); }
export function clearJobGone(jobId: string): void { if (jobId) goneJobIds.delete(jobId); }

export function serviceForJobCreate(type?: string | null, sourceType?: string | null, mobileOs?: string | null): ApiService {
  const t = (type || "").trim().toLowerCase();
  const src = (sourceType || "").trim().toLowerCase();
  const os = (mobileOs || "").trim().toLowerCase();
  if (t === "android_mobile" || t === "android_backup" || src === "android_backup" || os === "android") return "mobile-android";
  if (t === "ios_mobile" || t === "ios_backup" || src === "ios_backup" || os === "ios") return "mobile-ios";
  if (t === "mobile_extraction" || src === "mobile") return configuredMobileService() || "mobile-extract";
  return "forensic";
}

/** Which physically isolated API should handle this request. */
export function inferApiService(path: string, explicit?: ApiService): ApiService {
  if (explicit) return explicit;
  if (pathIsVuln(path)) return "vuln";
  const jobId = jobIdFromApiPath(path);
  if (jobId) {
    const pinned = lookupJobService(jobId);
    if (pinned) return pinned;
  }
  if (path.startsWith("/api/acquisition")) return browserRouteService() || configuredMobileService() || "mobile-android";
  if (path.startsWith("/api/jobs") || path.startsWith("/api/reports") || path.startsWith("/api/cases") || path.startsWith("/api/hostdrive")) {
    return browserRouteService() || configuredMobileService() || "forensic";
  }
  return configuredMobileService() || "forensic";
}

/** Cross-product 404 fallback is intentionally disabled. Isolation is a security boundary. */
export function alternateJobService(_service: ApiService): ApiService | null { return null; }
export function serviceHeaders(path: string, explicit?: ApiService): Record<string, string> {
  return { "X-Aetheris-Service": inferApiService(path, explicit) };
}
