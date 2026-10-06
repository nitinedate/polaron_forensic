/**
 * Thin API client for the IAM gateway.
 *
 * - Attaches the tenant (`X-Tenant`) header and bearer token to every request.
 * - Transparently refreshes the access token once on a 401, then retries.
 *
 * Tokens are kept in localStorage for persistence across reloads. (For a
 * higher-security posture, move the refresh token to an httpOnly cookie issued
 * by a small BFF; the API already supports rotation.)
 */
import { serviceHeaders, type ApiService } from "./apiRouting";

export type { ApiService };

/** Empty = same-origin /api (Vite or nginx proxy to gateway). Set VITE_API_BASE for external hosts. */
export const API_BASE: string = (import.meta.env.VITE_API_BASE as string | undefined) ?? "";

const REQUEST_TIMEOUT_MS = 15_000;
export const DEFAULT_TENANT: string = (import.meta.env.VITE_DEFAULT_TENANT as string) || "platform";

const LS = {
  access: "iam.accessToken",
  refresh: "iam.refreshToken",
  tenant: "iam.tenant",
};

export const tokenStore = {
  access: () => localStorage.getItem(LS.access),
  refresh: () => localStorage.getItem(LS.refresh),
  tenant: () => localStorage.getItem(LS.tenant) || DEFAULT_TENANT,
  set(access: string, refresh: string) {
    localStorage.setItem(LS.access, access);
    localStorage.setItem(LS.refresh, refresh);
  },
  setTenant(tenant: string) {
    localStorage.setItem(LS.tenant, tenant);
  },
  clear() {
    localStorage.removeItem(LS.access);
    localStorage.removeItem(LS.refresh);
  },
};

export class ApiError extends Error {
  status: number;
  code: string;
  constructor(status: number, code: string, message: string) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

interface RequestOptions {
  method?: string;
  body?: unknown;
  auth?: boolean; // attach bearer token (default true)
  tenant?: boolean; // attach X-Tenant header (default true)
  query?: Record<string, string | number | boolean | undefined>;
  /** Override default 15s abort (e.g. inventory during large jobs). */
  timeoutMs?: number;
  /** Force which isolated backend the gateway should use. */
  service?: ApiService;
}

async function parse(res: Response): Promise<any> {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

export function resolveApiUrl(path: string, query?: RequestOptions["query"]): string {
  const base = API_BASE.replace(/\/$/, "");
  const url = base
    ? new URL(base + path)
    : new URL(path, typeof window !== "undefined" ? window.location.origin : "http://localhost");
  if (query) {
    for (const [k, v] of Object.entries(query)) {
      if (v !== undefined && v !== "") url.searchParams.set(k, String(v));
    }
  }
  return base ? url.toString() : `${url.pathname}${url.search}`;
}

async function rawRequest(path: string, opts: RequestOptions): Promise<Response> {
  const headers: Record<string, string> = {};
  const isForm = typeof FormData !== "undefined" && opts.body instanceof FormData;
  if (opts.body !== undefined && !isForm) headers["Content-Type"] = "application/json";
  if (opts.tenant !== false) {
    const slug = (tokenStore.tenant() || DEFAULT_TENANT).trim().toLowerCase();
    headers["X-Tenant"] = slug || DEFAULT_TENANT;
  }
  if (opts.auth !== false) {
    const token = tokenStore.access();
    if (token) headers["Authorization"] = `Bearer ${token}`;
  }
  Object.assign(headers, serviceHeaders(path, opts.service));
  const controller = new AbortController();
  const timeoutMs = opts.timeoutMs ?? REQUEST_TIMEOUT_MS;
  const timeout = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(resolveApiUrl(path, opts.query), {
      method: opts.method || "GET",
      headers,
      body:
        opts.body === undefined ? undefined : isForm ? (opts.body as FormData) : JSON.stringify(opts.body),
      signal: controller.signal,
    });
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new ApiError(
        0,
        "timeout",
        "Request timed out while contacting the product API through the Enterprise Console. Check the gateway and the selected product backend, then try again."
      );
    }
    const target = API_BASE || "the Vite dev proxy (/api -> localhost:8080)";
    throw new ApiError(
      0,
      "network_error",
      `Unable to reach the API server via ${target}. Ensure the gateway is running (e.g. make up).`
    );
  } finally {
    clearTimeout(timeout);
  }
}

let refreshing: Promise<boolean> | null = null;
let refreshCooldownUntil = 0;

const REFRESH_FAILURE_COOLDOWN_MS = 60_000;
const REFRESH_DEBOUNCE_MS = 2_000;

function decodeJwtExpMs(token: string): number | null {
  try {
    const payload = token.split(".")[1];
    if (!payload) return null;
    const json = JSON.parse(atob(payload.replace(/-/g, "+").replace(/_/g, "/")));
    return typeof json.exp === "number" ? json.exp * 1000 : null;
  } catch {
    return null;
  }
}

function accessTokenFresh(skewSeconds: number): boolean {
  const token = tokenStore.access();
  if (!token) return false;
  const expMs = decodeJwtExpMs(token);
  if (!expMs) return true;
  return Date.now() < expMs - skewSeconds * 1000;
}

function notifySessionExpired(): void {
  tokenStore.clear();
  if (typeof window !== "undefined") {
    window.dispatchEvent(new CustomEvent("iam:session-expired"));
  }
}

/** Refresh the access token using the stored refresh token. */
export async function refreshAccessToken(): Promise<boolean> {
  return tryRefresh();
}

/** Refresh only when the access token is missing or near expiry. Respects cooldown after failures. */
export async function ensureFreshAccessToken(skewSeconds = 120): Promise<boolean> {
  if (accessTokenFresh(skewSeconds)) return true;
  if (Date.now() < refreshCooldownUntil) return false;
  return tryRefresh();
}

export function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/** Poll until nginx can reach the API. Docker "running" is not the same as ready after a remount recreate. */
export async function waitForApiReady(timeoutMs = 180_000): Promise<boolean> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(resolveApiUrl("/api/health"), {
        method: "GET",
        headers: { Accept: "application/json" },
        signal: AbortSignal.timeout(4000),
      });
      if (res.ok) return true;
    } catch {
      /* 502 / connection refused while uvicorn is still starting */
    }
    await sleep(1500);
  }
  return false;
}

async function tryRefresh(): Promise<boolean> {
  if (Date.now() < refreshCooldownUntil) return false;

  const refresh = tokenStore.refresh();
  if (!refresh) {
    notifySessionExpired();
    return false;
  }

  if (!refreshing) {
    refreshing = (async () => {
      try {
        const res = await rawRequest("/api/auth/refresh", {
          method: "POST",
          body: { refresh_token: refresh },
          auth: false,
        });
        if (!res.ok) {
          refreshCooldownUntil = Date.now() + REFRESH_FAILURE_COOLDOWN_MS;
          if (!accessTokenFresh(0)) notifySessionExpired();
          return false;
        }
        const data = await parse(res);
        tokenStore.set(data.access_token, data.refresh_token);
        refreshCooldownUntil = 0;
        return true;
      } catch {
        refreshCooldownUntil = Date.now() + REFRESH_FAILURE_COOLDOWN_MS;
        return false;
      } finally {
        setTimeout(() => {
          refreshing = null;
        }, REFRESH_DEBOUNCE_MS);
      }
    })();
  }
  return refreshing;
}

export async function request<T = any>(path: string, opts: RequestOptions = {}): Promise<T> {
  if (opts.auth !== false && !accessTokenFresh(300)) {
    await tryRefresh();
  }
  let res = await rawRequest(path, opts);

  if (res.status === 401 && opts.auth !== false) {
    const ok = await tryRefresh();
    if (ok) {
      res = await rawRequest(path, opts);
    } else if (!accessTokenFresh(0)) {
      notifySessionExpired();
    }
  }

  // One short retry for a gateway blip. Do not sit on 503/busy or stack
  // 36s of backoff — pages must stay interactive while an API is blocked.
  if (res.status === 502 || res.status === 504) {
    await sleep(400);
    res = await rawRequest(path, opts);
  }


  if (!res.ok) {
    const data = await parse(res);
    const err = data?.error;
    const fallback =
      res.status === 502
        ? "Bad Gateway — the API is still starting (or was just restarted). Wait a few seconds and try again."
        : res.statusText;
    throw new ApiError(res.status, err?.code || "error", err?.message || fallback);
  }
  return (await parse(res)) as T;
}

export const api = {
  get: <T = any>(path: string, query?: RequestOptions["query"], extra?: Partial<RequestOptions>) =>
    request<T>(path, { query, ...extra }),
  post: <T = any>(path: string, body?: unknown, extra?: Partial<RequestOptions>) =>
    request<T>(path, { method: "POST", body, ...extra }),
  postForm: <T = any>(path: string, body: FormData, extra?: Partial<RequestOptions>) =>
    request<T>(path, { method: "POST", body, timeoutMs: extra?.timeoutMs ?? 180_000, ...extra }),
  put: <T = any>(path: string, body?: unknown, extra?: Partial<RequestOptions>) =>
    request<T>(path, { method: "PUT", body, ...extra }),
  patch: <T = any>(path: string, body?: unknown, extra?: Partial<RequestOptions>) =>
    request<T>(path, { method: "PATCH", body, ...extra }),
  del: <T = any>(path: string, extra?: Partial<RequestOptions>) =>
    request<T>(path, { method: "DELETE", ...extra }),
  /** Fetch a binary/text attachment with auth headers and trigger a browser download. */
  download: async (
    path: string,
    filename: string,
    query?: RequestOptions["query"],
    timeoutMs = 180_000,
  ) => {
    if (!accessTokenFresh(300)) {
      await tryRefresh();
    }
    let res = await rawRequest(path, { query, timeoutMs });
    if (res.status === 401) {
      const ok = await tryRefresh();
      if (ok) res = await rawRequest(path, { query, timeoutMs });
    }
    if (!res.ok) {
      throw new ApiError(res.status, "download_failed", `Download failed (${res.status})`);
    }
    const blob = await res.blob();
    const contentDisposition = res.headers.get("Content-Disposition") || "";
    const encodedMatch = /filename\*=UTF-8''([^;]+)/i.exec(contentDisposition);
    const plainMatch = /filename=\"?([^\";]+)\"?/i.exec(contentDisposition);
    let responseFilename = (encodedMatch?.[1] || plainMatch?.[1] || "").trim();
    if (responseFilename) {
      try {
        responseFilename = decodeURIComponent(responseFilename.replace(/^\"|\"$/g, ""));
      } catch {
        responseFilename = responseFilename.replace(/^\"|\"$/g, "");
      }
    }
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    // Prefer the server's format-aware forensic report filename (.pdf/.docx).
    // The supplied argument remains a fallback for endpoints that do not send one.
    a.download = responseFilename || filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  },
};
