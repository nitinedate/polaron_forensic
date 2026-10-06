/**
 * Convert API/database numeric values into a safe finite number for rendering.
 *
 * Forensic endpoints can legitimately return partial objects while a job is still
 * ingesting/indexing, and mixed-version deployments may omit newly-added count
 * fields. UI code must never call toLocaleString() on undefined/null values.
 */
export function safeNumber(value: unknown, fallback = 0): number {
  if (typeof value === "number") return Number.isFinite(value) ? value : fallback;
  if (typeof value === "bigint") return Number(value);
  if (typeof value === "string" && value.trim() !== "") {
    const parsed = Number(value);
    return Number.isFinite(parsed) ? parsed : fallback;
  }
  return fallback;
}

/** Counts are displayed as non-negative whole numbers. */
export function safeCount(value: unknown, fallback = 0): number {
  const n = safeNumber(value, fallback);
  return Math.max(0, Math.trunc(n));
}

export function formatCount(value: unknown, fallback = 0): string {
  return safeCount(value, fallback).toLocaleString();
}
