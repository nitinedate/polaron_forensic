/** Forensic datetime display helpers (browser local timezone with optional server hints). */

export interface TimestampFields {
  timestamp: string;
  timestamp_local?: string | null;
  timezone?: string | null;
  display_timestamp?: string | null;
}

export function formatForensicTimestamp(
  row: TimestampFields | string,
  options?: { dateStyle?: "short" | "medium"; showTimezone?: boolean }
): string {
  const showTimezone = options?.showTimezone ?? true;
  if (typeof row === "object" && row.display_timestamp) {
    return showTimezone && row.timezone
      ? `${row.display_timestamp} (${row.timezone})`
      : row.display_timestamp;
  }

  const iso = typeof row === "string" ? row : row.timestamp_local || row.timestamp;
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;

  const formatted = d.toLocaleString(undefined, {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  });

  if (typeof row === "object" && row.timezone && showTimezone) {
    return `${formatted} (${row.timezone})`;
  }
  const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
  return showTimezone ? `${formatted} (${tz})` : formatted;
}

export function formatLogLineTimestamp(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, {
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  });
}

const IST_ZONE = "Asia/Kolkata";

/** Display an instant in Indian Standard Time. */
export function formatIstTimestamp(iso: string | null | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const formatted = d.toLocaleString("en-IN", {
    timeZone: IST_ZONE,
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: true,
  });
  return formatted;
}

/** Interpret a datetime-local value as IST and return an offset ISO string. */
export function istLocalInputToQuery(value: string): string | undefined {
  const raw = value.trim();
  if (!raw) return undefined;
  if (/Z$|[+-]\d{2}:?\d{2}$/.test(raw)) return raw;
  return raw.length === 16 ? `${raw}:00+05:30` : `${raw}+05:30`;
}
