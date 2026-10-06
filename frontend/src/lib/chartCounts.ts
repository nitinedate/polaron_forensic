export type ChartDatum = {
  name: string;
  value: number;
  fill?: string;
};

const STATUS_COLORS: Record<string, string> = {
  active: "rgb(var(--chart-success))",
  completed: "rgb(var(--chart-success))",
  healthy: "rgb(var(--chart-success))",
  pending: "rgb(var(--chart-pending))",
  queued: "rgb(var(--chart-pending))",
  created: "rgb(var(--chart-muted))",
  registered: "rgb(var(--chart-pending))",
  processing: "rgb(var(--chart-processing))",
  running: "rgb(var(--chart-processing))",
  indexing: "rgb(var(--chart-processing))",
  building_disk: "rgb(var(--chart-processing))",
  disk_ready: "rgb(var(--chart-success))",
  failed: "rgb(var(--chart-danger))",
  locked: "rgb(var(--chart-danger))",
  disabled: "rgb(var(--chart-muted))",
  cancelled: "rgb(var(--chart-muted))",
  canceled: "rgb(var(--chart-muted))",
  paused: "rgb(var(--chart-pending))",
  stale: "rgb(var(--chart-pending))",
  approved: "rgb(var(--chart-success))",
  rejected: "rgb(var(--chart-danger))",
  open: "rgb(var(--chart-pending))",
  in_progress: "rgb(var(--chart-processing))",
  resolved: "rgb(var(--chart-success))",
  accepted_risk: "rgb(var(--chart-muted))",
  error: "rgb(var(--chart-danger))",
  warning: "rgb(var(--chart-pending))",
  info: "rgb(var(--chart-info))",
  debug: "rgb(var(--chart-muted))",
  critical: "rgb(var(--chart-critical))",
  high: "rgb(var(--chart-high))",
  medium: "rgb(var(--chart-medium))",
  low: "rgb(var(--chart-low))",
};

function semanticStatusColor(name: string): string | undefined {
  return STATUS_COLORS[name.toLowerCase()];
}

export function statusColor(name: string): string {
  return semanticStatusColor(name) || "rgb(var(--chart-1))";
}

export function countBy<T>(
  items: T[],
  key: (item: T) => string,
  colors?: Record<string, string>,
): ChartDatum[] {
  const map = new Map<string, number>();
  for (const item of items) {
    const name = (key(item) || "unknown").trim() || "unknown";
    map.set(name, (map.get(name) || 0) + 1);
  }
  return [...map.entries()]
    .sort((a, b) => b[1] - a[1])
    .map(([name, value]) => ({
      name,
      value,
      // Only force a color for semantic states/severities. Arbitrary
      // categories deliberately remain unfilled so the chart can assign a
      // distinct theme-aware palette color instead of making every slice
      // fall back to the same brand orange.
      fill: colors?.[name] || semanticStatusColor(name),
    }));
}

export function namedValues(
  rows: Array<{ name: string; value: number; fill?: string }>,
): ChartDatum[] {
  return rows.map((row) => ({
    ...row,
    fill: row.fill || semanticStatusColor(row.name),
  }));
}
