import { useMemo, type ReactNode } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Pie,
  PieChart,
  PolarAngleAxis,
  RadialBar,
  RadialBarChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Card } from "../ui";
import type { ChartDatum } from "../../lib/chartCounts";

const PALETTE = [
  "rgb(var(--chart-1))",
  "rgb(var(--chart-2))",
  "rgb(var(--chart-3))",
  "rgb(var(--chart-4))",
  "rgb(var(--chart-5))",
  "rgb(var(--chart-6))",
  "rgb(var(--chart-7))",
  "rgb(var(--chart-8))",
  "rgb(var(--chart-9))",
  "rgb(var(--chart-10))",
];

const tooltipStyle = {
  borderRadius: 12,
  border: "1px solid #d5dae2",
  boxShadow: "0 8px 22px rgb(28 28 28 / 0.08)",
  fontSize: 12,
};

function paletteOffset(key: string): number {
  let hash = 0;
  for (let i = 0; i < key.length; i += 1) {
    hash = (hash * 31 + key.charCodeAt(i)) >>> 0;
  }
  return hash % PALETTE.length;
}

function withFills(data: ChartDatum[], paletteKey = ""): ChartDatum[] {
  const offset = paletteKey ? paletteOffset(paletteKey) : 0;
  return data.map((row, i) => ({
    ...row,
    fill: row.fill || PALETTE[(i + offset) % PALETTE.length],
  }));
}

export function ChartCard({
  title,
  subtitle,
  children,
  className = "",
  height = 220,
}: {
  title: string;
  subtitle?: string;
  children: ReactNode;
  className?: string;
  height?: number;
}) {
  return (
    <Card className={`overflow-hidden ${className}`}>
      <div className="border-b border-ink-100 px-5 py-3">
        <h3 className="text-sm font-bold text-ink-900">{title}</h3>
        {subtitle ? <p className="mt-0.5 text-xs text-ink-400">{subtitle}</p> : null}
      </div>
      <div className="px-2 pb-3 pt-2" style={{ height }}>
        {children}
      </div>
    </Card>
  );
}

function EmptyPlot({ label = "No data from API yet" }: { label?: string }) {
  return (
    <div className="flex h-full items-center justify-center rounded-xl bg-ink-50/70 text-xs font-medium text-ink-400">
      {label}
    </div>
  );
}

export function MetricBarChart({
  data,
  emptyLabel,
}: {
  data: ChartDatum[];
  emptyLabel?: string;
}) {
  const rows = useMemo(() => withFills(data, "bar"), [data]);
  if (rows.length === 0) return <EmptyPlot label={emptyLabel} />;

  return (
    <ResponsiveContainer width="100%" height="100%">
      <BarChart data={rows} margin={{ top: 8, right: 12, left: -8, bottom: 4 }}>
        <CartesianGrid strokeDasharray="3 3" stroke="#eceef2" vertical={false} />
        <XAxis
          dataKey="name"
          tick={{ fontSize: 11, fill: "#65748d" }}
          axisLine={false}
          tickLine={false}
          interval={0}
        />
        <YAxis allowDecimals={false} tick={{ fontSize: 11, fill: "#65748d" }} axisLine={false} tickLine={false} />
        <Tooltip contentStyle={tooltipStyle} cursor={{ fill: "rgb(200 163 74 / 0.08)" }} />
        <Bar dataKey="value" radius={[8, 8, 0, 0]} maxBarSize={56} minPointSize={10}>
          {rows.map((row) => (
            <Cell key={row.name} fill={row.fill} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

export function MetricDonutChart({
  data,
  centerLabel,
  emptyLabel,
  paletteKey,
}: {
  data: ChartDatum[];
  centerLabel?: string;
  emptyLabel?: string;
  paletteKey?: string;
}) {
  const derivedPaletteKey = paletteKey || `${centerLabel || "total"}:${data.map((row) => row.name).join("|")}`;
  const rows = useMemo(
    () => withFills(data, derivedPaletteKey).filter((row) => row.value > 0),
    [data, derivedPaletteKey]
  );
  const total = rows.reduce((sum, row) => sum + row.value, 0);
  if (rows.length === 0) return <EmptyPlot label={emptyLabel} />;

  return (
    <div className="flex h-full items-center gap-2 px-2">
      <div className="relative min-h-0 min-w-0 flex-1 self-stretch">
        <ResponsiveContainer width="100%" height="100%">
          <PieChart>
            <Pie
              data={rows}
              dataKey="value"
              nameKey="name"
              innerRadius="56%"
              outerRadius="86%"
              paddingAngle={rows.length > 1 ? 3 : 0}
              cornerRadius={rows.length > 1 ? 5 : 0}
              stroke="rgb(var(--chart-separator))"
              strokeWidth={rows.length > 1 ? 2 : 0}
            >
              {rows.map((row) => (
                <Cell key={row.name} fill={row.fill} />
              ))}
            </Pie>
            <Tooltip contentStyle={tooltipStyle} />
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <p className="text-2xl font-bold tabular-nums text-ink-900">{total}</p>
          <p className="text-[10px] font-semibold uppercase tracking-wider text-ink-400">
            {centerLabel || "Total"}
          </p>
        </div>
      </div>
      <ul className="hidden w-[38%] shrink-0 space-y-1.5 pr-2 sm:block">
        {rows.map((row) => (
          <li key={row.name} className="flex items-center gap-2 text-xs text-ink-600">
            <span className="h-2.5 w-2.5 shrink-0 rounded-full" style={{ backgroundColor: row.fill }} />
            <span className="truncate capitalize">{row.name}</span>
            <span className="ml-auto font-semibold tabular-nums text-ink-800">{row.value}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function MetricRadialGauge({
  value,
  label,
  max = 100,
}: {
  value: number;
  label: string;
  max?: number;
}) {
  const safe = Number.isFinite(value) ? Math.max(0, value) : 0;
  const pct = max > 0 ? Math.min(100, (safe / max) * 100) : 0;
  const fill = pct >= 80
    ? "rgb(var(--chart-danger))"
    : pct >= 50
      ? "rgb(var(--chart-pending))"
      : "rgb(var(--chart-success))";
  const rows = [{ name: label, value: pct, fill }];

  return (
    <div className="relative h-full">
      <ResponsiveContainer width="100%" height="100%">
        <RadialBarChart
          data={rows}
          innerRadius="72%"
          outerRadius="100%"
          startAngle={90}
          endAngle={-270}
          barSize={12}
        >
          <PolarAngleAxis type="number" domain={[0, 100]} tick={false} />
          <RadialBar dataKey="value" cornerRadius={8} background={{ fill: "rgb(var(--chart-track))" }} />
        </RadialBarChart>
      </ResponsiveContainer>
      <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
        <p className="text-2xl font-bold tabular-nums text-ink-900">{Math.round(safe)}</p>
        <p className="text-[10px] font-semibold uppercase tracking-wider text-ink-400">{label}</p>
      </div>
    </div>
  );
}

export function InsightCharts({
  left,
  right,
}: {
  left: { title: string; subtitle?: string; data: ChartDatum[]; kind?: "bar" | "donut"; centerLabel?: string };
  right?: { title: string; subtitle?: string; data: ChartDatum[]; kind?: "bar" | "donut"; centerLabel?: string };
}) {
  return (
    <div className="row g-3 mb-4">
      <div className={right ? "col-12 col-lg-7" : "col-12"}>
        <ChartCard title={left.title} subtitle={left.subtitle}>
          {left.kind === "donut" ? (
            <MetricDonutChart data={left.data} centerLabel={left.centerLabel} paletteKey={`left:${left.title}`} />
          ) : (
            <MetricBarChart data={left.data} />
          )}
        </ChartCard>
      </div>
      {right ? (
        <div className="col-12 col-lg-5">
          <ChartCard title={right.title} subtitle={right.subtitle}>
            {right.kind === "bar" ? (
              <MetricBarChart data={right.data} />
            ) : (
              <MetricDonutChart data={right.data} centerLabel={right.centerLabel} paletteKey={`right:${right.title}`} />
            )}
          </ChartCard>
        </div>
      ) : null}
    </div>
  );
}
