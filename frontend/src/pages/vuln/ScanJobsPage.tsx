import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { ChevronDown, ChevronRight, Download, Eye, FolderPlus, Play, Radar, RotateCcw, Trash2 } from "lucide-react";
import { Badge, Button, Card, Field, Input, Modal, PageHeader, Select, Spinner } from "../../components/ui";
import { InsightCharts } from "../../components/charts";
import { countBy } from "../../lib/chartCounts";
import { vulnApi } from "../../lib/vulnApi";
import { targetsOutsideCidr } from "../../lib/cidr";
import { useToast } from "../../lib/toast";
import { useAuth } from "../../lib/auth";
import type { Case } from "../../lib/types/forensic";
import type {
  NetworkToken,
  Scanner,
  ScanJob,
  ScanJobSeverityBucket,
  ScanJobSeveritySummary,
  ScanJobTargetProgress,
  ScanPolicy,
} from "../../lib/types/vuln";

function isRemoteScannerUrl(url: string | null | undefined): boolean {
  const u = (url || "").trim().toLowerCase();
  if (!u) return false;
  if (u.startsWith("unix://")) return false;
  if (u.includes("://gvmd") || u.includes("gvmd:9390")) return false;
  return true;
}

function scannerRoleOf(scanner: Scanner | null | undefined): string {
  const role = (scanner?.scanner_role || "").toLowerCase();
  if (role) return role;
  if ((scanner?.connection_mode || "").toLowerCase() === "edge_agent") return "portable";
  if (isRemoteScannerUrl(scanner?.url) && !(scanner?.url || "").toLowerCase().startsWith("agent://")) {
    return "remote_vpn";
  }
  return "central";
}

function isEdgeAgentScanner(scanner: Scanner | null | undefined): boolean {
  const role = scannerRoleOf(scanner);
  if (role === "persistent_edge" || role === "portable") return true;
  if (!scanner) return false;
  if ((scanner.connection_mode || "").toLowerCase() === "edge_agent") return true;
  return (scanner.url || "").toLowerCase().startsWith("agent://");
}

const EDGE_ONLINE_MS = 180_000;

function scannerIsOffline(scanner: Scanner): boolean {
  if (!isEdgeAgentScanner(scanner)) return false;
  if (scanner.online === true) return false;
  if (scanner.last_heartbeat_at) {
    const age = Date.now() - Date.parse(scanner.last_heartbeat_at);
    if (!Number.isNaN(age) && age >= 0 && age <= EDGE_ONLINE_MS) return false;
  }
  return scanner.online === false || !scanner.last_heartbeat_at;
}

const ROLE_SHORT: Record<string, string> = {
  persistent_edge: "Persistent Edge",
  portable: "Portable",
  remote_vpn: "Remote/VPN",
  central: "Central GMP",
};

const STATUS_TONE: Record<string, "neutral" | "green" | "amber" | "red" | "indigo"> = {
  pending: "amber",
  queued: "amber",
  processing: "indigo",
  syncing: "indigo",
  running: "indigo",
  completed: "green",
  failed: "red",
  cancelled: "neutral",
};

const ACTIVE_STATUSES = new Set(["pending", "queued", "running", "processing", "syncing"]);
const DELETABLE_JOB_STATUSES = new Set(["pending", "queued", "running", "processing", "syncing"]);
const DEFAULT_WORKSPACE_ID = "00000000-0000-4000-8000-000000000001";
const MAX_EXPORT_IPS = 65_536;

const SEVERITY_COLORS: Record<string, string> = {
  critical: "rgb(var(--chart-critical))",
  high: "rgb(var(--chart-high))",
  medium: "rgb(var(--chart-medium))",
  low: "rgb(var(--chart-low))",
  info: "rgb(var(--chart-info))",
};

const AETHERIS_SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"] as const;

function aetherisSeverityBuckets(buckets: ScanJobSeverityBucket[]): ScanJobSeverityBucket[] {
  const bySev = new Map(buckets.map((b) => [b.severity, b]));
  return AETHERIS_SEVERITY_ORDER.map(
    (severity) =>
      bySev.get(severity) || {
        severity,
        count: 0,
        pct: 0,
        hosts: [],
      },
  );
}

function ipv4ToInt(ip: string): number | null {
  const parts = ip.trim().split(".");
  if (parts.length !== 4) return null;
  const nums = parts.map((p) => Number(p));
  if (nums.some((n) => !Number.isInteger(n) || n < 0 || n > 255)) return null;
  return ((nums[0]! << 24) >>> 0) + (nums[1]! << 16) + (nums[2]! << 8) + nums[3]!;
}

function intToIpv4(n: number): string {
  return [(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255].join(".");
}

/** Expand inclusive IPv4 From→To range (capped). */
function expandIpv4Range(fromIp: string, toIp: string): { ips: string[]; error?: string } {
  const start = ipv4ToInt(fromIp);
  const end = ipv4ToInt(toIp);
  if (start == null || end == null) {
    return { ips: [], error: "From/To must be valid IPv4 addresses (e.g. 192.168.1.1)." };
  }
  if (end < start) {
    return { ips: [], error: "To IP must be greater than or equal to From IP." };
  }
  const count = end - start + 1;
  if (count > MAX_EXPORT_IPS) {
    return {
      ips: [],
      error: `Range has ${count.toLocaleString()} addresses — max export is ${MAX_EXPORT_IPS.toLocaleString()}.`,
    };
  }
  const ips: string[] = [];
  for (let n = start; n <= end; n += 1) ips.push(intToIpv4(n));
  return { ips };
}

function downloadTextFile(filename: string, content: string) {
  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function scanJobProgressPct(job: ScanJob): number {
  if (typeof job.progress_pct === "number") return Math.min(100, Math.max(0, job.progress_pct));
  if (job.status === "completed") return 100;
  if (job.status === "failed") return 100;
  if (job.status === "running") return 45;
  if (job.status === "pending") return 8;
  return 0;
}

function progressCircleStroke(job: { status: string }): string {
  if (job.status === "failed") return "rgb(var(--chart-danger))";
  if (job.status === "completed") return "rgb(var(--chart-success))";
  return "rgb(var(--chart-1))";
}

function ProgressCircle({
  pct,
  status,
  size = 40,
  title,
}: {
  pct: number;
  status: string;
  size?: number;
  title?: string;
}) {
  const r = (size - 6) / 2;
  const c = 2 * Math.PI * r;
  const clamped = Math.min(100, Math.max(0, pct));
  const offset = c * (1 - clamped / 100);
  const stroke = progressCircleStroke({ status });
  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }} title={title}>
      <svg width={size} height={size} className="-rotate-90" aria-hidden>
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="rgb(var(--chart-track))" strokeWidth={5} />
        <circle
          cx={size / 2}
          cy={size / 2}
          r={r}
          fill="none"
          stroke={stroke}
          strokeWidth={5}
          strokeLinecap="round"
          strokeDasharray={c}
          strokeDashoffset={offset}
          className="transition-[stroke-dashoffset] duration-500 ease-out"
        />
      </svg>
      <span className="absolute text-[10px] font-semibold tabular-nums text-ink-700">{Math.round(clamped)}%</span>
    </div>
  );
}

function polarToCartesian(cx: number, cy: number, radius: number, angleDeg: number) {
  const rad = ((angleDeg - 90) * Math.PI) / 180;
  return { x: cx + radius * Math.cos(rad), y: cy + radius * Math.sin(rad) };
}

function donutSlicePath(
  cx: number,
  cy: number,
  outerR: number,
  innerR: number,
  startAngle: number,
  endAngle: number,
): string {
  const large = endAngle - startAngle > 180 ? 1 : 0;
  const os = polarToCartesian(cx, cy, outerR, endAngle);
  const oe = polarToCartesian(cx, cy, outerR, startAngle);
  const is = polarToCartesian(cx, cy, innerR, startAngle);
  const ie = polarToCartesian(cx, cy, innerR, endAngle);
  return [
    `M ${os.x} ${os.y}`,
    `A ${outerR} ${outerR} 0 ${large} 0 ${oe.x} ${oe.y}`,
    `L ${is.x} ${is.y}`,
    `A ${innerR} ${innerR} 0 ${large} 1 ${ie.x} ${ie.y}`,
    "Z",
  ].join(" ");
}

function SeverityDonut({
  buckets,
  selected,
  onSelect,
  totalFindings,
}: {
  buckets: ScanJobSeverityBucket[];
  selected: string | null;
  onSelect: (severity: string) => void;
  totalFindings: number;
}) {
  const size = 200;
  const cx = size / 2;
  const cy = size / 2;
  const outerR = 78;
  const innerR = 46;
  const scale = aetherisSeverityBuckets(buckets);
  const total = totalFindings > 0 ? totalFindings : scale.reduce((s, x) => s + x.count, 0);
  let angle = 0;
  const slices = scale
    .filter((b) => b.count > 0)
    .map((b) => {
      const sweep = total > 0 ? (b.count / total) * 360 : 0;
      const start = angle;
      const end = angle + Math.max(sweep, 0.5);
      angle = end;
      return { ...b, start, end };
    });

  // Clean / zero-finding scan: full green ring
  if (slices.length === 0) {
    return (
      <div className="flex flex-col items-center gap-3 sm:flex-row sm:items-center">
        <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="shrink-0" aria-label="No findings">
          <circle
            cx={cx}
            cy={cy}
            r={(outerR + innerR) / 2}
            fill="none"
            stroke="rgb(var(--chart-success))"
            strokeWidth={outerR - innerR}
          />
          <text x={cx} y={cy - 2} textAnchor="middle" className="fill-ink-800 text-lg font-bold">
            0
          </text>
          <text x={cx} y={cy + 16} textAnchor="middle" className="fill-emerald-600 text-[10px] font-semibold uppercase">
            clean
          </text>
        </svg>
        <p className="text-sm text-ink-500">No vulnerabilities found — scan completed clean.</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col items-center gap-4 sm:flex-row sm:items-start">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="shrink-0">
        {slices.length === 1 ? (
          <circle
            cx={cx}
            cy={cy}
            r={(outerR + innerR) / 2}
            fill="none"
            stroke={SEVERITY_COLORS[slices[0]!.severity] || SEVERITY_COLORS.info}
            strokeWidth={outerR - innerR}
            className="cursor-pointer"
            opacity={selected && selected !== slices[0]!.severity ? 0.45 : 1}
            onClick={() => onSelect(slices[0]!.severity)}
          />
        ) : (
          slices.map((s) => (
            <path
              key={s.severity}
              d={donutSlicePath(cx, cy, outerR, innerR, s.start, s.end)}
              fill={SEVERITY_COLORS[s.severity] || SEVERITY_COLORS.info}
              className="cursor-pointer transition-opacity"
              opacity={selected && selected !== s.severity ? 0.4 : 1}
              onClick={() => onSelect(s.severity)}
            >
              <title>
                {s.severity}: {s.count} ({s.pct}%)
              </title>
            </path>
          ))
        )}
        <text x={cx} y={cy - 4} textAnchor="middle" className="fill-ink-800 text-lg font-bold">
          {total}
        </text>
        <text x={cx} y={cy + 14} textAnchor="middle" className="fill-ink-400 text-[10px] font-semibold uppercase">
          findings
        </text>
      </svg>
      <ul className="w-full min-w-[10rem] space-y-1.5">
        {scale.map((b) => (
          <li key={b.severity}>
            <button
              type="button"
              onClick={() => onSelect(b.severity)}
              className={`flex w-full items-center gap-2 rounded-lg px-2 py-1.5 text-left text-sm transition ${
                selected === b.severity ? "bg-brand-100 ring-1 ring-brand-300" : "hover:bg-ink-50"
              }`}
            >
              <span
                className="h-2.5 w-2.5 shrink-0 rounded-full"
                style={{ backgroundColor: SEVERITY_COLORS[b.severity] || SEVERITY_COLORS.info }}
              />
              <span className="flex-1 capitalize text-ink-700">{b.severity}</span>
              <span className="tabular-nums text-ink-500">
                {b.count} · {b.pct}%
              </span>
            </button>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function ScanJobsPage() {
  const toast = useToast();
  const { hasPermission } = useAuth();
  const canLaunch = hasPermission("scan:launch");
  const canCreateCase = hasPermission("scan:launch") || hasPermission("job:run") || hasPermission("case:manage");

  const [cases, setCases] = useState<Case[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState("");
  const [jobs, setJobs] = useState<ScanJob[]>([]);
  const [policies, setPolicies] = useState<ScanPolicy[]>([]);
  const [loading, setLoading] = useState(true);
  const [createOpen, setCreateOpen] = useState(false);
  const [caseModalOpen, setCaseModalOpen] = useState(false);
  const [deletingJobId, setDeletingJobId] = useState<string | null>(null);
  const [deletingCase, setDeletingCase] = useState(false);
  const [retryingJobId, setRetryingJobId] = useState<string | null>(null);
  const [retryingAll, setRetryingAll] = useState(false);
  const [detailsJob, setDetailsJob] = useState<ScanJob | null>(null);
  const jobsRef = useRef(jobs);
  jobsRef.current = jobs;

  const loadCases = useCallback(async () => {
    try {
      const res = await vulnApi.listCases({ page: 1, page_size: 50 });
      setCases(res.items);
      setSelectedCaseId((prev) => {
        if (prev && res.items.some((c) => c.id === prev)) return prev;
        return res.items[0]?.id ?? "";
      });
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to load cases");
    }
  }, [toast]);

  useEffect(() => {
    loadCases();
    vulnApi.listScanPolicies().then(setPolicies).catch(() => undefined);
  }, [loadCases]);

  const loadJobs = useCallback(
    async (silent = false) => {
      if (!selectedCaseId) {
        setJobs([]);
        if (!silent) setLoading(false);
        return;
      }
      if (!silent) setLoading(true);
      try {
        setJobs(await vulnApi.listScanJobs(selectedCaseId));
      } catch (e: unknown) {
        if (!silent) toast.error(e instanceof Error ? e.message : "Failed to load scan jobs");
      } finally {
        if (!silent) setLoading(false);
      }
    },
    [selectedCaseId, toast],
  );

  useEffect(() => {
    loadJobs();
  }, [loadJobs]);

  useEffect(() => {
    if (!selectedCaseId) return;
    const poll = () => {
      if (!jobsRef.current.some((j) => ACTIVE_STATUSES.has(j.status))) return;
      loadJobs(true);
    };
    const id = window.setInterval(poll, 5000);
    return () => window.clearInterval(id);
  }, [selectedCaseId, loadJobs]);

  const deleteQueuedJob = useCallback(
    async (job: ScanJob) => {
      if (!canLaunch || !DELETABLE_JOB_STATUSES.has(job.status)) return;
      const running = ["running", "processing", "syncing"].includes(job.status);
      const confirmed = window.confirm(
        running
          ? `Stop and delete scan ${job.id.slice(0, 8)}? This terminates OpenVAS and worker tasks for this job, then removes it. Nothing will keep running for this job.`
          : `Delete ${job.status} scan ${job.id.slice(0, 8)}? This removes it from the queue so it will not start.`,
      );
      if (!confirmed) return;

      setDeletingJobId(job.id);
      try {
        await vulnApi.deleteScanJob(job.id);
        toast.success("Scan stopped and deleted");
        await loadJobs(true);
      } catch (e: unknown) {
        toast.error(e instanceof Error ? e.message : "Failed to delete scan");
        await loadJobs(true);
      } finally {
        setDeletingJobId(null);
      }
    },
    [canLaunch, loadJobs, toast],
  );

  const deleteSelectedCase = useCallback(async () => {
    if (!canCreateCase || !selectedCaseId || selectedCaseId === DEFAULT_WORKSPACE_ID) return;
    const selected = cases.find((c) => c.id === selectedCaseId);
    const label = selected?.title || selected?.number || selectedCaseId.slice(0, 8);
    const confirmed = window.confirm(
      `Delete case "${label}" and all of its queued, processing, and running scans? This cannot be undone.`,
    );
    if (!confirmed) return;
    setDeletingCase(true);
    try {
      const result = await vulnApi.deleteCase(selectedCaseId);
      toast.success(
        result.deleted_scan_jobs
          ? `Case deleted (${result.deleted_scan_jobs} scan${result.deleted_scan_jobs === 1 ? "" : "s"} removed)`
          : "Case deleted",
      );
      await loadCases();
      setJobs([]);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to delete case");
    } finally {
      setDeletingCase(false);
    }
  }, [canCreateCase, cases, loadCases, selectedCaseId, toast]);

  const retryFailedJob = useCallback(
    async (job: ScanJob) => {
      if (!canLaunch || !["failed", "cancelled", "canceled"].includes(job.status)) return;
      setRetryingJobId(job.id);
      try {
        try {
          await vulnApi.retryScanJob(job.id);
        } catch (e: unknown) {
          const msg = (e instanceof Error ? e.message : "").toLowerCase();
          if (!msg.includes("404") && !msg.includes("not found")) throw e;
          // Older central API: requeue this same row so its target list stays put.
          await vulnApi.updateScanJob(job.id, { status: "queued" });
        }
        toast.success(`Resumed scan ${job.id.slice(0, 8)} with its original targets`);
        await loadJobs(true);
      } catch (e: unknown) {
        toast.error(e instanceof Error ? e.message : "Failed to resume scan");
        await loadJobs(true);
      } finally {
        setRetryingJobId(null);
      }
    },
    [canLaunch, loadJobs, toast],
  );

  const retryAllFailedJobs = useCallback(async () => {
    if (!canLaunch || !selectedCaseId) return;
    const failed = jobs.filter((j) => ["failed", "cancelled", "canceled"].includes(j.status));
    if (failed.length === 0) return;
    setRetryingAll(true);
    try {
      try {
        const result = await vulnApi.retryFailedScanJobs(selectedCaseId);
        toast.success(
          `Resumed ${result.count} scan${result.count === 1 ? "" : "s"} — each keeps its own network`,
        );
      } catch (e: unknown) {
        const msg = (e instanceof Error ? e.message : "").toLowerCase();
        if (!msg.includes("404") && !msg.includes("not found")) throw e;
        for (const job of failed) {
          await vulnApi.updateScanJob(job.id, { status: "queued" });
        }
        toast.success(
          `Requeued ${failed.length} scan${failed.length === 1 ? "" : "s"} — each keeps its own network`,
        );
      }
      await loadJobs(true);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to resume scans");
      await loadJobs(true);
    } finally {
      setRetryingAll(false);
    }
  }, [canLaunch, jobs, loadJobs, selectedCaseId, toast]);

  return (
    <div>
      <PageHeader
        title="Scan jobs"
        subtitle="Launch and monitor vulnerability scans per case."
        actions={
          <>
            {canCreateCase && (
              <Button variant="ghost" onClick={() => setCaseModalOpen(true)}>
                <FolderPlus className="h-4 w-4" /> New case
              </Button>
            )}
            {canCreateCase && selectedCaseId && selectedCaseId !== DEFAULT_WORKSPACE_ID && (
              <Button
                variant="danger"
                loading={deletingCase}
                onClick={() => void deleteSelectedCase()}
                title="Delete this case and its queued, processing, and running scans"
              >
                <Trash2 className="h-4 w-4" /> Delete case
              </Button>
            )}
            {canLaunch &&
              selectedCaseId &&
              jobs.some((j) => ["failed", "cancelled", "canceled"].includes(j.status)) && (
                <Button
                  variant="outline"
                  loading={retryingAll}
                  disabled={Boolean(retryingJobId)}
                  onClick={() => retryAllFailedJobs()}
                  title="Requeue each failed job with its original targets. Networks are not merged."
                >
                  <RotateCcw className="h-4 w-4" /> Resume failed
                </Button>
              )}
            {canLaunch && selectedCaseId && (
              <Button variant="brand" onClick={() => setCreateOpen(true)}>
                <Play className="h-4 w-4" /> Launch scan
              </Button>
            )}
          </>
        }
      />

      {jobs.length > 0 && (
        <InsightCharts
          left={{
            title: "Scan status",
            subtitle: "From case scan-jobs API",
            data: countBy(jobs, (j) => j.status),
            kind: "bar",
          }}
          right={{
            title: "Scan source",
            subtitle: "How jobs were launched",
            data: countBy(jobs, (j) => j.source || "manual"),
            kind: "donut",
            centerLabel: "Scans",
          }}
        />
      )}

      <Card className="mb-4 p-4">
        <Field label="Case" hint="Cases group scans, findings, and assets. Create one or use Default workspace.">
          <Select value={selectedCaseId} onChange={(e) => setSelectedCaseId(e.target.value)}>
            <option value="">Select a case…</option>
            {cases.map((c) => (
              <option key={c.id} value={c.id}>
                {c.title || c.number || c.id.slice(0, 8)}
              </option>
            ))}
          </Select>
        </Field>
      </Card>

      <Card className="overflow-hidden">
        {loading ? (
          <Spinner />
        ) : !selectedCaseId ? (
          <p className="px-5 py-16 text-center text-sm text-ink-400">Select a case to view scan jobs.</p>
        ) : jobs.length === 0 ? (
          <p className="px-5 py-16 text-center text-sm text-ink-400">No scan jobs for this case.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="table-head border-b border-brand-300/70 text-xs uppercase tracking-wider text-ink-700">
                  <th className="px-5 py-3 font-semibold">Job</th>
                  <th className="px-5 py-3 font-semibold">Status</th>
                  <th className="px-5 py-3 font-semibold">Progress</th>
                  <th className="px-5 py-3 font-semibold">Targets</th>
                  <th className="px-5 py-3 font-semibold">Started</th>
                  <th className="px-5 py-3 font-semibold">Completed</th>
                  <th className="px-5 py-3 font-semibold">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-100">
                {jobs.map((j) => (
                  <tr key={j.id} className="hover:bg-ink-50/60">
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-2">
                        <Radar className="h-4 w-4 text-brand-600" />
                        <span className="font-mono text-xs text-ink-700">{j.id.slice(0, 8)}…</span>
                      </div>
                    </td>
                    <td className="px-5 py-3">
                      <Badge tone={STATUS_TONE[j.status] ?? "neutral"}>{j.status}</Badge>
                      {j.status === "failed" && j.error ? (
                        <p className="mt-1 max-w-xs text-xs text-red-700" title={j.error}>
                          {j.error}
                        </p>
                      ) : null}
                    </td>
                    <td className="px-5 py-3">
                      <ProgressCircle
                        pct={scanJobProgressPct(j)}
                        status={j.status}
                        title={j.progress_label || `${scanJobProgressPct(j)}%`}
                      />
                    </td>
                    <td className="px-5 py-3 text-ink-500">{j.targets.length}</td>
                    <td className="px-5 py-3 text-ink-500">
                      {j.started_at ? new Date(j.started_at).toLocaleString() : "—"}
                    </td>
                    <td className="px-5 py-3 text-ink-500">
                      {j.completed_at ? new Date(j.completed_at).toLocaleString() : "—"}
                    </td>
                    <td className="px-5 py-3">
                      <div className="flex flex-wrap items-center gap-2">
                        <Button variant="outline" onClick={() => setDetailsJob(j)}>
                          <Eye className="h-4 w-4" /> View Details
                        </Button>
                        {canLaunch && ["failed", "cancelled", "canceled"].includes(j.status) ? (
                          <Button
                            variant="outline"
                            loading={retryingJobId === j.id}
                            disabled={Boolean(retryingAll || (retryingJobId && retryingJobId !== j.id))}
                            onClick={() => retryFailedJob(j)}
                            title="Resume this job from leftover OpenVAS work. Its target list stays with this job."
                          >
                            <RotateCcw className="h-4 w-4" /> Resume
                          </Button>
                        ) : null}
                        {canLaunch && DELETABLE_JOB_STATUSES.has(j.status) ? (
                          <Button
                            variant="danger"
                            loading={deletingJobId === j.id}
                            disabled={Boolean(deletingJobId && deletingJobId !== j.id)}
                            onClick={() => deleteQueuedJob(j)}
                            title="Stop this scan on the server and delete the job"
                          >
                            <Trash2 className="h-4 w-4" /> Stop & delete
                          </Button>
                        ) : null}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>

      {detailsJob && <JobDetailsModal job={detailsJob} onClose={() => setDetailsJob(null)} />}

      {createOpen && selectedCaseId && (
        <LaunchModal
          caseId={selectedCaseId}
          policies={policies}
          onClose={() => setCreateOpen(false)}
          onSaved={() => {
            setCreateOpen(false);
            loadJobs();
          }}
        />
      )}

      {caseModalOpen && (
        <CreateCaseModal
          onClose={() => setCaseModalOpen(false)}
          onSaved={async (caseId) => {
            setCaseModalOpen(false);
            await loadCases();
            setSelectedCaseId(caseId);
          }}
        />
      )}
    </div>
  );
}

function scannerIsScanReady(scanner: Scanner | null | undefined): boolean {
  return !isEdgeAgentScanner(scanner) || scanner?.openvas_ready === true;
}

function targetStatusTone(status: string): "neutral" | "green" | "amber" | "red" | "indigo" {
  const s = (status || "").toLowerCase();
  if (s === "completed") return "green";
  if (s === "failed" || s === "incomplete") return "red";
  if (s === "scanning" || s === "running") return "indigo";
  if (s === "skipped" || s === "cancelled") return "neutral";
  return "amber";
}

function JobDetailsModal({ job, onClose }: { job: ScanJob; onClose: () => void }) {
  const toast = useToast();
  const [loading, setLoading] = useState(true);
  const [summary, setSummary] = useState<ScanJobSeveritySummary | null>(null);
  const [selectedSeverity, setSelectedSeverity] = useState<string | null>(null);
  const [ipsOpen, setIpsOpen] = useState(true);

  useEffect(() => {
    let cancelled = false;
    let first = true;
    let timer: number | undefined;
    setSelectedSeverity(null);
    setLoading(true);

    const load = () =>
      vulnApi
        .getScanJobSeveritySummary(job.id)
        .then((data) => {
          if (cancelled) return;
          setSummary(data);
          if (!ACTIVE_STATUSES.has((data.status || "").toLowerCase()) && timer !== undefined) {
            window.clearInterval(timer);
            timer = undefined;
          }
        })
        .catch((e: unknown) => {
          if (!cancelled && first) toast.error(e instanceof Error ? e.message : "Failed to load job details");
        })
        .finally(() => {
          if (!cancelled) {
            setLoading(false);
            first = false;
          }
        });

    void load();
    timer = window.setInterval(() => {
      void load();
    }, 4000);
    return () => {
      cancelled = true;
      if (timer !== undefined) window.clearInterval(timer);
    };
  }, [job.id, toast]);

  const pct = summary?.progress_pct ?? scanJobProgressPct(job);
  const jobStatus = (summary?.status || job.status || "").toLowerCase();
  const complete = pct >= 100 || jobStatus === "completed" || jobStatus === "failed";
  const selectedBucket = summary?.severities.find((s) => s.severity === selectedSeverity) ?? null;
  const hostList =
    selectedSeverity && selectedBucket
      ? selectedBucket.hosts.length > 0
        ? selectedBucket.hosts
        : summary?.all_hosts || []
      : summary?.all_hosts || [];
  const hostHeading =
    selectedSeverity && selectedBucket && selectedBucket.hosts.length > 0
      ? `${selectedSeverity} — host IPs`
      : "All host IPs";
  const targetRows: ScanJobTargetProgress[] = summary?.targets?.length
    ? summary.targets
    : (summary?.all_hosts || []).map((ip) => ({
        ip,
        status: complete ? "completed" : "pending",
        activity: complete ? "Completed" : "Waiting",
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
      }));
  const showFindings = complete || (summary?.total ?? 0) > 0;

  return (
    <Modal open onClose={onClose} title={`Scan details · ${job.id.slice(0, 8)}…`} size="lg">
      {loading && !summary ? (
        <Spinner />
      ) : (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-4">
            <ProgressCircle pct={pct} status={summary?.status || job.status} size={56} />
            <div>
              <Badge tone={STATUS_TONE[summary?.status || job.status] ?? "neutral"}>
                {summary?.status || job.status}
              </Badge>
              {summary?.progress_label ? (
                <p className="mt-1 text-sm text-ink-500">{summary.progress_label}</p>
              ) : (
                <p className="mt-1 text-sm text-ink-500">{Math.round(pct)}% complete</p>
              )}
              {(summary?.error || job.error) && (summary?.status || job.status) === "failed" ? (
                <p className="mt-2 max-w-xl text-sm text-red-700">{summary?.error || job.error}</p>
              ) : null}
            </div>
          </div>

          <div className="overflow-hidden rounded-xl border border-ink-200 bg-white">
            <button
              type="button"
              onClick={() => setIpsOpen((o) => !o)}
              className="flex w-full items-center gap-2 px-4 py-3 text-left hover:bg-ink-50/60"
            >
              {ipsOpen ? <ChevronDown className="h-4 w-4 text-ink-400" /> : <ChevronRight className="h-4 w-4 text-ink-400" />}
              <div className="min-w-0 flex-1">
                <p className="text-sm font-semibold text-ink-800">Per-IP scan activity</p>
                <p className="text-xs text-ink-500">
                  {targetRows.filter((t) => t.status === "scanning" || t.status === "running").length} scanning
                  {" · "}
                  {targetRows.filter((t) => t.status === "completed").length} completed
                  {" · "}
                  {targetRows.length} total
                </p>
              </div>
            </button>
            {ipsOpen ? (
              <div className="max-h-72 overflow-auto border-t border-ink-100">
                {targetRows.length === 0 ? (
                  <p className="px-4 py-3 text-sm text-ink-400">No target IPs on this job.</p>
                ) : (
                  <table className="w-full text-left text-sm">
                    <thead className="sticky top-0 bg-ink-50 text-xs uppercase tracking-wide text-ink-500">
                      <tr>
                        <th className="px-4 py-2 font-semibold">IP</th>
                        <th className="px-3 py-2 font-semibold">Status</th>
                        <th className="px-3 py-2 text-right font-semibold">Progress</th>
                        <th className="px-3 py-2 font-semibold">Activity</th>
                        <th className="px-2 py-2 text-right font-semibold text-red-700">Crit</th>
                        <th className="px-2 py-2 text-right font-semibold text-orange-700">High</th>
                        <th className="px-2 py-2 text-right font-semibold text-amber-600">Med</th>
                        <th className="px-2 py-2 text-right font-semibold text-amber-700">Low</th>
                      </tr>
                    </thead>
                    <tbody>
                      {targetRows.map((row) => (
                        <tr key={row.ip} className="border-t border-ink-100">
                          <td className="px-4 py-2 font-mono text-ink-800">{row.ip}</td>
                          <td className="px-3 py-2">
                            <Badge tone={targetStatusTone(row.status)}>{({ pending: "Waiting", scanning: "In progress", running: "In progress", completed: "Completed", failed: "Fail", incomplete: "Incomplete", skipped: "Skipped", cancelled: "Cancelled" } as Record<string, string>)[row.status] || row.status}</Badge>
                          </td>
                          <td className="px-3 py-2 text-right tabular-nums text-ink-700">{typeof row.progress_pct === "number" ? `${Math.round(Math.min(100, Math.max(0, row.progress_pct)))}%` : "—"}</td>
                          <td className="px-3 py-2 text-ink-600">{row.status === "completed" ? "Completed" : row.activity}</td>
                          <td className="px-2 py-2 text-right font-semibold text-red-700">{row.critical}</td>
                          <td className="px-2 py-2 text-right font-semibold text-orange-700">{row.high}</td>
                          <td className="px-2 py-2 text-right font-semibold text-amber-600">{row.medium}</td>
                          <td className="px-2 py-2 text-right font-semibold text-amber-700">{row.low}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                )}
              </div>
            ) : null}
          </div>
          {summary?.accel?.detail ? (
            <p className="text-xs text-ink-400">{summary.accel.detail}</p>
          ) : null}

          {!showFindings ? (
            <p className="rounded-xl border border-ink-200 bg-ink-50/80 px-4 py-3 text-sm text-ink-600">
              Findings appear here as each IP finishes. The job is still in progress.
            </p>
          ) : (
            <>
              <div>
                <h4 className="mb-3 text-sm font-semibold text-ink-800">Polaron — Findings by severity</h4>
                <SeverityDonut
                  buckets={summary?.severities || []}
                  selected={selectedSeverity}
                  onSelect={setSelectedSeverity}
                  totalFindings={summary?.total ?? 0}
                />
              </div>
              <div>
                <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
                  <h4 className="text-sm font-semibold capitalize text-ink-800">{hostHeading}</h4>
                  {selectedSeverity ? (
                    <button
                      type="button"
                      className="text-xs font-semibold text-brand-700 hover:underline"
                      onClick={() => setSelectedSeverity(null)}
                    >
                      Show all IPs
                    </button>
                  ) : null}
                </div>
                {hostList.length === 0 ? (
                  <p className="text-sm text-ink-400">No host IPs recorded for this scan.</p>
                ) : (
                  <div className="max-h-48 overflow-y-auto rounded-xl border border-ink-200 bg-white/80 px-4 py-3 font-mono text-sm leading-relaxed text-ink-700">
                    {hostList.join(", ")}
                  </div>
                )}

                {summary?.assessment ? (
                  <div className="mt-4 grid gap-x-8 gap-y-2 rounded-xl border border-ink-200 bg-ink-50/70 px-4 py-3 text-sm sm:grid-cols-[auto_1fr]">
                    <span className="font-semibold text-ink-700">Assessed</span>
                    <span className="text-ink-600">
                      {summary.assessment.assessed} / {summary.assessment.target_count}
                    </span>
                    <span className="font-semibold text-ink-700">Skipped</span>
                    <span className="text-ink-600">{summary.assessment.skipped}</span>
                    <span className="font-semibold text-ink-700">Assessment</span>
                    <span className={summary.assessment.verified ? "font-semibold text-emerald-700" : "font-semibold text-red-700"}>
                      {summary.assessment.label}
                    </span>
                    <span className="font-semibold text-ink-700">Engine clean eligible</span>
                    <span className={summary.assessment.clean_eligible ? "font-semibold text-emerald-700" : "font-semibold text-amber-700"}>
                      {summary.assessment.clean_eligible ? "YES" : "NO"}
                    </span>
                  </div>
                ) : null}
                {Object.entries(summary?.service_coverage || {}).length > 0 ? (
                  <div className="mt-4 space-y-3">
                    <h4 className="font-semibold text-ink-900">Service coverage</h4>
                    <p className="text-sm text-ink-600">Native engine evidence for the 52 service families. A completed scan or an open port does not establish that every rule passed.</p>
                    {Object.entries(summary?.service_coverage || {}).map(([host, coverage]) => (
                      <details key={host} className="rounded-xl border border-ink-200 bg-white p-3">
                        <summary className="cursor-pointer text-sm font-semibold text-ink-800">
                          {host} · {coverage.counts.finding || 0} with findings · {coverage.counts.observation || 0} observed · {coverage.counts["not-tested"] || 0} not tested · {coverage.counts.unsupported || 0} unsupported
                        </summary>
                        <p className="my-2 text-xs text-amber-800">{coverage.limitation}</p>
                        <div className="max-h-80 overflow-auto">
                          <table className="w-full text-left text-xs">
                            <thead><tr><th className="p-2">Service</th><th className="p-2">Evidence state</th><th className="p-2">Explanation / source</th></tr></thead>
                            <tbody>{coverage.services.map(service => (
                              <tr key={service.service_id} className="border-t border-ink-100">
                                <td className="p-2">{service.service_id} {service.name}</td>
                                <td className="p-2">{service.status}</td>
                                <td className="p-2">{service.reason}<br />{service.credentialed_checks}
                                  {service.source_result_ids.length ? <div className="break-all font-mono">{service.source_result_ids.join(", ")}</div> : null}
                                </td>
                              </tr>
                            ))}</tbody>
                          </table>
                        </div>
                        <p className="mt-2 text-xs">IP forwarding: {coverage.ip_forwarding.status} · {coverage.ip_forwarding.reason}</p>
                      </details>
                    ))}
                    {Object.entries(summary?.policy_snapshots || {}).map(([task, policy]) => (
                      <details key={task} className="rounded-xl border border-ink-200 bg-white p-3 text-xs">
                        <summary className="cursor-pointer font-semibold">Task policy · {task} · {policy.snapshot_status}</summary>
                        <p className="mt-2 break-all">Ports: {policy.port_range || "Original scope not captured"}</p>
                        <p className="break-all font-mono">SHA-256: {policy.configuration_sha256 || "Unavailable"}</p>
                        <p>Feed: {JSON.stringify(policy.feed_versions || {})}</p>
                        <p>Credential status: {JSON.stringify(policy.credential_status || {})}</p>
                      </details>
                    ))}
                  </div>
                ) : null}
              </div>
            </>
          )}
        </div>
      )}
    </Modal>
  );
}

function CreateCaseModal({ onClose, onSaved }: { onClose: () => void; onSaved: (caseId: string) => void }) {
  const toast = useToast();
  const [loading, setLoading] = useState(false);
  const [title, setTitle] = useState("");

  async function submit() {
    const trimmed = title.trim();
    if (!trimmed) {
      toast.error("Enter a case title");
      return;
    }
    setLoading(true);
    try {
      const created = await vulnApi.createCase({ title: trimmed });
      toast.success("Case created");
      onSaved(created.id);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to create case");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title="New case"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="brand" loading={loading} onClick={submit}>
            Create case
          </Button>
        </>
      }
    >
      <Field label="Title" hint="e.g. PCI Q1 external scan, Acme prod network">
        <Input value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Case title" autoFocus />
      </Field>
    </Modal>
  );
}

function LaunchModal({
  caseId,
  policies,
  onClose,
  onSaved,
}: {
  caseId: string;
  policies: ScanPolicy[];
  onClose: () => void;
  onSaved: () => void;
}) {
  const toast = useToast();
  const [loading, setLoading] = useState(false);
  const [scanners, setScanners] = useState<Scanner[]>([]);
  const [networkSession, setNetworkSession] = useState<NetworkToken | null>(null);
  const [form, setForm] = useState({
    policy_id: "",
    scanner_id: "",
    from_ip: "",
    to_ip: "",
    targets: "",
    authorization_ref: "CHG-12345 / written authorization ID",
    preflight_confirmed: false,
  });

  useEffect(() => {
    let cancelled = false;
    const load = () => {
      Promise.all([
        vulnApi.listScanners().catch(() => [] as Scanner[]),
        vulnApi.getNetworkTokenSession().catch(() => null),
      ]).then(([rows, session]) => {
        if (cancelled) return;
        const active = rows.filter((s) => (s.status || "").toLowerCase() === "active");
        setScanners(active);
        setNetworkSession(session);
        setForm((prev) => {
          const next = { ...prev };
          if (session?.connected_public_ip && !prev.targets.trim()) {
            next.targets = session.connected_public_ip;
          }
          if (session) {
            const central = active.find((s) => scannerRoleOf(s) === "central") || active.find((s) => !isEdgeAgentScanner(s) && !isRemoteScannerUrl(s.url));
            if (central) next.scanner_id = central.id;
            return next;
          }
          const live = active.filter((s) => isEdgeAgentScanner(s) && !scannerIsOffline(s));
          const newest = [...live].sort((a, b) => {
            const ta = a.last_heartbeat_at ? Date.parse(a.last_heartbeat_at) : 0;
            const tb = b.last_heartbeat_at ? Date.parse(b.last_heartbeat_at) : 0;
            return tb - ta;
          })[0];
          const selected = active.find((s) => s.id === prev.scanner_id);
          if (newest && (!prev.scanner_id || !selected || scannerIsOffline(selected))) {
            return { ...next, scanner_id: newest.id };
          }
          if (prev.scanner_id) return next;
          return newest ? { ...next, scanner_id: newest.id } : next;
        });
      });
    };
    load();
    const timer = window.setInterval(load, 10_000);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, []);

  const selectedScanner = useMemo(
    () => scanners.find((s) => s.id === form.scanner_id) || null,
    [scanners, form.scanner_id],
  );
  const edgeAgent = isEdgeAgentScanner(selectedScanner);
  const edgeScannerNotReady = edgeAgent && !scannerIsScanReady(selectedScanner);
  const remoteOpenvas = edgeAgent || isRemoteScannerUrl(selectedScanner?.url);

  const rangePreview = useMemo(() => {
    if (!form.from_ip.trim() && !form.to_ip.trim()) return null;
    if (!form.from_ip.trim() || !form.to_ip.trim()) {
      return { ips: [] as string[], error: "Enter both From and To IPv4 addresses." };
    }
    return expandIpv4Range(form.from_ip, form.to_ip);
  }, [form.from_ip, form.to_ip]);

  function applyRangeToTargets() {
    if (!rangePreview || rangePreview.error || rangePreview.ips.length === 0) {
      toast.error(rangePreview?.error || "Enter a valid From → To IPv4 range first");
      return;
    }
    const existing = form.targets
      .split(/[\n,]/)
      .map((t) => t.trim())
      .filter(Boolean);
    const merged = Array.from(new Set([...existing, ...rangePreview.ips]));
    setForm({ ...form, targets: merged.join("\n") });
    toast.success(`Added ${rangePreview.ips.length.toLocaleString()} IP(s) to Targets`);
  }

  function exportAllIps() {
    const fromRange =
      form.from_ip.trim() && form.to_ip.trim() ? expandIpv4Range(form.from_ip, form.to_ip) : { ips: [] as string[] };
    if (fromRange.error) {
      toast.error(fromRange.error);
      return;
    }
    const fromTargets = form.targets
      .split(/[\n,]/)
      .map((t) => t.trim())
      .filter(Boolean);
    const all = Array.from(new Set([...fromRange.ips, ...fromTargets]));
    if (all.length === 0) {
      toast.error("No IPs to export — set From/To range and/or Targets first");
      return;
    }
    if (all.length > MAX_EXPORT_IPS) {
      toast.error(`Too many IPs to export (max ${MAX_EXPORT_IPS.toLocaleString()})`);
      return;
    }
    downloadTextFile(`scan-ips-${caseId.slice(0, 8)}.txt`, `${all.join("\n")}\n`);
    toast.success(`Exported ${all.length.toLocaleString()} IP(s)`);
  }

  async function submit() {
    let targetList = form.targets
      .split(/[\n,]/)
      .map((t) => t.trim())
      .filter(Boolean);
    if (form.from_ip.trim() && form.to_ip.trim()) {
      const expanded = expandIpv4Range(form.from_ip, form.to_ip);
      if (expanded.error) {
        toast.error(expanded.error);
        return;
      }
      targetList = Array.from(new Set([...targetList, ...expanded.ips]));
    }
    const targets = targetList.map((target) => ({ target }));
    if (targets.length === 0) {
      toast.error("Enter a From→To IP range and/or at least one target");
      return;
    }
    if (networkSession?.cidr) {
      const outside = targetsOutsideCidr(
        targets.map((t) => t.target),
        networkSession.cidr,
      );
      if (outside.length) {
        toast.error(`IPs must be inside ${networkSession.cidr}: ${outside.slice(0, 4).join(", ")}`);
        return;
      }
    }
    if (!form.authorization_ref.trim()) {
      toast.error("Authorization reference is required");
      return;
    }
    if (!form.preflight_confirmed) {
      toast.error("Confirm pre-scan controls before launch");
      return;
    }
    setLoading(true);
    try {
      await vulnApi.createScanJob(caseId, {
        policy_id: form.policy_id || null,
        scanner_id: form.scanner_id || null,
        authorization_ref: form.authorization_ref,
        targets,
        preflight_confirmed: true,
        orchestration_enabled: networkSession || remoteOpenvas ? false : null,
        network_token_id: networkSession?.id || null,
      });
      toast.success(
        networkSession
          ? "Scan job created — server Central GMP will scan this network"
          : scannerRoleOf(selectedScanner) === "persistent_edge"
            ? "Scan queued — waiting for the on-site Persistent Edge appliance"
            : edgeAgent
              ? "Scan queued — keep the laptop on this LAN until the portable scan finishes"
              : scannerRoleOf(selectedScanner) === "remote_vpn" || remoteOpenvas
                ? "Scan job created — central will drive site gvmd over VPN GMP"
                : "Scan job created",
      );
      onSaved();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Launch failed");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Modal
      open
      onClose={onClose}
      title="Launch scan"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Cancel
          </Button>
          <Button variant="brand" loading={loading} onClick={submit} disabled={edgeScannerNotReady}>
            Launch
          </Button>
        </>
      }
    >
      <div className="space-y-5 text-base">
        {networkSession ? (
          <p className="rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-sm text-emerald-950">
            Connected network <span className="font-mono">{networkSession.cidr}</span>
            {networkSession.connected_public_ip ? ` · browser ${networkSession.connected_public_ip}` : ""}.
            Scanner is locked to Central GMP. Only IPs in this CIDR are accepted. The server must be able to
            reach those hosts.
          </p>
        ) : (
          <p className="rounded-md border border-ink-200 bg-ink-50 px-3 py-2 text-sm text-ink-700">
            For a client site, request a network token and paste it on Connect client network first. Without
            a token, this launch uses the selected server/VPN scanner as before.
          </p>
        )}
        <Field label="Policy">
          <Select
            className="text-base"
            value={form.policy_id}
            onChange={(e) => {
              const policyId = e.target.value;
              const pol = policies.find((p) => p.id === policyId);
              setForm({
                ...form,
                policy_id: policyId,
                scanner_id: pol?.scanner_id || form.scanner_id,
              });
            }}
          >
            <option value="">— default —</option>
            {policies.map((p) => (
              <option key={p.id} value={p.id}>
                {p.name}
              </option>
            ))}
          </Select>
        </Field>

        <Field
          label="Scanner"
          hint={
            networkSession
              ? "Locked to the server Central GMP scanner while a client network token is connected."
              : "Use Central GMP for browser network tokens. Leave empty for premise OpenVAS."
          }
        >
          <Select
            className="text-base"
            value={form.scanner_id}
            disabled={Boolean(networkSession)}
            onChange={(e) => setForm({ ...form, scanner_id: e.target.value })}
          >
            <option value="">— premise default OpenVAS —</option>
            {scanners.map((s) => {
              const role = scannerRoleOf(s);
              const stale = scannerIsOffline(s);
              return (
                <option key={s.id} value={s.id}>
                  {s.name} [{ROLE_SHORT[role] || role}
                  {stale ? ", offline" : isEdgeAgentScanner(s) ? ", online" : ""}
                  ] — {s.edition || "openvas"}
                </option>
              );
            })}
          </Select>
        </Field>
        {scannerRoleOf(selectedScanner) === "persistent_edge" ? (
          <p className="rounded-md border border-green-200 bg-green-50 px-3 py-2 text-sm text-green-950">
            Persistent Edge selected. The on-site appliance pulls this job over HTTPS and scans from local OpenVAS.
            Leave the box on this customer LAN. Targets stay with this job only.
          </p>
        ) : scannerRoleOf(selectedScanner) === "portable" || edgeAgent ? (
          <p className="rounded-md border border-indigo-200 bg-indigo-50 px-3 py-2 text-sm text-indigo-900">
            Portable Assessment selected. Keep the laptop on the original LAN until the job completes. Moving to
            another network mid-scan stops OpenVAS; it will not scan the new network&apos;s IPs under this job.
          </p>
        ) : scannerRoleOf(selectedScanner) === "remote_vpn" || (remoteOpenvas && !edgeAgent) ? (
          <p className="rounded-md border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900">
            Managed Remote / VPN selected. Central drives on-site gvmd over GMP (tls://…:9390). Premise must reach
            that URL on the VPN. Scan packets originate on the customer site. Orchestration (nmap/ZAP) stays off.
          </p>
        ) : null}

        <div className="space-y-3 rounded-lg border border-ink-200 bg-ink-50/60 p-4">
          <p className="text-base font-semibold text-ink-800">IP address range</p>
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="From IP">
              <Input
                className="font-mono text-base"
                value={form.from_ip}
                onChange={(e) => setForm({ ...form, from_ip: e.target.value })}
                placeholder="192.168.1.1"
              />
            </Field>
            <Field label="To IP">
              <Input
                className="font-mono text-base"
                value={form.to_ip}
                onChange={(e) => setForm({ ...form, to_ip: e.target.value })}
                placeholder="192.168.1.254"
              />
            </Field>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button type="button" variant="outline" onClick={applyRangeToTargets}>
              Add range to Targets
            </Button>
            <Button type="button" variant="ghost" onClick={exportAllIps}>
              <Download className="h-4 w-4" /> Export all IPs
            </Button>
            {rangePreview && !rangePreview.error && rangePreview.ips.length > 0 ? (
              <span className="text-sm font-medium text-ink-600">
                {rangePreview.ips.length.toLocaleString()} address(es) in range
              </span>
            ) : null}
            {rangePreview?.error ? (
              <span className="text-sm font-medium text-red-600">{rangePreview.error}</span>
            ) : null}
          </div>
        </div>

        {edgeScannerNotReady ? <p className="text-sm text-amber-700">{selectedScanner?.agent_status_detail || "Laptop scanner is waiting for OpenVAS feed/configuration readiness."}</p> : null}

        <Field label="Targets" hint="One IP/hostname per line or comma-separated. Range IPs are merged on Launch.">
          <textarea
            className="input min-h-[110px] resize-y font-mono text-sm"
            value={form.targets}
            onChange={(e) => setForm({ ...form, targets: e.target.value })}
            placeholder="192.168.1.1&#10;10.0.0.0/24"
          />
        </Field>
        <Field label="Authorization reference">
          <Input
            className="text-base"
            value={form.authorization_ref}
            onChange={(e) => setForm({ ...form, authorization_ref: e.target.value })}
            placeholder="CHG-12345 / written authorization ID"
          />
        </Field>
        <label className="flex items-start gap-3 rounded-lg border border-ink-200 bg-ink-50 p-4 text-base text-ink-700">
          <input
            type="checkbox"
            className="mt-1 h-4 w-4"
            checked={form.preflight_confirmed}
            onChange={(e) => setForm({ ...form, preflight_confirmed: e.target.checked })}
          />
          <span>
            I confirm pre-scan controls: authorization, target validation, forbidden ranges excluded, scanner healthy,
            plugin feed current, credentials tested (if used), maintenance window, and concurrency estimate.
          </span>
        </label>
      </div>
    </Modal>
  );
}
