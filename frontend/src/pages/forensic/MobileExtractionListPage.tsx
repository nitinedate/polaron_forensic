import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ChevronLeft, ChevronRight, Eye, Plus, Smartphone } from "lucide-react";
import { Badge, Button, Card, LoadPanel, PageHeader, Select } from "../../components/ui";
import { forensicApi } from "../../lib/forensicApi";
import { useAuth } from "../../lib/auth";
import type { Job, JobList } from "../../lib/types/forensic";
import { InsightCharts } from "../../components/charts";
import { countBy } from "../../lib/chartCounts";

const PAGE_SIZE = 10;

const STATUS_TONE: Record<string, "neutral" | "green" | "amber" | "red" | "indigo"> = {
  pending: "amber",
  created: "neutral",
  registered: "amber",
  processing: "indigo",
  building_disk: "indigo",
  disk_ready: "green",
  indexing: "indigo",
  completed: "green",
  failed: "red",
  paused: "amber",
};

function mobileOsLabel(job: Job): string {
  const os = String(job.disk_source?.mobile_os || "").toLowerCase();
  if (os === "android") return "Android";
  if (os === "ios") return "iOS";
  if (os === "other") return "Other";
  return "—";
}

export function MobileExtractionListPage() {
  const navigate = useNavigate();
  const { hasPermission } = useAuth();
  const canRun = hasPermission("job:run");

  const [data, setData] = useState<JobList | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState("");
  const [chartJobs, setChartJobs] = useState<Job[]>([]);

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const res = await forensicApi.listJobs({
        page,
        page_size: PAGE_SIZE,
        status: status || undefined,
        type: "mobile_extraction",
      });
      setData(res);
    } catch (e: unknown) {
      setLoadError(e instanceof Error ? e.message : "Failed to load mobile jobs");
    } finally {
      setLoading(false);
    }
  }, [page, status]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    forensicApi
      .listJobs({ page: 1, page_size: 100, type: "mobile_extraction" }, { service: "mobile-extract" })
      .then((res) => setChartJobs(res.items))
      .catch(() => setChartJobs([]));
  }, []);

  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;
  const statusSeries = useMemo(() => countBy(chartJobs, (j) => j.status), [chartJobs]);
  const osSeries = useMemo(
    () => countBy(chartJobs, (j) => mobileOsLabel(j) === "—" ? "unknown" : mobileOsLabel(j)),
    [chartJobs],
  );

  return (
    <div>
      <PageHeader
        title="Mobile Extraction"
        subtitle="Import mobile extractions for any OS, preserve originals, and build working images for analysis."
        actions={
          canRun && (
            <Link to="/forensic/mobile/new">
              <Button variant="brand">
                <Plus className="h-4 w-4" /> New mobile extraction
              </Button>
            </Link>
          )
        }
      />

      {chartJobs.length > 0 && (
        <InsightCharts
          left={{ title: "Extraction status", subtitle: "From mobile extract API", data: statusSeries, kind: "bar" }}
          right={{ title: "Mobile OS", subtitle: "Android / iOS mix", data: osSeries, kind: "donut", centerLabel: "Jobs" }}
        />
      )}

      <Card className="overflow-hidden">
        <div className="flex flex-wrap items-center gap-3 border-b border-ink-100 p-4">
          <Select
            className="w-40"
            value={status}
            onChange={(e) => {
              setPage(1);
              setStatus(e.target.value);
            }}
          >
            <option value="">All statuses</option>
            <option value="created">created</option>
            <option value="registered">registered</option>
            <option value="building_disk">building_disk</option>
            <option value="disk_ready">disk_ready</option>
            <option value="indexing">indexing</option>
            <option value="completed">completed</option>
            <option value="failed">failed</option>
          </Select>
          {data && <span className="text-sm text-ink-400">{data.total} total</span>}
        </div>

        <LoadPanel
          loading={loading}
          error={loadError}
          hasData={Boolean(data?.items.length)}
          onRetry={() => void load()}
          empty={
            <div className="px-5 py-16 text-center">
              <Smartphone className="mx-auto mb-3 h-8 w-8 text-ink-300" />
              <p className="text-sm text-ink-400">No mobile extraction jobs yet.</p>
              {canRun && (
                <Button className="mt-4" variant="brand" onClick={() => navigate("/forensic/mobile/new")}>
                  Start mobile extraction
                </Button>
              )}
            </div>
          }
        >
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="table-head border-b border-brand-300/70 text-xs uppercase tracking-wider text-ink-700">
                  <th className="px-5 py-3 font-semibold">Job ID</th>
                  <th className="px-5 py-3 font-semibold">Mobile OS</th>
                  <th className="px-5 py-3 font-semibold">Capability</th>
                  <th className="px-5 py-3 font-semibold">Status</th>
                  <th className="px-5 py-3 font-semibold">Progress</th>
                  <th className="px-5 py-3 font-semibold">Created</th>
                  <th className="px-5 py-3 text-right font-semibold">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-ink-100">
                {(data?.items ?? []).map((job: Job) => (
                  <tr key={job.id} className="hover:bg-ink-50/60">
                    <td className="px-5 py-3 font-mono text-xs text-ink-700">{job.id.slice(0, 12)}…</td>
                    <td className="px-5 py-3 text-ink-600">{mobileOsLabel(job)}</td>
                    <td className="px-5 py-3 text-xs text-ink-500">
                      {String(job.disk_source?.capability_label || "SUPPORTED_IMPORT")}
                    </td>
                    <td className="px-5 py-3">
                      <Badge tone={STATUS_TONE[job.status] ?? "neutral"}>{job.status}</Badge>
                    </td>
                    <td className="px-5 py-3">
                      <div className="flex items-center gap-2">
                        <div className="h-1.5 w-20 rounded-full bg-ink-100">
                          <div
                            className="h-1.5 rounded-full bg-brand-500"
                            style={{ width: `${job.progress_pct}%` }}
                          />
                        </div>
                        <span className="text-xs text-ink-400">{job.progress_pct}%</span>
                      </div>
                    </td>
                    <td className="px-5 py-3 text-ink-500">
                      {new Date(job.created_at).toLocaleDateString()}
                    </td>
                    <td className="px-5 py-3 text-right">
                      <Link
                        to={`/forensic/jobs/${job.id}`}
                        state={{ lockedSourceType: "mobile" }}
                        className="inline-flex items-center gap-1 rounded-lg px-3 py-1.5 text-xs font-semibold text-brand-600 hover:bg-brand-50"
                      >
                        <Eye className="h-3.5 w-3.5" /> Open
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </LoadPanel>

        <div className="flex items-center justify-between border-t border-ink-100 px-5 py-3">
          <span className="text-sm text-ink-400">
            Page {page} of {totalPages}
          </span>
          <div className="flex gap-1">
            <Button variant="outline" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
              <ChevronLeft className="h-4 w-4" />
            </Button>
            <Button variant="outline" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>
              <ChevronRight className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </Card>
    </div>
  );
}
