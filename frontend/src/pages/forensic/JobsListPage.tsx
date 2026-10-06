import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ChevronLeft, ChevronRight, Eye, FolderOpen, Plus, Trash2 } from "lucide-react";
import { Badge, Button, Card, LoadPanel, PageHeader, Select } from "../../components/ui";
import { forensicApi } from "../../lib/forensicApi";
import { useToast } from "../../lib/toast";
import { useAuth } from "../../lib/auth";
import type { Job, JobList } from "../../lib/types/forensic";
import { InsightCharts } from "../../components/charts";
import { countBy } from "../../lib/chartCounts";

const PAGE_SIZE = 10;

const STATUS_TONE: Record<string, "neutral" | "green" | "amber" | "red" | "indigo"> = {
  pending: "amber",
  processing: "indigo",
  running: "indigo",
  completed: "green",
  failed: "red",
  paused: "amber",
};

export function JobsListPage() {
  const toast = useToast();
  const navigate = useNavigate();
  const { hasPermission } = useAuth();
  const canRun = hasPermission("job:run");

  const [data, setData] = useState<JobList | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [quickStarting, setQuickStarting] = useState(false);
  const [page, setPage] = useState(1);
  const [status, setStatus] = useState("");
  const [chartJobs, setChartJobs] = useState<Job[]>([]);
  const [deletingId, setDeletingId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const res = await forensicApi.listJobs({
        page,
        page_size: PAGE_SIZE,
        status: status || undefined,
      });
      setData(res);
    } catch (e: unknown) {
      setLoadError(e instanceof Error ? e.message : "Failed to load jobs");
    } finally {
      setLoading(false);
    }
  }, [page, status]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    forensicApi
      .listJobs({ page: 1, page_size: 100 }, { service: "forensic" })
      .then((res) => setChartJobs(res.items))
      .catch(() => setChartJobs([]));
  }, []);

  async function quickStartFromFolder() {
    if (quickStarting) return;
    setQuickStarting(true);
    try {
      const job = await forensicApi.createJob({
        type: "host_disk",
        domain_pack: "forensic",
        case_id: null,
      });
      toast.success("Job created — pick the image folder on this computer");
      navigate(`/forensic/jobs/${job.id}`, {
        state: { autoSelectFolder: true },
      });
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Could not create job");
    } finally {
      setQuickStarting(false);
    }
  }

  async function hardDeleteJob(job: Job) {
    const ok = window.confirm(
      `Permanently delete job ${job.id}?\n\nThis hard-deletes the job and every related file, object, and database row. This cannot be undone.`
    );
    if (!ok || deletingId) return;
    setDeletingId(job.id);
    try {
      await forensicApi.deleteJob(job.id);
      toast.success("Job deleted");
      await load();
      forensicApi
        .listJobs({ page: 1, page_size: 100 }, { service: "forensic" })
        .then((res) => setChartJobs(res.items))
        .catch(() => {});
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Could not delete job");
    } finally {
      setDeletingId(null);
    }
  }

  const totalPages = data ? Math.max(1, Math.ceil(data.total / PAGE_SIZE)) : 1;
  const statusSeries = useMemo(() => countBy(chartJobs, (j) => j.status), [chartJobs]);
  const typeSeries = useMemo(() => countBy(chartJobs, (j) => j.type || "disk"), [chartJobs]);

  return (
    <div>
      <PageHeader
        title="Forensic jobs"
        subtitle="Manage evidence processing pipelines and track extraction progress."
        actions={
          canRun && (
            <div className="flex flex-wrap gap-2">
              <Button variant="brand" loading={quickStarting} onClick={() => void quickStartFromFolder()}>
                <FolderOpen className="h-4 w-4" /> Select folder &amp; start
              </Button>
              <Link to="/forensic/jobs/new">
                <Button variant="outline">
                  <Plus className="h-4 w-4" /> New job
                </Button>
              </Link>
            </div>
          )
        }
      />

      {chartJobs.length > 0 && (
        <InsightCharts
          left={{ title: "Job status", subtitle: "From /api/jobs", data: statusSeries, kind: "bar" }}
          right={{ title: "Job type", subtitle: "Evidence pipelines", data: typeSeries, kind: "donut", centerLabel: "Jobs" }}
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
            <option value="pending">pending</option>
            <option value="processing">processing</option>
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
          empty={<p className="px-5 py-16 text-center text-sm text-ink-400">No jobs found.</p>}
        >
          <div className="overflow-x-auto">
            <table className="w-full text-left text-sm">
              <thead>
                <tr className="table-head border-b border-brand-300/70 text-xs uppercase tracking-wider text-ink-700">
                  <th className="px-5 py-3 font-semibold">Job ID</th>
                  <th className="px-5 py-3 font-semibold">Type</th>
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
                    <td className="px-5 py-3 text-ink-600">
                      <span className="font-medium text-ink-800">
                        {job.type === "mobile_extraction"
                          ? "Mobile image"
                          : job.type === "host_disk"
                            ? "Host disk"
                            : job.type === "vulnerability"
                              ? "Vulnerability"
                              : job.type || job.domain_pack}
                      </span>
                      {job.domain_pack ? (
                        <span className="ml-1 text-xs text-ink-400">({job.domain_pack})</span>
                      ) : null}
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
                      <div className="flex items-center justify-end gap-1">
                        <Link
                          to={`/forensic/jobs/${job.id}`}
                          className="inline-flex items-center gap-1 rounded-lg px-3 py-1.5 text-xs font-semibold text-brand-600 hover:bg-brand-50"
                        >
                          <Eye className="h-3.5 w-3.5" /> Open
                        </Link>
                        {canRun && (
                          <Button
                            variant="danger"
                            className="px-2.5 py-1.5 text-xs"
                            loading={deletingId === job.id}
                            onClick={() => void hardDeleteJob(job)}
                          >
                            <Trash2 className="h-3.5 w-3.5" /> Delete
                          </Button>
                        )}
                      </div>
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
