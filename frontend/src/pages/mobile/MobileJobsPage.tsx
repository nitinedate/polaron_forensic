import { useCallback, useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Plus, Smartphone, Trash2 } from "lucide-react";
import { Badge, Button, Card, LoadPanel, PageHeader } from "../../components/ui";
import { forensicApi } from "../../lib/forensicApi";
import { useAuth } from "../../lib/auth";
import { useToast } from "../../lib/toast";
import { mobilePlatformService, mobileUiBasePath } from "../../lib/serviceMode";
import type { ApiService } from "../../lib/api";
import type { Job, JobList } from "../../lib/types/forensic";

const tones: Record<string, "neutral" | "green" | "amber" | "red" | "indigo"> = {
  created: "neutral",
  registered: "amber",
  processing: "indigo",
  building_disk: "indigo",
  indexing: "indigo",
  completed: "green",
  ready: "green",
  failed: "red",
  paused: "amber",
};

export function MobileJobsPage() {
  const platform = mobilePlatformService() ?? "android";
  const service = `mobile-${platform}` as ApiService;
  const jobType = `${platform}_mobile`;
  const label = platform === "ios" ? "iOS" : "Android";
  const base = mobileUiBasePath(platform);
  const toast = useToast();
  const { hasPermission } = useAuth();
  const canRun = hasPermission("job:run");
  const [data, setData] = useState<JobList | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const [deletingAll, setDeletingAll] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      setData(await forensicApi.listJobs({ page: 1, page_size: 100, type: jobType }, { service }));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Unable to load mobile jobs");
    } finally {
      setLoading(false);
    }
  }, [jobType, service]);

  useEffect(() => {
    void load();
  }, [load]);

  async function hardDeleteJob(job: Job) {
    const ok = window.confirm(
      `Permanently delete ${label} job ${job.id}?\n\n` +
        `Removes job metadata, RAG index and staging. Original mobile image files on the host are NOT deleted.`,
    );
    if (!ok || deletingId) return;
    setDeletingId(job.id);
    try {
      await forensicApi.deleteJob(job.id, { service });
      toast.success("Job deleted — host images preserved");
      await load();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Could not delete job");
    } finally {
      setDeletingId(null);
    }
  }

  async function hardDeleteAllJobs() {
    const items = data?.items ?? [];
    if (!items.length || deletingAll) return;
    const ok = window.confirm(
      `Delete ALL ${items.length} ${label} jobs?\n\n` +
        `Removes every job's metadata, RAG index and staging copies.\n` +
        `Original mobile image files on the host evidence folders are NOT deleted.`,
    );
    if (!ok) return;
    setDeletingAll(true);
    let deleted = 0;
    try {
      for (const job of items) {
        await forensicApi.deleteJob(job.id, { service });
        deleted += 1;
      }
      toast.success(`Deleted ${deleted} ${label} job(s) — host images preserved`);
      await load();
    } catch (e: unknown) {
      toast.error(
        e instanceof Error
          ? `Deleted ${deleted} then failed: ${e.message}`
          : `Deleted ${deleted} then failed`,
      );
      await load();
    } finally {
      setDeletingAll(false);
    }
  }

  return (
    <div>
      <PageHeader
        title={`${label} mobile jobs`}
        subtitle={`Independent ${label} extraction, RAG and reporting pipeline — same controls as Disk RAG.`}
        actions={
          <div className="flex flex-wrap gap-2">
            {canRun && (data?.items?.length ?? 0) > 0 ? (
              <Button variant="danger" loading={deletingAll} onClick={() => void hardDeleteAllJobs()}>
                <Trash2 className="h-4 w-4" /> Delete all jobs
              </Button>
            ) : null}
            <Link to={`${base}/acquire`}>
              <Button variant="outline">Device → Image</Button>
            </Link>
            <Link to={`${base}/new`}>
              <Button variant="brand">
                <Plus className="h-4 w-4" /> Images → RAG
              </Button>
            </Link>
          </div>
        }
      />
      <Card className="overflow-hidden">
        <LoadPanel
          loading={loading}
          error={error}
          hasData={Boolean(data?.items.length)}
          onRetry={() => void load()}
          empty={
            <div className="py-16 text-center text-sm text-ink-400">
              <Smartphone className="mx-auto mb-2 h-8 w-8" />
              No {label} jobs yet.
            </div>
          }
        >
          <div className="divide-y divide-ink-100">
            {(data?.items ?? []).map((job) => (
              <div key={job.id} className="grid grid-cols-[1fr_auto] gap-4 p-4 hover:bg-ink-50">
                <Link to={`${base}/jobs/${job.id}`} className="min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-mono text-xs text-ink-500">{job.id.slice(0, 12)}…</span>
                    <Badge tone={tones[job.status] ?? "neutral"}>{job.status}</Badge>
                  </div>
                  <div className="mt-2 h-1.5 max-w-md rounded-full bg-ink-100">
                    <div
                      className="h-1.5 rounded-full bg-brand-500"
                      style={{ width: `${Math.max(0, Math.min(100, job.progress_pct || 0))}%` }}
                    />
                  </div>
                  <p className="mt-1 text-xs text-ink-400">
                    {job.progress_pct ?? 0}% · {new Date(job.updated_at).toLocaleString()}
                  </p>
                </Link>
                <div className="flex items-center gap-2 self-center">
                  <Link to={`${base}/jobs/${job.id}`} className="text-xs font-semibold text-brand-700">
                    Open
                  </Link>
                  {canRun ? (
                    <Button
                      variant="danger"
                      className="h-8 px-2"
                      loading={deletingId === job.id}
                      disabled={Boolean(deletingId) || deletingAll}
                      onClick={() => void hardDeleteJob(job)}
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </Button>
                  ) : null}
                </div>
              </div>
            ))}
          </div>
        </LoadPanel>
      </Card>
    </div>
  );
}
