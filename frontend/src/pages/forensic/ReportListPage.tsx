import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ExternalLink, Eye, RefreshCw } from "lucide-react";
import { Badge, Button, Card, Field, Input, LoadPanel, PageHeader, Select } from "../../components/ui";
import { forensicApi } from "../../lib/forensicApi";
import type { Job, ReportCatalogEntry } from "../../lib/types/forensic";
import { InsightCharts } from "../../components/charts";
import { countBy } from "../../lib/chartCounts";

const PAGE_SIZE = 20;

const REPORT_STATUS_TONE: Record<string, "neutral" | "green" | "amber" | "red" | "indigo"> = {
  completed: "green",
  running: "amber",
  failed: "red",
  none: "neutral",
};

function formatDate(iso: string | null | undefined) {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function toDayStartIso(date: string): string {
  return new Date(`${date}T00:00:00`).toISOString();
}

function toDayEndIso(date: string): string {
  return new Date(`${date}T23:59:59.999`).toISOString();
}

export function ReportListPage() {
  const [entries, setEntries] = useState<ReportCatalogEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [jobs, setJobs] = useState<Job[]>([]);

  const [jobId, setJobId] = useState("");
  const [runStatus, setRunStatus] = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");

  useEffect(() => {
    forensicApi
      .listJobs({ page: 1, page_size: 100 })
      .then((res) => setJobs(res.items))
      .catch(() => setJobs([]));
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const res = await forensicApi.listReportCatalog({
        job_id: jobId || undefined,
        run_status: runStatus || undefined,
        from: dateFrom ? toDayStartIso(dateFrom) : undefined,
        to: dateTo ? toDayEndIso(dateTo) : undefined,
        page,
        page_size: PAGE_SIZE,
      });
      setEntries(res.items ?? []);
      setTotal(res.total ?? 0);
    } catch (e: unknown) {
      setLoadError(e instanceof Error ? e.message : "Failed to load reports");
    } finally {
      setLoading(false);
    }
  }, [jobId, runStatus, dateFrom, dateTo, page]);

  useEffect(() => {
    void load();
  }, [load]);

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));
  const reportStatusSeries = useMemo(() => countBy(entries, (e) => e.report_status || "none"), [entries]);
  const jobStatusSeries = useMemo(() => countBy(entries, (e) => e.job_status || "unknown"), [entries]);

  return (
    <div>
      <PageHeader
        title="Report list"
        subtitle="All forensic jobs with report versions, creator, organization, and direct links to the report editor."
        actions={
          <Button variant="outline" onClick={() => void load()} disabled={loading}>
            <RefreshCw className="h-4 w-4" /> Refresh
          </Button>
        }
      />

      {entries.length > 0 && (
        <InsightCharts
          left={{ title: "Report status", subtitle: "From report catalog API", data: reportStatusSeries, kind: "bar" }}
          right={{ title: "Job status", subtitle: "Linked forensic jobs", data: jobStatusSeries, kind: "donut", centerLabel: "Reports" }}
        />
      )}

      <Card className="mb-6 p-4">
        <div className="grid gap-4 md:grid-cols-3 lg:grid-cols-5 md:items-end">
          <Field label="Job">
            <Select value={jobId} onChange={(e) => { setJobId(e.target.value); setPage(1); }}>
              <option value="">All jobs</option>
              {jobs.map((j) => (
                <option key={j.id} value={j.id}>
                  {j.id.slice(0, 8)}… · {j.status}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Report status">
            <Select value={runStatus} onChange={(e) => { setRunStatus(e.target.value); setPage(1); }}>
              <option value="">Any status</option>
              <option value="completed">Completed</option>
              <option value="running">Running</option>
              <option value="failed">Failed</option>
              <option value="none">No report yet</option>
            </Select>
          </Field>
          <Field label="From date">
            <Input type="date" value={dateFrom} onChange={(e) => { setDateFrom(e.target.value); setPage(1); }} />
          </Field>
          <Field label="To date">
            <Input type="date" value={dateTo} onChange={(e) => { setDateTo(e.target.value); setPage(1); }} />
          </Field>
          <Button onClick={() => void load()} disabled={loading}>
            Apply filters
          </Button>
        </div>
      </Card>

      <Card className="overflow-hidden">
        <LoadPanel
          loading={loading}
          error={loadError}
          hasData={entries.length > 0}
          onRetry={() => void load()}
          empty={
            <p className="p-10 text-center text-sm text-ink-500">
              No jobs match your filters. Create a disk job, complete intake, and generate a report from the Report editor.
            </p>
          }
        >
          <>
            <div className="overflow-x-auto">
              <table className="min-w-full text-left text-sm">
                <thead className="table-head text-xs uppercase tracking-wide text-ink-700">
                  <tr>
                    <th className="px-5 py-3 font-semibold">Job ID</th>
                    <th className="px-5 py-3 font-semibold">Version</th>
                    <th className="px-5 py-3 font-semibold">Created by</th>
                    <th className="px-5 py-3 font-semibold">Organization</th>
                    <th className="px-5 py-3 font-semibold">Job status</th>
                    <th className="px-5 py-3 font-semibold">Report status</th>
                    <th className="px-5 py-3 font-semibold">Sections</th>
                    <th className="px-5 py-3 font-semibold">Report created</th>
                    <th className="px-5 py-3 font-semibold">Exports</th>
                    <th className="px-5 py-3 font-semibold">View</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-ink-100">
                  {entries.map((item) => (
                    <tr
                      key={`${item.job_id}-${item.report_run_id ?? "none"}`}
                      className="hover:bg-slate-50/80"
                    >
                      <td className="px-5 py-3 font-mono text-xs text-ink-800" title={item.job_id}>
                        {item.job_id.slice(0, 8)}…
                      </td>
                      <td className="px-5 py-3">
                        {item.version ? (
                          <Badge tone="indigo">{item.version}</Badge>
                        ) : (
                          <span className="text-ink-400">—</span>
                        )}
                      </td>
                      <td className="px-5 py-3 text-ink-700">
                        {item.created_by_email ?? item.created_by ?? "—"}
                      </td>
                      <td className="max-w-[200px] truncate px-5 py-3 text-ink-700" title={item.organization ?? undefined}>
                        {item.organization ?? "—"}
                      </td>
                      <td className="px-5 py-3 capitalize text-ink-600">{item.job_status}</td>
                      <td className="px-5 py-3">
                        <Badge tone={REPORT_STATUS_TONE[item.report_status] ?? "neutral"}>
                          {item.report_status}
                        </Badge>
                      </td>
                      <td className="px-5 py-3 tabular-nums text-ink-600">
                        {item.report_run_id
                          ? `${item.sections_completed}/${item.sections_total ?? "—"}`
                          : "—"}
                      </td>
                      <td className="px-5 py-3 text-ink-700">
                        {formatDate(item.report_created_at ?? item.job_created_at)}
                      </td>
                      <td className="px-5 py-3 tabular-nums text-ink-600">{item.export_count}</td>
                      <td className="px-5 py-3">
                        <Link
                          to={`/forensic/jobs/${item.job_id}/report`}
                          className="inline-flex items-center gap-1 text-brand-700 hover:underline"
                        >
                          <Eye className="h-4 w-4" />
                          View
                          <ExternalLink className="h-3 w-3" />
                        </Link>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="flex items-center justify-between border-t border-ink-100 px-5 py-3 text-sm text-ink-600">
              <span>
                {total} row{total === 1 ? "" : "s"}
              </span>
              <div className="flex items-center gap-2">
                <Button variant="ghost" disabled={page <= 1} onClick={() => setPage((p) => p - 1)}>
                  Previous
                </Button>
                <span className="tabular-nums">
                  Page {page} / {totalPages}
                </span>
                <Button variant="ghost" disabled={page >= totalPages} onClick={() => setPage((p) => p + 1)}>
                  Next
                </Button>
              </div>
            </div>
          </>
        </LoadPanel>
      </Card>
    </div>
  );
}
