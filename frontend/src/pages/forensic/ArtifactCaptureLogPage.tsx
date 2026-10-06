import { useCallback, useEffect, useMemo, useState } from "react";
import { Calendar, Search } from "lucide-react";
import { Badge, Button, Card, Field, Input, PageHeader, Select, Spinner } from "../../components/ui";
import { forensicApi } from "../../lib/forensicApi";
import { stripAxiomBranding } from "../../lib/displayText";
import { formatForensicTimestamp } from "../../lib/formatDateTime";
import { useToast } from "../../lib/toast";
import type { CaptureLogEntry, Job } from "../../lib/types/forensic";

function toDayStartIso(date: string): string {
  return new Date(`${date}T00:00:00`).toISOString();
}

function toDayEndIso(date: string): string {
  return new Date(`${date}T23:59:59.999`).toISOString();
}

export function ArtifactCaptureLogPage() {
  const toast = useToast();
  const [jobs, setJobs] = useState<Job[]>([]);
  const [jobId, setJobId] = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [entries, setEntries] = useState<CaptureLogEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [storageUri, setStorageUri] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [jobsLoading, setJobsLoading] = useState(true);

  useEffect(() => {
    forensicApi
      .listJobs({ page: 1, page_size: 100 })
      .then((res) => {
        setJobs(res.items);
        if (res.items.length > 0) setJobId(res.items[0].id);
      })
      .catch((e: unknown) => {
        toast.error(e instanceof Error ? e.message : "Failed to load jobs");
      })
      .finally(() => setJobsLoading(false));
  }, [toast]);

  const jobOptions = useMemo(() => jobs, [jobs]);

  const load = useCallback(async () => {
    if (!jobId) return;
    setLoading(true);
    try {
      const query: { from?: string; to?: string; limit?: number } = { limit: 1000 };
      if (dateFrom) query.from = toDayStartIso(dateFrom);
      if (dateTo) query.to = toDayEndIso(dateTo);
      const res = await forensicApi.listCaptureLogs(jobId, query);
      setEntries(res.items);
      setTotal(res.total);
      setStorageUri(res.storage_uri);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to load capture logs");
    } finally {
      setLoading(false);
    }
  }, [jobId, dateFrom, dateTo, toast]);

  useEffect(() => {
    if (jobId) load();
  }, [jobId, load]);

  return (
    <div>
      <PageHeader
        title="Artifact capture log"
        subtitle="Review datetime-stamped artifact capture details stored in MinIO for each forensic job."
      />

      <Card className="mb-6 p-4">
        <div className="grid gap-4 md:grid-cols-4 md:items-end">
          <Field label="Job">
            {jobsLoading ? (
              <Spinner className="h-5 w-5" />
            ) : (
              <Select value={jobId} onChange={(e) => setJobId(e.target.value)}>
                <option value="">Select a job</option>
                {jobOptions.map((j) => (
                  <option key={j.id} value={j.id}>
                    {j.id.slice(0, 8)}… · {j.status} · {new Date(j.created_at).toLocaleDateString()}
                  </option>
                ))}
              </Select>
            )}
          </Field>
          <Field label="From date">
            <Input type="date" value={dateFrom} onChange={(e) => setDateFrom(e.target.value)} />
          </Field>
          <Field label="To date">
            <Input type="date" value={dateTo} onChange={(e) => setDateTo(e.target.value)} />
          </Field>
          <Button onClick={load} disabled={!jobId || loading}>
            <Search className="mr-2 h-4 w-4" />
            Search
          </Button>
        </div>
        {storageUri ? (
          <p className="mt-3 text-xs text-ink-500 truncate" title={storageUri}>
            Log file: {storageUri}
          </p>
        ) : null}

      </Card>

      <Card className="overflow-hidden">
        <div className="flex items-center justify-between border-b border-ink-100 px-4 py-3">
          <div className="flex items-center gap-2 text-sm text-ink-600">
            <Calendar className="h-4 w-4" />
            {total} capture event{total === 1 ? "" : "s"}
            {(dateFrom || dateTo) && " in selected range"}
          </div>
          {loading ? <Spinner className="h-4 w-4" /> : null}
        </div>

        {loading && entries.length === 0 ? (
          <div className="flex justify-center py-16">
            <Spinner className="h-8 w-8" />
          </div>
        ) : entries.length === 0 ? (
          <p className="px-4 py-12 text-center text-sm text-ink-500">
            No capture log entries found. Process a job to record artifacts, then search again.
          </p>
        ) : (
          <div className="max-h-[640px] overflow-auto">
            <table className="w-full text-left text-sm">
              <thead className="table-head sticky top-0 text-xs uppercase text-ink-700">
                <tr>
                  <th className="px-4 py-2 font-medium">Timestamp (local)</th>
                  <th className="px-4 py-2 font-medium">Type</th>
                  <th className="px-4 py-2 font-medium">Title</th>
                  <th className="px-4 py-2 font-medium">Category</th>
                  <th className="px-4 py-2 font-medium">Source path</th>
                </tr>
              </thead>
              <tbody>
                {entries.map((row, idx) => (
                  <tr key={`${row.artifact_id ?? idx}-${row.timestamp}`} className="border-t border-ink-100">
                    <td className="whitespace-nowrap px-4 py-2 font-mono text-xs text-ink-600">
                      {formatForensicTimestamp(row)}
                    </td>
                    <td className="px-4 py-2">
                      <Badge tone="neutral">{row.artifact_type ?? row.event}</Badge>
                    </td>
                    <td className="max-w-[200px] px-4 py-2" title={row.title ?? undefined}>
                      <span className="inline-flex max-w-full items-center gap-2 truncate">
                        <span className="truncate">{row.title ?? row.message ?? "—"}</span>
                        {row.details?.ocr_text ? <Badge tone="indigo">OCR</Badge> : null}
                      </span>
                    </td>
                    <td className="max-w-[160px] truncate px-4 py-2 text-ink-600">
                      {stripAxiomBranding(
                        [row.axiom_category, row.axiom_sub_category].filter(Boolean).join(" › ")
                      ) || "—"}
                    </td>
                    <td className="max-w-[280px] truncate px-4 py-2 font-mono text-xs text-ink-500" title={row.source_path ?? undefined}>
                      {row.source_path ?? "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
