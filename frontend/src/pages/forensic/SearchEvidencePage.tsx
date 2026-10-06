import { useCallback, useEffect, useState } from "react";
import { Search } from "lucide-react";
import { Badge, Button, Card, Field, Input, PageHeader, Select, Spinner } from "../../components/ui";
import { stripVendorBranding } from "../../lib/displayText";
import { forensicApi } from "../../lib/forensicApi";
import { useToast } from "../../lib/toast";
import type { EvidenceActivity, Job } from "../../lib/types/forensic";

const PAGE_SIZE = 100;

function toDayStartIso(date: string): string {
  return new Date(`${date}T00:00:00`).toISOString();
}

function toDayEndIso(date: string): string {
  return new Date(`${date}T23:59:59.999`).toISOString();
}

function formatTimestamp(iso: string) {
  try {
    return new Date(iso).toLocaleString();
  } catch {
    return iso;
  }
}

function formatBytes(size: number | null | undefined) {
  if (size == null || size <= 0) return "—";
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  if (size < 1024 * 1024 * 1024) return `${(size / (1024 * 1024)).toFixed(1)} MB`;
  return `${(size / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

const PARSE_TONE: Record<string, "neutral" | "green" | "amber" | "red" | "indigo"> = {
  parsed: "green",
  pending: "amber",
  skipped: "neutral",
  no_parser: "neutral",
};

export function SearchEvidencePage() {
  const toast = useToast();
  const [jobs, setJobs] = useState<Job[]>([]);
  const [jobsLoading, setJobsLoading] = useState(true);
  const [jobId, setJobId] = useState("");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [query, setQuery] = useState("");
  const [entries, setEntries] = useState<EvidenceActivity[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loading, setLoading] = useState(false);
  const [searched, setSearched] = useState(false);

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

  const search = useCallback(
    async (targetPage: number) => {
      if (!jobId) return;
      setLoading(true);
      try {
        const res = await forensicApi.searchEvidence(jobId, {
          from: dateFrom ? toDayStartIso(dateFrom) : undefined,
          to: dateTo ? toDayEndIso(dateTo) : undefined,
          q: query.trim() || undefined,
          scope: "artifacts",
          page: targetPage,
          page_size: PAGE_SIZE,
        });
        setEntries(res.items);
        setTotal(res.total);
        setSearched(true);
      } catch (e: unknown) {
        toast.error(e instanceof Error ? e.message : "Search failed");
        setEntries([]);
        setTotal(0);
      } finally {
        setLoading(false);
      }
    },
    [jobId, dateFrom, dateTo, query, toast]
  );

  useEffect(() => {
    if (jobId && searched && page > 1) {
      void search(page);
    }
  }, [page, jobId, searched, search]);

  function runSearch() {
    setSearched(true);
    setPage(1);
    void search(1);
  }

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div>
      <PageHeader
        title="Search evidence"
        subtitle="Find forensic artifacts captured for a job within a date range."
      />

      <Card className="mb-6 p-4">
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5 md:items-end">
          <Field label="Job ID">
            {jobsLoading ? (
              <Spinner className="h-5 w-5" />
            ) : (
              <Select
                value={jobId}
                onChange={(e) => {
                  setJobId(e.target.value);
                  setSearched(false);
                  setEntries([]);
                  setTotal(0);
                  setPage(1);
                }}
              >
                <option value="">Select a job</option>
                {jobs.map((j) => (
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
          <Field label="Search text">
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="File name, path, or category…"
              onKeyDown={(e) => {
                if (e.key === "Enter") runSearch();
              }}
            />
          </Field>
          <Button onClick={runSearch} disabled={!jobId || loading}>
            <Search className="mr-2 h-4 w-4" />
            Search
          </Button>
        </div>
      </Card>

      <Card className="overflow-hidden">
        <div className="flex items-center justify-between border-b border-ink-100 px-4 py-3">
          <p className="text-sm text-ink-600">
            {searched ? (
              <>
                {total.toLocaleString()} artifact{total === 1 ? "" : "s"}
                {(dateFrom || dateTo) && " in selected date range"}
              </>
            ) : (
              "Select a job and optional date range, then click Search."
            )}
          </p>
          {loading ? <Spinner className="h-4 w-4" /> : null}
        </div>

        {loading && entries.length === 0 ? (
          <div className="flex justify-center py-16">
            <Spinner className="h-8 w-8" />
          </div>
        ) : !searched ? (
          <p className="px-4 py-12 text-center text-sm text-ink-500">
            Use the date filters to narrow artifacts by capture time, then click Search.
          </p>
        ) : entries.length === 0 ? (
          <p className="px-4 py-12 text-center text-sm text-ink-500">
            No artifacts match your filters. Try widening the date range or clearing the search text.
          </p>
        ) : (
          <>
            <div className="max-h-[640px] overflow-auto">
              <table className="w-full text-left text-sm">
                <thead className="table-head sticky top-0 text-xs uppercase text-ink-700">
                  <tr>
                    <th className="px-4 py-2 font-medium">Captured</th>
                    <th className="px-4 py-2 font-medium">File name</th>
                    <th className="px-4 py-2 font-medium">Extension</th>
                    <th className="px-4 py-2 font-medium">Category</th>
                    <th className="px-4 py-2 font-medium">Parse status</th>
                    <th className="px-4 py-2 font-medium">Size</th>
                    <th className="px-4 py-2 font-medium">SHA256</th>
                    <th className="px-4 py-2 font-medium">Path</th>
                  </tr>
                </thead>
                <tbody>
                  {entries.map((row) => (
                    <tr key={`${row.id}-${row.timestamp}`} className="border-t border-ink-100">
                      <td className="whitespace-nowrap px-4 py-2 font-mono text-xs text-ink-600">
                        {formatTimestamp(row.timestamp)}
                      </td>
                      <td className="max-w-[180px] truncate px-4 py-2 font-medium text-ink-800" title={row.file_name ?? row.message ?? undefined}>
                        {row.file_name ?? row.message ?? "—"}
                      </td>
                      <td className="px-4 py-2 font-mono text-xs text-ink-600">
                        {row.artifact_type ?? "—"}
                      </td>
                      <td className="max-w-[140px] truncate px-4 py-2 text-ink-600" title={stripVendorBranding(row.axiom_category) || undefined}>
                        {stripVendorBranding(row.axiom_category) || "—"}
                      </td>
                      <td className="px-4 py-2">
                        <Badge tone={PARSE_TONE[row.parse_status ?? ""] ?? "neutral"}>
                          {row.parse_status ?? "—"}
                        </Badge>
                      </td>
                      <td className="whitespace-nowrap px-4 py-2 text-ink-600">
                        {formatBytes(row.size_bytes)}
                      </td>
                      <td className="max-w-[120px] truncate px-4 py-2 font-mono text-xs text-ink-500" title={row.sha256 ?? undefined}>
                        {row.sha256 ? `${row.sha256.slice(0, 12)}…` : "—"}
                      </td>
                      <td className="max-w-[280px] truncate px-4 py-2 font-mono text-xs text-ink-500" title={row.source_path ?? undefined}>
                        {row.source_path ?? "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            {total > PAGE_SIZE ? (
              <div className="flex items-center justify-between border-t border-ink-100 px-4 py-3 text-sm text-ink-600">
                <span>
                  Page {page} / {totalPages}
                </span>
                <div className="flex items-center gap-2">
                  <Button variant="ghost" disabled={page <= 1 || loading} onClick={() => setPage((p) => p - 1)}>
                    Previous
                  </Button>
                  <Button
                    variant="ghost"
                    disabled={page >= totalPages || loading}
                    onClick={() => setPage((p) => p + 1)}
                  >
                    Next
                  </Button>
                </div>
              </div>
            ) : null}
          </>
        )}
      </Card>
    </div>
  );
}
