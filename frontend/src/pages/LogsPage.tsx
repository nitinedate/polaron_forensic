import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { ChevronDown, Pause, Play, RefreshCw, ScrollText, Search } from "lucide-react";
import clsx from "clsx";
import { Badge, Button, Card, Input, LoadPanel, PageHeader, Select } from "../components/ui";
import { ChartCard, MetricDonutChart } from "../components/charts";
import { countBy } from "../lib/chartCounts";
import { forensicApi } from "../lib/forensicApi";
import { formatIstTimestamp, istLocalInputToQuery } from "../lib/formatDateTime";
import { useToast } from "../lib/toast";
import { isVulnModuleEnabled } from "../lib/vulnFlags";
import type { UnifiedLogEntry, UnifiedLogSource } from "../lib/types/forensic";

const PAGE_SIZE = 50;

const LEVEL_TEXT: Record<string, string> = {
  error: "text-red-400",
  warning: "text-amber-400",
  info: "text-emerald-400",
  debug: "text-ink-400",
};

function jobHref(entry: UnifiedLogEntry): string | null {
  if (!entry.job_id) return null;
  if (entry.source_type === "vuln") return "/vuln/scans";
  if (entry.source_type === "mobile") return `/forensic/jobs/${entry.job_id}`;
  return `/forensic/jobs/${entry.job_id}`;
}

export function LogsPage() {
  const toast = useToast();
  const canVuln = isVulnModuleEnabled();

  const [sourceType, setSourceType] = useState("all");
  const [origin, setOrigin] = useState("all");
  const [jobKey, setJobKey] = useState("all");
  const [level, setLevel] = useState("all");
  const [fromLocal, setFromLocal] = useState("");
  const [toLocal, setToLocal] = useState("");
  const [q, setQ] = useState("");
  const [qDraft, setQDraft] = useState("");
  const [sources, setSources] = useState<UnifiedLogSource[]>([]);
  const [items, setItems] = useState<UnifiedLogEntry[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [live, setLive] = useState(true);
  const scrollRef = useRef<HTMLDivElement>(null);
  const sentinelRef = useRef<HTMLDivElement>(null);
  const loadingMoreRef = useRef(false);
  const pageRef = useRef(1);
  const totalRef = useRef(0);
  const itemsLenRef = useRef(0);

  const filteredSources = useMemo(
    () =>
      sources.filter((s) => {
        if (sourceType !== "all" && s.source_type !== sourceType) return false;
        if (origin !== "all" && (s.origin || "inhouse") !== origin) return false;
        return true;
      }),
    [sources, sourceType, origin]
  );

  const selectedJobId = jobKey === "all" ? undefined : jobKey.split(":").slice(1).join(":");

  const loadSources = useCallback(async () => {
    try {
      const res = await forensicApi.listLogSources({
        source_type: sourceType === "all" ? undefined : sourceType,
        origin: origin === "all" ? undefined : origin,
      });
      setSources(res.items);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to load jobs");
    }
  }, [origin, sourceType, toast]);

  const loadLogs = useCallback(
    async (nextPage: number, append: boolean) => {
      if (append) setLoadingMore(true);
      else {
        setLoading(true);
        setLoadError(null);
      }
      try {
        const res = await forensicApi.listUnifiedLogs({
          source_type: sourceType === "all" ? undefined : sourceType,
          origin: origin === "all" ? undefined : origin,
          level: level === "all" ? undefined : level,
          job_id: selectedJobId,
          from: istLocalInputToQuery(fromLocal),
          to: istLocalInputToQuery(toLocal),
          q: q || undefined,
          page: nextPage,
          page_size: PAGE_SIZE,
        });
        setTotal(res.total);
        totalRef.current = res.total;
        pageRef.current = res.page;
        setItems((prev) => {
          const next = append ? [...prev, ...res.items] : res.items;
          itemsLenRef.current = next.length;
          return next;
        });
      } catch (e: unknown) {
        if (!append) setLoadError(e instanceof Error ? e.message : "Failed to load logs");
        else toast.error(e instanceof Error ? e.message : "Failed to load logs");
      } finally {
        setLoading(false);
        setLoadingMore(false);
        loadingMoreRef.current = false;
      }
    },
    [fromLocal, level, origin, q, selectedJobId, sourceType, toLocal, toast]
  );

  const loadNextPage = useCallback(() => {
    if (loadingMoreRef.current) return;
    if (itemsLenRef.current >= totalRef.current) return;
    loadingMoreRef.current = true;
    void loadLogs(pageRef.current + 1, true);
  }, [loadLogs]);

  useEffect(() => {
    void loadSources();
  }, [loadSources]);

  useEffect(() => {
    if (jobKey !== "all" && !filteredSources.some((s) => `${s.source_type}:${s.id}` === jobKey)) {
      setJobKey("all");
    }
  }, [filteredSources, jobKey]);

  useEffect(() => {
    void loadLogs(1, false);
  }, [loadLogs]);

  useEffect(() => {
    if (!live) return;
    const timer = window.setInterval(() => {
      const el = scrollRef.current;
      if (el && el.scrollTop > 48) return;
      if (pageRef.current > 1) return;
      void loadLogs(1, false);
    }, 8000);
    return () => window.clearInterval(timer);
  }, [live, loadLogs]);

  const hasMore = items.length < total;
  const levelSeries = useMemo(() => countBy(items, (e) => e.level || "info"), [items]);
  const sourceSeries = useMemo(() => countBy(items, (e) => e.source_type || "unknown"), [items]);

  useEffect(() => {
    const root = scrollRef.current;
    const sentinel = sentinelRef.current;
    if (!root || !sentinel || !hasMore) return;
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((entry) => entry.isIntersecting)) loadNextPage();
      },
      { root, rootMargin: "240px", threshold: 0 }
    );
    io.observe(sentinel);
    return () => io.disconnect();
  }, [hasMore, items.length, loadNextPage]);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el || loading || loadingMore || !hasMore) return;
    if (el.scrollHeight <= el.clientHeight + 8) {
      loadNextPage();
    }
  }, [hasMore, items.length, loadNextPage, loading, loadingMore]);

  return (
    <div className="flex h-[calc(100vh-8.5rem)] min-h-0 flex-col overflow-hidden">
      <div className="shrink-0">
      <PageHeader
        title="Logs"
        subtitle="Disk extract, mobile extract, in-house scans, and laptop scanner logs."
        actions={
          <div className="flex items-center gap-2">
            <Button variant={live ? "brand" : "outline"} onClick={() => setLive((v) => !v)}>
              {live ? <Pause className="h-4 w-4" /> : <Play className="h-4 w-4" />}
              {live ? "Live" : "Paused"}
            </Button>
            <Button
              variant="outline"
              onClick={() => {
                void loadSources();
                void loadLogs(1, false);
              }}
            >
              <RefreshCw className="h-4 w-4" /> Refresh
            </Button>
          </div>
        }
      />
      {items.length > 0 && (
        <div className="row g-3 mb-4">
          <div className="col-12 col-md-6">
            <ChartCard title="Log levels" subtitle="From unified logs API" height={160}>
              <MetricDonutChart data={levelSeries} centerLabel="Events" />
            </ChartCard>
          </div>
          <div className="col-12 col-md-6">
            <ChartCard title="Sources" subtitle="Disk / mobile / vuln" height={160}>
              <MetricDonutChart data={sourceSeries} centerLabel="Sources" />
            </ChartCard>
          </div>
        </div>
      )}
      </div>

      <Card className="mb-4 shrink-0 overflow-hidden">
        <div className="grid gap-3 p-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
          <label className="block text-xs font-semibold uppercase tracking-wider text-ink-500">
            Type
            <Select
              className="mt-1 w-full"
              value={sourceType}
              onChange={(e) => {
                setSourceType(e.target.value);
                setJobKey("all");
              }}
            >
              <option value="all">All</option>
              <option value="disk">Disk extract</option>
              <option value="mobile">Mobile extract</option>
              {canVuln && <option value="vuln">Vuln</option>}
            </Select>
          </label>

          <label className="block text-xs font-semibold uppercase tracking-wider text-ink-500">
            Origin
            <Select
              className="mt-1 w-full"
              value={origin}
              onChange={(e) => {
                setOrigin(e.target.value);
                setJobKey("all");
              }}
            >
              <option value="all">All</option>
              <option value="inhouse">In-house</option>
              <option value="external">External</option>
            </Select>
          </label>

          <label className="block text-xs font-semibold uppercase tracking-wider text-ink-500">
            Job
            <Select
              className="mt-1 w-full"
              value={jobKey}
              onChange={(e) => setJobKey(e.target.value)}
            >
              <option value="all">All jobs</option>
              {filteredSources.map((s) => (
                <option key={`${s.source_type}:${s.id}`} value={`${s.source_type}:${s.id}`}>
                  {s.label}
                </option>
              ))}
            </Select>
          </label>

          <label className="block text-xs font-semibold uppercase tracking-wider text-ink-500">
            Log type
            <Select className="mt-1 w-full" value={level} onChange={(e) => setLevel(e.target.value)}>
              <option value="all">All</option>
              <option value="error">Error</option>
              <option value="warning">Warning</option>
              <option value="info">Info</option>
              <option value="debug">Debug</option>
            </Select>
          </label>

          <label className="block text-xs font-semibold uppercase tracking-wider text-ink-500">
            From
            <Input
              type="datetime-local"
              className="mt-1 w-full"
              value={fromLocal}
              onChange={(e) => setFromLocal(e.target.value)}
            />
          </label>

          <label className="block text-xs font-semibold uppercase tracking-wider text-ink-500">
            To
            <Input
              type="datetime-local"
              className="mt-1 w-full"
              value={toLocal}
              onChange={(e) => setToLocal(e.target.value)}
            />
          </label>

          <label className="block text-xs font-semibold uppercase tracking-wider text-ink-500">
            Search
            <span className="mt-1 flex gap-2">
              <Input
                className="w-full"
                value={qDraft}
                placeholder="Message text"
                onChange={(e) => setQDraft(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") setQ(qDraft.trim());
                }}
              />
              <Button
                variant="outline"
                className="shrink-0 px-3"
                onClick={() => setQ(qDraft.trim())}
              >
                <Search className="h-4 w-4" />
              </Button>
            </span>
          </label>
        </div>
        <div className="flex items-center justify-between border-t border-ink-100 px-4 py-2 text-sm text-ink-500">
          <span>
            {total} matching log{total === 1 ? "" : "s"}
          </span>
          {(fromLocal || toLocal || q) && (
            <button
              className="text-xs font-semibold text-brand-700 hover:underline"
              onClick={() => {
                setFromLocal("");
                setToLocal("");
                setQ("");
                setQDraft("");
              }}
            >
              Clear time &amp; search
            </button>
          )}
        </div>
      </Card>

      <div className="flex min-h-0 flex-1 flex-col overflow-hidden rounded-xl border border-ink-800 bg-ink-950">
        <div className="flex shrink-0 items-center justify-between border-b border-ink-800 px-4 py-2 text-ink-300">
          <div className="flex items-center gap-2">
            <ScrollText className="h-4 w-4" />
            <span className="text-xs font-semibold uppercase tracking-wider">All logs</span>
            <ChevronDown className="h-3.5 w-3.5 text-ink-500" />
          </div>
          <span className="text-xs text-ink-500">
            Showing {items.length}
            {total ? ` of ${total}` : ""}
          </span>
        </div>

        <div
          ref={scrollRef}
          className="min-h-0 flex-1 overflow-auto overscroll-contain font-mono text-[12px] leading-5 [scrollbar-gutter:stable]"
        >
          <LoadPanel
            loading={loading}
            error={loadError}
            hasData={items.length > 0}
            onRetry={() => void loadLogs(1, false)}
            empty={<p className="px-4 py-16 text-center text-sm text-ink-500">No logs match the current filters.</p>}
          >
            <table className="w-full border-collapse text-left">
              <thead className="sticky top-0 bg-ink-950 text-[11px] uppercase tracking-wider text-ink-500">
                <tr>
                  <th className="whitespace-nowrap px-3 py-2 font-semibold">Time</th>
                  <th className="whitespace-nowrap px-3 py-2 font-semibold">Type</th>
                  <th className="whitespace-nowrap px-3 py-2 font-semibold">Origin</th>
                  <th className="whitespace-nowrap px-3 py-2 font-semibold">Log type</th>
                  <th className="whitespace-nowrap px-3 py-2 font-semibold">Job</th>
                  <th className="whitespace-nowrap px-3 py-2 font-semibold">Stage</th>
                  <th className="px-3 py-2 font-semibold">Message</th>
                </tr>
              </thead>
              <tbody>
                {items.map((entry) => {
                  const href = jobHref(entry);
                  return (
                    <tr key={entry.id} className="border-t border-ink-800/80 align-top hover:bg-ink-900/80">
                      <td className="whitespace-nowrap px-3 py-1.5 text-ink-300">
                        {(entry.timestamp_ist || formatIstTimestamp(entry.timestamp)).replace(/\s*(?:IST|\(Asia\/Kolkata\))$/, "")}
                      </td>
                      <td className="whitespace-nowrap px-3 py-1.5">
                        <Badge
                          tone={
                            entry.source_type === "vuln"
                              ? "indigo"
                              : entry.source_type === "mobile"
                                ? "amber"
                                : "neutral"
                          }
                        >
                          {entry.source_label}
                        </Badge>
                      </td>
                      <td className="whitespace-nowrap px-3 py-1.5">
                        <Badge tone={entry.origin === "external" ? "green" : "neutral"}>
                          {entry.origin_label || (entry.origin === "external" ? "External" : "In-house")}
                        </Badge>
                      </td>
                      <td className="whitespace-nowrap px-3 py-1.5">
                        <span className={clsx("font-semibold uppercase", LEVEL_TEXT[entry.level] || "text-ink-300")}>
                          {entry.level}
                        </span>
                      </td>
                      <td className="max-w-[14rem] truncate px-3 py-1.5 text-ink-200" title={entry.job_label}>
                        {href ? (
                          <Link className="hover:underline" to={href}>
                            {entry.job_label}
                          </Link>
                        ) : (
                          entry.job_label
                        )}
                      </td>
                      <td className="whitespace-nowrap px-3 py-1.5 text-sky-300">{entry.stage}</td>
                      <td className="whitespace-pre-wrap break-all px-3 py-1.5 text-ink-100">{entry.message}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </LoadPanel>
          {items.length > 0 && (
            <div ref={sentinelRef} className="h-8 w-full" aria-hidden />
          )}
          {loadingMore && (
            <p className="border-t border-ink-800 px-4 py-3 text-center text-xs text-ink-400">
              Loading more logs…
            </p>
          )}
          {!hasMore && items.length > 0 && !loading && (
            <p className="border-t border-ink-800 px-4 py-3 text-center text-xs text-ink-500">
              End of logs
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
