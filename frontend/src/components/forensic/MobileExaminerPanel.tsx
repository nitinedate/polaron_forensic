import { useCallback, useEffect, useRef, useState } from "react";
import { ChevronDown, ChevronRight, Download, Filter, RefreshCw, Shield } from "lucide-react";
import { Badge, Button, Spinner } from "../ui";
import { forensicApi } from "../../lib/forensicApi";
import { useToast } from "../../lib/toast";

type FilterBucket = "LIVE" | "HISTORICAL" | "RECOVERED" | "FRAGMENTS" | "UNVERIFIED" | "ALL";

type NormArtifact = {
  artifact_id: string;
  artifact_type: string;
  source_domain: string;
  timestamp_utc?: string | null;
  state?: string;
  ui_label?: string;
  data?: Record<string, unknown>;
  forensic?: {
    state?: string;
    source_path?: string;
    parser?: string;
    parser_version?: string;
    recovery_source?: string;
    confidence?: { label?: string; score?: number; validation?: string[] };
    examiner_status?: string;
  };
  examiner_status?: string;
};

const FILTERS: FilterBucket[] = ["ALL", "LIVE", "HISTORICAL", "RECOVERED", "FRAGMENTS", "UNVERIFIED"];

export function MobileExaminerPanel({ jobId }: { jobId: string }) {
  const toast = useToast();
  const [filter, setFilter] = useState<FilterBucket>("ALL");
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(false);
  const [artifacts, setArtifacts] = useState<NormArtifact[]>([]);
  const [selected, setSelected] = useState<NormArtifact | null>(null);
  const [timeline, setTimeline] = useState<NormArtifact[]>([]);
  const [counts, setCounts] = useState<{ total_artifacts?: number; inventory_total?: number } | null>(null);
  const queuedRef = useRef(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const opts =
        filter === "ALL"
          ? { limit: 200 }
          : { filter, limit: 200 };
      const [board, tl] = await Promise.all([
        forensicApi.getMobileNormalizedArtifacts(jobId, opts),
        forensicApi.getMobileTimeline(jobId, { limit: 80 }),
      ]);
      setArtifacts(board.artifacts || []);
      setCounts(board.counts || null);
      if ((board.artifacts || []).length === 0 && !queuedRef.current) {
        queuedRef.current = true;
        try {
          await forensicApi.runMobileAnalysis(jobId);
          toast.info("Building examiner artifacts in the background — refresh in a minute.");
        } catch {
          queuedRef.current = false;
        }
      }
      setTimeline(tl.events || []);
      setSelected((prev) => {
        if (!prev) return null;
        return (board.artifacts || []).find((a) => a.artifact_id === prev.artifact_id) || null;
      });
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Could not load normalized artifacts");
    } finally {
      setLoading(false);
    }
  }, [filter, jobId, toast]);

  useEffect(() => {
    if (open) void load();
  }, [open, load]);

  async function review(decision: "accepted" | "rejected") {
    if (!selected) return;
    try {
      await forensicApi.reviewMobileArtifact(jobId, selected.artifact_id, { decision });
      toast.success(`Marked ${decision}`);
      void load();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Review failed");
    }
  }

  async function exportCase() {
    try {
      await forensicApi.downloadMobileCasePackage(jobId);
      toast.success("Case package download started");
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Export failed");
    }
  }

  async function rerun() {
    try {
      setLoading(true);
      await forensicApi.runMobileAnalysis(jobId);
      toast.success("Analysis queued — refresh when counts appear");
      await load();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Analysis failed");
      setLoading(false);
    }
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <p className="flex items-center gap-2 text-sm font-semibold text-ink-800">
            <Shield className="h-4 w-4 text-brand-600" />
            Examiner review — normalized artifacts
          </p>
          <p className="mt-1 text-xs text-ink-500">
            State filters never label “deleted” solely because a live record is absent.
            {counts?.total_artifacts != null
              ? ` · ${counts.total_artifacts.toLocaleString()} artifacts`
              : open
                ? ""
                : " · Expand to load normalized artifacts."}
            {counts?.inventory_total != null
              ? ` · ${counts.inventory_total.toLocaleString()} inventory files`
              : ""}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" className="h-8 text-xs" onClick={() => setOpen((v) => !v)}>
            {open ? <ChevronDown className="mr-1 h-3.5 w-3.5" /> : <ChevronRight className="mr-1 h-3.5 w-3.5" />}
            {open ? "Collapse" : "Expand"}
          </Button>
          <Button variant="outline" className="h-8 text-xs" disabled={!open} onClick={() => void load()}>
            <RefreshCw className="mr-1 h-3.5 w-3.5" />
            Refresh
          </Button>
          <Button variant="outline" className="h-8 text-xs" onClick={() => void rerun()}>
            Re-analyze
          </Button>
          <Button variant="outline" className="h-8 text-xs" onClick={() => void exportCase()}>
            <Download className="mr-1 h-3.5 w-3.5" />
            Case ZIP
          </Button>
        </div>
      </div>

      {!open ? null : (
      <>
      <div className="flex flex-wrap items-center gap-1.5">
        <Filter className="h-3.5 w-3.5 text-ink-400" />
        {FILTERS.map((f) => (
          <button
            key={f}
            type="button"
            onClick={() => setFilter(f)}
            className={
              filter === f
                ? "rounded px-2 py-1 text-[11px] font-semibold bg-brand-600 text-white"
                : "rounded px-2 py-1 text-[11px] font-medium bg-ink-50 text-ink-600 hover:bg-ink-100"
            }
          >
            {f}
          </button>
        ))}
      </div>

      {loading ? (
        <div className="flex h-32 items-center justify-center">
          <Spinner />
        </div>
      ) : (
        <div className="grid gap-3 lg:grid-cols-2">
          <div className="max-h-96 overflow-y-auto rounded-md border border-ink-100">
            <table className="min-w-full text-left text-xs">
              <thead className="table-head sticky top-0 text-[10px] uppercase tracking-wide text-ink-700">
                <tr>
                  <th className="px-2 py-2">Type</th>
                  <th className="px-2 py-2">State</th>
                  <th className="px-2 py-2">Domain</th>
                  <th className="px-2 py-2">Time</th>
                </tr>
              </thead>
              <tbody>
                {artifacts.length === 0 ? (
                  <tr>
                    <td colSpan={4} className="px-3 py-6 text-center text-ink-400">
                      No normalized artifacts yet — run inventory or Re-analyze.
                    </td>
                  </tr>
                ) : (
                  artifacts.map((a) => (
                    <tr
                      key={a.artifact_id}
                      className={
                        selected?.artifact_id === a.artifact_id
                          ? "cursor-pointer border-t border-ink-100 bg-brand-50"
                          : "cursor-pointer border-t border-ink-100 hover:bg-ink-50/80"
                      }
                      onClick={() => setSelected(a)}
                    >
                      <td className="px-2 py-1.5 font-medium text-ink-800">{a.artifact_type}</td>
                      <td className="px-2 py-1.5">
                        <Badge tone={a.state === "allocated" ? "green" : "neutral"}>
                          {a.ui_label || a.state || "—"}
                        </Badge>
                      </td>
                      <td className="px-2 py-1.5 text-ink-500">{a.source_domain}</td>
                      <td className="px-2 py-1.5 font-mono text-[10px] text-ink-400">
                        {a.timestamp_utc ? String(a.timestamp_utc).slice(0, 19) : "—"}
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>

          <div className="rounded-md border border-ink-100 bg-ink-50/40 p-3 text-xs">
            {selected ? (
              <div className="space-y-2">
                <p className="font-semibold text-ink-800">Provenance</p>
                <dl className="grid grid-cols-[7rem_1fr] gap-y-1 text-ink-600">
                  <dt className="text-ink-400">Artifact</dt>
                  <dd className="font-mono text-[10px]">{selected.artifact_id}</dd>
                  <dt className="text-ink-400">Source path</dt>
                  <dd className="break-all font-mono text-[10px]">
                    {selected.forensic?.source_path || "—"}
                  </dd>
                  <dt className="text-ink-400">Parser</dt>
                  <dd>
                    {selected.forensic?.parser || "—"}
                    {selected.forensic?.parser_version
                      ? `@${selected.forensic.parser_version}`
                      : ""}
                  </dd>
                  <dt className="text-ink-400">Recovery</dt>
                  <dd>{selected.forensic?.recovery_source || "—"}</dd>
                  <dt className="text-ink-400">Confidence</dt>
                  <dd>
                    {selected.forensic?.confidence?.label || "—"}
                    {typeof selected.forensic?.confidence?.score === "number"
                      ? ` (${selected.forensic.confidence.score.toFixed(2)})`
                      : ""}
                  </dd>
                  <dt className="text-ink-400">Examiner</dt>
                  <dd>{selected.examiner_status || selected.forensic?.examiner_status || "—"}</dd>
                </dl>
                <pre className="max-h-40 overflow-auto rounded bg-white p-2 font-mono text-[10px] text-ink-600">
                  {JSON.stringify(selected.data || {}, null, 2)}
                </pre>
                {(selected.state || "") !== "allocated" ? (
                  <div className="flex gap-2">
                    <Button variant="brand" className="h-8 text-xs" onClick={() => void review("accepted")}>
                      Accept
                    </Button>
                    <Button variant="outline" className="h-8 text-xs" onClick={() => void review("rejected")}>
                      Reject
                    </Button>
                  </div>
                ) : null}
              </div>
            ) : (
              <p className="text-ink-500">Select an artifact to inspect provenance.</p>
            )}
          </div>
        </div>
      )}

      {timeline.length > 0 ? (
        <div>
          <p className="mb-1 text-xs font-semibold text-ink-700">Timeline (sample)</p>
          <ul className="max-h-40 space-y-1 overflow-y-auto rounded-md border border-ink-100 p-2 text-[11px]">
            {timeline.map((e) => (
              <li key={e.artifact_id} className="flex gap-2 text-ink-600">
                <span className="w-36 shrink-0 font-mono text-ink-400">
                  {e.timestamp_utc ? String(e.timestamp_utc).slice(0, 19) : "—"}
                </span>
                <Badge tone="neutral">{e.ui_label || e.state}</Badge>
                <span className="font-medium">{e.artifact_type}</span>
                <span className="truncate text-ink-400">{e.source_domain}</span>
              </li>
            ))}
          </ul>
        </div>
      ) : null}
      </>
      )}
    </div>
  );
}
