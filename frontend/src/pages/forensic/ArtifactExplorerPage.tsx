import { PriorityEvidencePanel } from "../../components/forensic/PriorityEvidencePanel";
import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { useVirtualizer } from "@tanstack/react-virtual";
import { ArrowLeft, ArrowRight, Download, ExternalLink, FileSpreadsheet, Search, ShieldAlert, Tag } from "lucide-react";
import clsx from "clsx";
import { Badge, Button, Card, Field, Input, PageHeader, Spinner } from "../../components/ui";
import { ArtifactCategoryTree } from "../../components/forensic/ArtifactCategoryTree";
import { ArtifactGraphPanel } from "../../components/forensic/ArtifactGraphPanel";
import { ArtifactPreviewPanel } from "../../components/forensic/ArtifactPreviewPanel";
import { stripAxiomBranding } from "../../lib/displayText";
import { forensicApi } from "../../lib/forensicApi";
import { useToast } from "../../lib/toast";
import type { Artifact, ArtifactReviewSummary, CategoryTree } from "../../lib/types/forensic";

const PAGE_SIZE = 20;

export function ArtifactExplorerPage() {
  const { jobId } = useParams<{ jobId: string }>();
  const toast = useToast();
  const parentRef = useRef<HTMLDivElement>(null);

  const [tree, setTree] = useState<CategoryTree | null>(null);
  const [artifacts, setArtifacts] = useState<Artifact[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [loadingMore, setLoadingMore] = useState(false);
  const [selected, setSelected] = useState<{ category: string | null; subCategory: string | null }>({
    category: null,
    subCategory: null,
  });
  const [detail, setDetail] = useState<Artifact | null>(null);
  const [search, setSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [comment, setComment] = useState("");
  const [jobStatus, setJobStatus] = useState<string | null>(null);
  const [exporting, setExporting] = useState(false);
  const [reviewSummary, setReviewSummary] = useState<ArtifactReviewSummary | null>(null);

  const loadTree = useCallback(async () => {
    if (!jobId) return;
    try {
      const t = await forensicApi.getArtifactCategories(jobId);
      setTree(t);
    } catch {
      /* optional */
    }
  }, [jobId]);

  const loadReviewSummary = useCallback(async () => {
    if (!jobId) return;
    try {
      setReviewSummary(await forensicApi.getArtifactReviewSummary(jobId, 80));
    } catch {
      setReviewSummary(null);
    }
  }, [jobId]);

  const loadJobStatus = useCallback(async () => {
    if (!jobId) return;
    try {
      const job = await forensicApi.getJob(jobId);
      setJobStatus(job.status);
    } catch {
      setJobStatus(null);
    }
  }, [jobId]);

  const loadArtifacts = useCallback(async (opts?: { silent?: boolean; page?: number; append?: boolean }) => {
    if (!jobId) return;
    const pageToLoad = opts?.page ?? 1;
    const append = Boolean(opts?.append);
    if (!opts?.silent && !append) setLoading(true);
    if (append) setLoadingMore(true);
    try {
      const res = await forensicApi.listArtifacts(jobId, {
        page: pageToLoad,
        page_size: PAGE_SIZE,
        category: selected.category ?? undefined,
        sub_category: selected.subCategory ?? undefined,
        q: search || undefined,
      });
      setTotal(res.total);
      setPage(pageToLoad);
      setArtifacts((prev) => {
        if (!append) return res.items;
        const seen = new Set(prev.map((row) => row.id));
        return [...prev, ...res.items.filter((row) => !seen.has(row.id))];
      });
      setDetail((prev) => prev ?? res.items[0] ?? null);
    } catch (e: unknown) {
      if (!opts?.silent) {
        toast.error(e instanceof Error ? e.message : "Failed to load artifacts");
      }
    } finally {
      if (!opts?.silent) setLoading(false);
      setLoadingMore(false);
    }
  }, [jobId, selected, search, toast]);

  useEffect(() => {
    loadTree();
    loadJobStatus();
    loadReviewSummary();
  }, [loadTree, loadJobStatus, loadReviewSummary]);

  const ragInProgress =
    jobStatus === "processing" || jobStatus === "extracting";

  useEffect(() => {
    if (!jobId || !ragInProgress) return;
    const timer = window.setInterval(() => {
      loadTree();
      loadArtifacts({ silent: true });
      loadJobStatus();
    }, 5000);
    return () => window.clearInterval(timer);
  }, [jobId, ragInProgress, loadTree, loadArtifacts, loadJobStatus]);

  useEffect(() => {
    setDetail(null);
    setPage(1);
    setArtifacts([]);
  }, [selected, search]);

  useEffect(() => {
    loadArtifacts({ page: 1 });
  }, [loadArtifacts]);

  const virtualizer = useVirtualizer({
    count: artifacts.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 44,
    overscan: 8,
  });
  const virtualItems = virtualizer.getVirtualItems();
  const lastVirtual = virtualItems.length ? virtualItems[virtualItems.length - 1].index : 0;

  useEffect(() => {
    if (loading || loadingMore) return;
    if (artifacts.length === 0 || artifacts.length >= total) return;
    if (lastVirtual >= artifacts.length - 4) {
      void loadArtifacts({ page: page + 1, append: true, silent: true });
    }
  }, [lastVirtual, artifacts.length, total, page, loading, loadingMore, loadArtifacts]);

  async function selectArtifact(a: Artifact) {
    setDetail(a);
    setComment(a.examiner_comment ?? "");
    if (!jobId) return;
    try {
      const full = await forensicApi.getArtifact(jobId, a.id);
      setDetail(full);
      setComment(full.examiner_comment ?? "");
    } catch {
      /* use list item */
    }
  }

  async function saveComment() {
    if (!jobId || !detail) return;
    try {
      const updated = await forensicApi.updateArtifact(jobId, detail.id, {
        examiner_comment: comment,
      });
      setDetail(updated);
      toast.success("Comment saved");
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Save failed");
    }
  }

  async function exportArtifacts() {
    if (!jobId) return;
    setExporting(true);
    try {
      await forensicApi.downloadArtifactsExport(jobId, {
        q: search || undefined,
        category: selected.category ?? undefined,
      });
      toast.success("Artifacts exported to Excel");
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Export failed");
    } finally {
      setExporting(false);
    }
  }

  return (
    <div>
      <PageHeader
        title="Disk Artifacts"
        subtitle={
          tree
            ? `${tree.total.toLocaleString()} artifact(s) available${
                tree.pending_chunk ? ` · ${tree.pending_chunk.toLocaleString()} chunking…` : ""
              }${tree.platform ? ` · ${tree.platform}` : ""}`
            : "Browse actual extracted evidence files — email, documents, media, shortcuts, logs, chats and carved evidence."
        }
        actions={
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" disabled={exporting || loading} onClick={() => void exportArtifacts()}>
              <FileSpreadsheet className="h-4 w-4" />
              {exporting ? "Exporting…" : "Export Excel"}
            </Button>
            <Button
              variant="outline"
              onClick={() => {
                if (!jobId) return;
                forensicApi.downloadSuspiciousLog(jobId, "csv").catch((e: unknown) => {
                  toast.error(e instanceof Error ? e.message : "Could not download review log");
                });
              }}
            >
              <ShieldAlert className="h-4 w-4" /> Review log CSV
            </Button>
            <Link to={`/forensic/jobs/${jobId}`}>
              <Button variant="ghost">
                <ArrowLeft className="h-4 w-4" /> Processing
              </Button>
            </Link>
            <Link to={`/forensic/jobs/${jobId}/intake`}>
              <Button variant="brand">Continue to Intake <ArrowRight className="h-4 w-4" /></Button>
            </Link>
          </div>
        }
      />

      {jobId && <PriorityEvidencePanel jobId={jobId} />}

      {reviewSummary ? (
        <Card className="mb-4 border-amber-200 bg-amber-50/40 p-4">
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div>
              <p className="flex items-center gap-2 font-semibold text-amber-900"><ShieldAlert className="h-4 w-4" /> Examiner review signals</p>
              <p className="mt-1 text-xs text-amber-800">
                {reviewSummary.limited ? "At least " : ""}{reviewSummary.flagged_total.toLocaleString()} of {reviewSummary.total_artifacts.toLocaleString()} files have deterministic review signals · High {reviewSummary.by_severity.high || 0} · Medium {reviewSummary.by_severity.medium || 0} · Low {reviewSummary.by_severity.low || 0}.
              </p>
              <p className="mt-1 text-[10px] text-amber-700">{reviewSummary.disclaimer}</p>
            </div>
            <Button variant="outline" className="h-8 text-xs" onClick={() => void loadReviewSummary()}>Refresh signals</Button>
          </div>
        </Card>
      ) : null}

      <div className="grid h-[calc(100vh-300px)] min-h-[480px] grid-cols-12 gap-4">
        <Card className="col-span-12 overflow-hidden lg:col-span-3">
          {tree ? (
            <ArtifactCategoryTree
              jobId={jobId}
              categories={tree.categories}
              total={tree.total}
              selected={selected}
              onSelect={(category, subCategory) => {
                setSelected({ category, subCategory });
                setDetail(null);
              }}
            />
          ) : (
            <Spinner />
          )}
        </Card>

        <Card className="col-span-12 flex flex-col overflow-hidden lg:col-span-5">
          <div className="border-b border-ink-100 p-3">
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-400" />
              <Input
                className="pl-9"
                placeholder="Search artifacts…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
            <p className="mt-2 text-xs text-ink-400">
              {total.toLocaleString()} matching
              {tree && selected.category == null && selected.subCategory == null
                ? ` of ${tree.total.toLocaleString()} total`
                : ""}
            </p>
          </div>
          {loading ? (
            <Spinner />
          ) : artifacts.length === 0 ? (
            <p className="py-16 text-center text-sm text-ink-400">No artifacts found.</p>
          ) : (
            <div ref={parentRef} className="flex-1 overflow-y-auto">
              <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
                {virtualizer.getVirtualItems().map((row) => {
                  const a = artifacts[row.index];
                  const active = detail?.id === a.id;
                  return (
                    <button
                      key={a.id}
                      onClick={() => selectArtifact(a)}
                      className={clsx(
                        "absolute left-0 top-0 flex w-full items-center gap-2 border-b border-ink-50 px-4 py-2.5 text-left text-sm transition",
                        active ? "bg-brand-50" : "hover:bg-ink-50"
                      )}
                      style={{ height: row.size, transform: `translateY(${row.start}px)` }}
                    >
                      <span className="min-w-0 flex-1">
                        <span className="block truncate font-medium text-ink-800">
                          {a.title || a.artifact_type}
                        </span>
                        {a.artifact_datetime && (
                          <span className="text-xs text-amber-700">
                            Deleted {new Date(a.artifact_datetime).toLocaleString()}
                          </span>
                        )}
                      </span>
                      {a.tags?.includes("deleted") || a.metadata?.is_deleted ? (
                        <Badge tone="amber">deleted</Badge>
                      ) : (
                        <Badge tone="neutral">
                          {stripAxiomBranding(a.axiom_sub_category || a.axiom_category)}
                        </Badge>
                      )}
                      {(a.metadata?.review as { flagged?: boolean; severity?: string } | undefined)?.flagged ? (
                        <Badge tone={(a.metadata?.review as { severity?: string }).severity === "high" ? "red" : "amber"}>review</Badge>
                      ) : null}
                    </button>
                  );
                })}
              </div>
            </div>
          )}
        </Card>

        <Card className="col-span-12 overflow-y-auto lg:col-span-4">
          {!detail ? (
            <p className="py-16 text-center text-sm text-ink-400">Select an artifact to view details.</p>
          ) : (
            <div className="p-5">
              <div className="flex items-start justify-between gap-2">
                <h3 className="text-lg font-bold text-ink-900">{detail.title || detail.artifact_type}</h3>
                {jobId && (
                  <div className="flex shrink-0 flex-col items-end gap-1">
                    {detail.storage_uri && (
                      <Button
                        variant="ghost"
                        className="gap-1 text-xs"
                        onClick={() => forensicApi.openArtifactContent(jobId, detail.id).catch((e) => toast.error(e instanceof Error ? e.message : "Open failed"))}
                      >
                        <ExternalLink className="h-3.5 w-3.5" /> Open file
                      </Button>
                    )}
                    <Button
                      variant="ghost"
                      className="gap-1 text-xs"
                      onClick={() =>
                        forensicApi
                          .downloadArtifactContent(jobId, detail.id, detail.file_name || detail.title || undefined)
                          .catch((e) => toast.error(e instanceof Error ? e.message : "Download failed"))
                      }
                    >
                      <Download className="h-3.5 w-3.5" /> Download
                      {detail.size_bytes != null ? ` (${detail.size_bytes.toLocaleString()} B)` : ""}
                    </Button>
                  </div>
                )}
              </div>
              <div className="mt-2 flex flex-wrap gap-2">
                <Badge tone="indigo">{detail.artifact_type}</Badge>
                {detail.confidence != null && (
                  <Badge tone="green">{Math.round(detail.confidence * 100)}% conf.</Badge>
                )}
              </div>
              <dl className="mt-4 space-y-3 text-sm">
                <div>
                  <dt className="text-xs font-semibold uppercase text-ink-400">Category</dt>
                  <dd className="text-ink-700">
                    {stripAxiomBranding(detail.axiom_category)}
                    {detail.axiom_sub_category && ` › ${stripAxiomBranding(detail.axiom_sub_category)}`}
                  </dd>
                </div>
                {detail.source_path && (
                  <div>
                    <dt className="text-xs font-semibold uppercase text-ink-400">Source path</dt>
                    <dd className="break-all font-mono text-xs text-ink-600">{detail.source_path}</dd>
                  </div>
                )}
                {detail.artifact_datetime && (
                  <div>
                    <dt className="text-xs font-semibold uppercase text-ink-400">Timestamp</dt>
                    <dd className="text-ink-700">{new Date(detail.artifact_datetime).toLocaleString()}</dd>
                  </div>
                )}
                {(detail.metadata?.device_name as string | undefined) && (
                  <div>
                    <dt className="text-xs font-semibold uppercase text-ink-400">Device</dt>
                    <dd className="text-ink-700">{String(detail.metadata?.device_name)}</dd>
                  </div>
                )}
                {detail.tags && detail.tags.length > 0 && (
                  <div>
                    <dt className="flex items-center gap-1 text-xs font-semibold uppercase text-ink-400">
                      <Tag className="h-3 w-3" /> Tags
                    </dt>
                    <dd className="mt-1 flex flex-wrap gap-1">
                      {detail.tags.map((t) => (
                        <Badge key={t} tone="neutral">
                          {t}
                        </Badge>
                      ))}
                    </dd>
                  </div>
                )}
              </dl>
              {jobId && <ArtifactPreviewPanel jobId={jobId} artifact={detail} />}
              {jobId && <ArtifactGraphPanel jobId={jobId} artifact={detail} />}

              <div className="mt-4">
                <Field label="Examiner comment">
                  <textarea
                    className="input min-h-[100px] resize-y"
                    value={comment}
                    onChange={(e) => setComment(e.target.value)}
                  />
                </Field>
                <Button variant="brand" className="mt-2" onClick={saveComment}>
                  Save comment
                </Button>
              </div>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
