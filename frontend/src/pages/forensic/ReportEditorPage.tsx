import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, CheckCircle, Download, Play, Radio, RotateCcw, Settings } from "lucide-react";
import clsx from "clsx";
import { Badge, Button, Card, PageHeader, Spinner } from "../../components/ui";
import { ReportGenerationTimer } from "../../components/forensic/ReportGenerationTimer";
import {
  countPreviewPages,
  orderReportSections,
  ReportSectionPagesWithActions,
} from "../../components/forensic/ReportDocumentPreview";
import { forensicApi } from "../../lib/forensicApi";
import { streamReportGeneration } from "../../lib/reportSse";
import { useToast } from "../../lib/toast";
import type { Intake, ReportGate, ReportSection, ReportStreamEvent } from "../../lib/types/forensic";

const MISSING_LABEL: Record<string, string> = {
  subjects: "subject (name + email)",
  case_type: "case type",
  report_type: "report type",
  objectives: "at least one objective",
};

const STATUS_TONE: Record<string, "neutral" | "green" | "amber" | "red" | "indigo"> = {
  pending: "amber",
  approved: "green",
  verified: "green",
  rejected: "red",
  needs_review: "amber",
};

export function ReportEditorPage() {
  const { jobId } = useParams<{ jobId: string }>();
  const toast = useToast();
  const abortRef = useRef<AbortController | null>(null);
  const lastSectionRefresh = useRef<number>(0);

  const [sections, setSections] = useState<ReportSection[]>([]);
  const [loading, setLoading] = useState(true);
  const [streaming, setStreaming] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [streamProgress, setStreamProgress] = useState<{
    stage?: string;
    pct?: number;
    pipelineStage?: string;
    primaryModel?: string;
    reviewModel?: string;
    confidenceGrade?: string;
  }>({});
  const [elapsedMs, setElapsedMs] = useState(0);
  const [finalDurationMs, setFinalDurationMs] = useState<number | null>(null);
  const streamStartedAt = useRef<number | null>(null);
  const [activity, setActivity] = useState<string[]>([]);
  const [exportingPdf, setExportingPdf] = useState(false);

  const [intake, setIntake] = useState<Intake | null>(null);
  const [gate, setGate] = useState<ReportGate | null>(null);

  const loadGate = useCallback(async () => {
    if (!jobId) return;
    try {
      setGate(await forensicApi.reportGate(jobId));
    } catch {
      setGate(null);
    }
  }, [jobId]);

  function onSectionUpdated(updated: ReportSection) {
    setSections((prev) =>
      prev.map((s) =>
        s.section_key === updated.section_key || s.id === updated.id ? { ...s, ...updated } : s,
      ),
    );
    loadGate();
  }

  const loadSections = useCallback(async (opts?: { silent?: boolean }) => {
    if (!jobId) return;
    const silent = Boolean(opts?.silent);
    if (!silent) setLoading(true);
    try {
      const s = await forensicApi.listReportSections(jobId);
      setSections(s);
    } catch {
      if (!silent) setSections([]);
    } finally {
      if (!silent) setLoading(false);
    }
  }, [jobId]);

  const loadIntake = useCallback(async () => {
    if (!jobId) return;
    try {
      setIntake(await forensicApi.getIntake(jobId));
    } catch {
      setIntake(null);
    }
  }, [jobId]);

  useEffect(() => {
    if (!streaming) return;
    streamStartedAt.current = streamStartedAt.current ?? Date.now();
    const id = window.setInterval(() => {
      if (streamStartedAt.current) setElapsedMs(Date.now() - streamStartedAt.current);
    }, 1000);
    return () => window.clearInterval(id);
  }, [streaming]);

  useEffect(() => {
    loadSections();
    loadIntake();
    loadGate();
  }, [loadSections, loadIntake, loadGate]);

  useEffect(() => {
    return () => abortRef.current?.abort();
  }, []);

  /** Fallback when SSE drops before the done event — poll report run status from DB. */
  useEffect(() => {
    if (!streaming || !jobId) return;
    let cancelled = false;
    const poll = async () => {
      try {
        const st = await forensicApi.getReportStatus(jobId);
        if (cancelled) return;
        if (st.status === "completed") {
          setStreamProgress({
            stage: "complete",
            pct: 100,
            pipelineStage: "complete",
          });
          setStreaming(false);
          if (typeof st.duration_ms === "number") setFinalDurationMs(st.duration_ms);
          toast.success("Report generation complete");
          loadSections({ silent: true });
          loadGate();
          abortRef.current?.abort();
        } else if (st.status === "failed") {
          setStreaming(false);
          toast.error(st.error || "Report generation failed");
          loadSections({ silent: true });
          loadGate();
          abortRef.current?.abort();
        } else if (st.sections_total > 0) {
          const pct = Math.min(100, Math.round((st.sections_completed / st.sections_total) * 100));
          setStreamProgress((prev) => ({
            ...prev,
            pct: Math.max(prev.pct ?? 0, pct),
            stage: `Section ${st.sections_completed}/${st.sections_total}`,
            pipelineStage: "running",
          }));
        }
      } catch {
        /* ignore transient poll errors */
      }
    };
    void poll();
    const id = window.setInterval(poll, 4000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [streaming, jobId, loadGate, loadSections, toast]);

  const reportReady = intake?.report_ready ?? false;
  const missing = intake?.missing_fields ?? [];

  async function startGeneration(recreate = false) {
    if (!jobId) return;
    if (!reportReady) {
      toast.error(
        "Complete case intake before generating the report — missing: " +
          missing.map((m) => MISSING_LABEL[m] ?? m).join(", "),
      );
      return;
    }
    if (recreate) {
      const ok = window.confirm(
        "The Report Generator Agent will rebuild the entire report from scratch: every selected objective, A4 letterhead on each page, and tables that never split a row. Continue?",
      );
      if (!ok) return;
    }
    setGenerating(true);
    try {
      const res = await forensicApi.startReport(jobId, recreate ? { recreate: true } : {});
      if (res.status === "already_generating") {
        toast.info(res.message ?? "Report generation already in progress");
      } else {
        toast.success(recreate ? "Recreating the report from the beginning" : "Report generation started");
      }
      if (recreate) {
        setSections([]);
        setGate(null);
      }
      startStream();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Start failed");
    } finally {
      setGenerating(false);
    }
  }

  function startStream() {
    if (!jobId) return;
    abortRef.current?.abort();
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    setStreaming(true);
    setStreamProgress({});
    setActivity([]);
    streamStartedAt.current = Date.now();
    setElapsedMs(0);
    setFinalDurationMs(null);
    streamReportGeneration({
      jobId,
      signal: ctrl.signal,
      onEvent: (evt: ReportStreamEvent) => {
        if (evt.event === "progress") {
          const stage = (evt.data.stage as string) ?? "";
          const pct = evt.data.progress_pct as number;
          setStreamProgress((prev) => ({
            stage,
            pct: Math.max(prev.pct ?? 0, Number.isFinite(pct) ? pct : 0),
            pipelineStage: (evt.data.pipeline_stage as string) ?? prev.pipelineStage,
            primaryModel: (evt.data.primary_model as string) ?? prev.primaryModel,
            reviewModel: (evt.data.review_model as string) ?? prev.reviewModel,
            confidenceGrade: (evt.data.confidence_grade as string) ?? prev.confidenceGrade,
          }));
          if (stage) {
            setActivity((prev) => {
              if (prev.length > 0 && prev[prev.length - 1] === stage) return prev;
              const next = [...prev, stage];
              return next.length > 200 ? next.slice(-200) : next;
            });
          }
          const now = Date.now();
          if (now - lastSectionRefresh.current > 2500) {
            lastSectionRefresh.current = now;
            loadSections({ silent: true });
          }
        }
        if (evt.event === "error") {
          const msg = (evt.data.message as string) || "Report generation failed";
          setStreamProgress({ stage: "failed", pct: 0 });
          setStreaming(false);
          toast.error(msg);
          loadSections({ silent: true });
          loadGate();
        }
        if (evt.event === "done") {
          setStreamProgress({ stage: "complete", pct: 100 });
          setStreaming(false);
          const dur = evt.data.duration_ms as number | undefined;
          if (typeof dur === "number") setFinalDurationMs(dur);
          toast.success("Report stream complete");
          loadSections({ silent: true });
          loadGate();
        }
      },
      onError: (err) => {
        setStreaming(false);
        toast.error(err.message);
      },
    });
  }

  async function approveAll() {
    if (!jobId) return;
    try {
      const updated = await forensicApi.approveReport(jobId);
      setSections(updated);
      loadGate();
      toast.success("Report approved");
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Approve failed");
    }
  }

  async function exportReport(fmt: "pdf" | "docx" | "json" | "package") {
    if (!jobId) return;
    if (fmt !== "pdf" && fmt !== "docx" && gate && !gate.cleared) {
      toast.error("Export is blocked by Human-in-the-Loop review — approve all sections first.");
      return;
    }
    try {
      if (fmt === "pdf") {
        setExportingPdf(true);
        try {
          const result = await forensicApi.exportReport(jobId, { format: "pdf" });
          await forensicApi.downloadReportExport(result.id);
          toast.success("PDF downloaded.");
          return;
        } finally {
          setExportingPdf(false);
        }
      }
      const result = await forensicApi.exportReport(jobId, { format: fmt });
      await forensicApi.downloadReportExport(result.id);
      toast.success(`${fmt.toUpperCase()} export downloaded — see Report list in the menu for all exports.`);
    } catch (e: unknown) {
      setExportingPdf(false);
      toast.error(e instanceof Error ? e.message : "Export failed");
    }
  }

  const orderedSections = orderReportSections(sections);
  let pageCursor = 1;
  const sectionsWithPages = orderedSections.map((section) => {
    const pageStart = pageCursor;
    pageCursor += countPreviewPages(section);
    return { section, pageStart };
  });

  return (
    <div>
      <PageHeader
        title="Report editor"
        subtitle="Report Evidence & Content Agent builds the forensic findings. Report Formation Agent then packs the exact saved UI content into A4 pages and creates matching PDF/DOCX without rewriting it."
        actions={
          <div className="flex flex-wrap gap-2">
            <Link to="/forensic/reports">
              <Button variant="outline">Report list</Button>
            </Link>
            <Link to={`/forensic/jobs/${jobId}`}>
              <Button variant="ghost">
                <ArrowLeft className="h-4 w-4" /> Back
              </Button>
            </Link>
            {sections.length > 0 ? (
              <Button
                variant="brand"
                onClick={() => startGeneration(true)}
                disabled={generating || streaming || !reportReady}
              >
                <RotateCcw className={clsx("h-4 w-4", generating && "animate-spin")} />
                {generating ? "Recreating…" : "Recreate report"}
              </Button>
            ) : (
              <Button variant="outline" onClick={() => startGeneration(false)} disabled={generating || !reportReady}>
                <Play className="h-4 w-4" /> {generating ? "Starting…" : "Generate report"}
              </Button>
            )}
            <Button variant="brand" onClick={startStream} disabled={streaming}>
              <Radio className={clsx("h-4 w-4", streaming && "animate-pulse")} />
              {streaming ? "Streaming…" : "Live stream"}
            </Button>
            <Button variant="outline" onClick={approveAll}>
              <CheckCircle className="h-4 w-4" /> Approve all
            </Button>
            <Button variant="outline" onClick={() => exportReport("pdf")} disabled={exportingPdf}>
              <Download className="h-4 w-4" /> {exportingPdf ? "Preparing PDF…" : "Download PDF"}
            </Button>
            <Button variant="outline" onClick={() => exportReport("docx")} disabled={exportingPdf}>
              <Download className="h-4 w-4" /> Download DOCX
            </Button>
            <Button variant="outline" onClick={() => exportReport("package")} disabled={!!gate && !gate.cleared}>
              <Download className="h-4 w-4" /> Defensibility pack
            </Button>
          </div>
        }
      />

      {reportReady ? (
        <Card className="mb-6 flex items-center justify-between border-green-200 bg-green-50/50 p-4">
          <p className="text-sm text-green-800">
            Report configuration is set in Case intake
            {intake?.report_type ? ` (${intake.report_type})` : ""}
            {intake?.objective_ids ? ` — ${intake.objective_ids.length} objective(s)` : ""}. Ready to generate.
          </p>
          <Link to={`/forensic/jobs/${jobId}/intake`}>
            <Button variant="outline">
              <Settings className="h-4 w-4" /> Edit configuration
            </Button>
          </Link>
        </Card>
      ) : (
        <Card className="mb-6 flex items-center justify-between border-amber-200 bg-amber-50/50 p-4">
          <p className="text-sm text-amber-800">
            Generate is disabled until Case intake is complete. Missing:{" "}
            {missing.length > 0 ? missing.map((m) => MISSING_LABEL[m] ?? m).join(", ") : "open intake to configure"}.
          </p>
          <Link to={`/forensic/jobs/${jobId}/intake`}>
            <Button variant="brand">
              <Settings className="h-4 w-4" /> Complete intake
            </Button>
          </Link>
        </Card>
      )}

      <ReportGenerationTimer
        streaming={streaming}
        elapsedMs={elapsedMs}
        finalDurationMs={finalDurationMs}
        progressPct={streamProgress.pct ?? 0}
        stage={streamProgress.stage}
        pipelineStage={streamProgress.pipelineStage}
        primaryModel={streamProgress.primaryModel}
        reviewModel={streamProgress.reviewModel}
        confidenceGrade={streamProgress.confidenceGrade}
        activityLines={activity}
      />

      {!loading && sections.length > 0 && gate && (
        gate.cleared ? (
          <Card className="mb-4 border-green-200 bg-green-50/50 p-3 text-sm text-green-800">
            Human-in-the-Loop review complete — all sections approved. The report can be exported.
          </Card>
        ) : (
          <Card className="mb-4 border-amber-200 bg-amber-50/50 p-3 text-sm text-amber-800">
            Export is gated by Human-in-the-Loop review.
            {gate.run_status === "running" && (
              <> Report generating ({gate.sections_completed ?? 0}/{gate.sections_total ?? 14} sections).</>
            )}
            {gate.run_status === "completed" && (gate.sections_completed ?? 0) >= (gate.sections_total ?? 14) && (
              <> Report draft ready ({gate.sections_completed ?? 0}/{gate.sections_total ?? 14} sections).</>
            )}
            {gate.pending.length > 0 && <> Pending approval: {gate.pending.join(", ")}.</>}
            {gate.needs_review.length > 0 && <> Needs review: {gate.needs_review.join(", ")}.</>}
            {gate.missing_required.length > 0 && gate.run_status !== "running" && (
              <> Missing sections: {gate.missing_required.join(", ")}.</>
            )}
            {" "}Approve each section below (or use Approve all) to unblock export.
          </Card>
        )
      )}

      {loading ? (
        <Spinner />
      ) : sections.length === 0 ? (
        <Card className="p-8 text-center">
          <p className="text-sm text-ink-500">
            No report sections yet. Complete Case intake, then click Generate report. After a draft exists, use Recreate report to wipe it and generate every section from the beginning.
          </p>
        </Card>
      ) : (
        <div className="space-y-3">
          {sectionsWithPages.map(({ section, pageStart }) => (
            <Card key={section.id} className="p-5">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <h3 className="font-bold capitalize text-ink-900">{section.section_key.replace(/_/g, " ")}</h3>
                  <div className="mt-1 flex flex-wrap gap-2">
                    <Badge tone={STATUS_TONE[section.verification_status] ?? "neutral"}>
                      {section.verification_status}
                    </Badge>
                    {section.section_confidence != null && (
                      <Badge tone="indigo">{Math.round(section.section_confidence * 100)}% confidence</Badge>
                    )}
                    {section.conflicts && section.conflicts.length > 0 && (
                      <Badge tone="amber">{section.conflicts.length} validation conflict(s)</Badge>
                    )}
                  </div>
                </div>
              </div>
              {section.narrative_content || section.structured_json ? (
                <div className="mt-4 flex flex-col items-center rounded-xl bg-slate-100 p-4">
                  <ReportSectionPagesWithActions
                    section={section}
                    pageStart={pageStart}
                    jobId={jobId!}
                    allSections={sections}
                    onUpdated={onSectionUpdated}
                  />
                </div>
              ) : (
                <p className="mt-4 text-sm italic text-ink-400">No narrative content yet.</p>
              )}
              {section.citations && section.citations.length > 0 && (
                <p className="mt-3 text-xs text-ink-400">{section.citations.length} citation(s)</p>
              )}
            </Card>
          ))}
        </div>
      )}
    </div>
  );
}
