import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useLocation, useNavigate, useParams } from "react-router-dom";
import { FileUp, ListChecks, Play, RefreshCw, Square, Trash2 } from "lucide-react";
import { Badge, Button, Card, PageHeader } from "../../components/ui";
import { HostEvidencePanel, type HostEvidencePanelHandle } from "../../components/forensic/HostEvidencePanel";
import { AgentPipelineBanner } from "../../components/forensic/AgentPipelineBanner";
import { JobActivityPanel } from "../../components/forensic/JobActivityPanel";
import { JobInventoryButton } from "../../components/forensic/JobInventoryDialog";
import { ProgressAgentPanel } from "../../components/forensic/ProgressAgentPanel";
import { RagQaPanel } from "../../components/forensic/RagQaPanel";
import { forensicApi } from "../../lib/forensicApi";
import { useAuth } from "../../lib/auth";
import { mobilePlatformService, mobileUiBasePath } from "../../lib/serviceMode";
import type { ApiService } from "../../lib/api";
import type { Job } from "../../lib/types/forensic";
import { useToast } from "../../lib/toast";

const PIPELINE_STARTED = new Set([
  "processing",
  "building_disk",
  "disk_ready",
  "extracting",
  "extracted",
  "artifacts_registered",
  "parsing",
  "parsed",
  "classifying",
  "classified",
  "ocr",
  "ocring",
  "indexing",
  "indexed",
  "ready",
  "report_ready",
  "report_generating",
  "reporting",
  "completed",
  "paused",
]);

const ACTIVE_POLL = new Set([
  "processing",
  "building_disk",
  "disk_ready",
  "extracting",
  "extracted",
  "parsing",
  "parsed",
  "classifying",
  "classified",
  "ocr",
  "ocring",
  "indexing",
  "indexed",
]);

function needsFolderImport(job: Job): boolean {
  const status = String(job.status || "").toLowerCase();
  const evidence = Number(job.evidence_count ?? job.files_total ?? 0);
  const progress = Number(job.progress_pct ?? 0);
  if (evidence > 0 || progress > 0) return false;
  return !PIPELINE_STARTED.has(status);
}

export function MobileCompactJobPage() {
  const { jobId = "" } = useParams();
  const location = useLocation();
  const navigate = useNavigate();
  const toast = useToast();
  const { hasPermission } = useAuth();
  const canRun = hasPermission("job:run");
  const platform = mobilePlatformService() ?? "android";
  const service = `mobile-${platform}` as ApiService;
  const label = platform === "ios" ? "iOS" : "Android";
  const base = mobileUiBasePath(platform);
  const [job, setJob] = useState<Job | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [deleting, setDeleting] = useState(false);
  const [stopping, setStopping] = useState(false);
  const [logPanelHeight, setLogPanelHeight] = useState<number | undefined>();
  const evidencePanelRef = useRef<HostEvidencePanelHandle>(null);
  const pipelinePanelRef = useRef<HTMLDivElement>(null);

  const load = useCallback(
    async (silent = false) => {
      try {
        setJob(await forensicApi.getJob(jobId, { service }));
      } catch (e) {
        if (!silent) toast.error(e instanceof Error ? e.message : "Job load failed");
      } finally {
        setLoading(false);
      }
    },
    [jobId, service, toast],
  );

  useEffect(() => {
    void load(false);
    const t = window.setInterval(() => void load(true), 5000);
    return () => window.clearInterval(t);
  }, [load]);

  useEffect(() => {
    if (!(location.state as { autoImport?: boolean } | null)?.autoImport) return;
    const timer = window.setTimeout(() => evidencePanelRef.current?.openEvidenceFolder(), 200);
    return () => window.clearTimeout(timer);
  }, [location.state, jobId]);

  useEffect(() => {
    const el = pipelinePanelRef.current;
    if (!el) {
      setLogPanelHeight(undefined);
      return;
    }
    const syncHeight = () => setLogPanelHeight(Math.max(el.offsetHeight, 320));
    syncHeight();
    const ro = new ResizeObserver(syncHeight);
    ro.observe(el);
    return () => ro.disconnect();
  }, [job?.id, job?.status, job?.progress_pct, job?.pipeline_progress]);

  async function act(fn: () => Promise<unknown>, ok: string) {
    setBusy(true);
    try {
      await fn();
      toast.success(ok);
      await load(true);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Operation failed");
    } finally {
      setBusy(false);
    }
  }

  async function hardDeleteJob() {
    if (!jobId || deleting) return;
    const ok = window.confirm(
      `Permanently delete ${label} job ${jobId}?\n\n` +
        `Removes job metadata, RAG index, staging copies and database rows.\n` +
        `Original mobile image files on the host evidence folder are NOT deleted.`,
    );
    if (!ok) return;
    setDeleting(true);
    try {
      await forensicApi.deleteJob(jobId, { service });
      toast.success("Job deleted — host image files preserved");
      navigate(`${base}/jobs`);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Could not delete job");
      setDeleting(false);
    }
  }

  async function runStop() {
    if (!jobId) return;
    setStopping(true);
    try {
      await forensicApi.stopJob(jobId);
      toast.success("Stop requested");
      setJob((prev) => (prev ? { ...prev, stop_requested: true } : prev));
      await load(true);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Stop failed");
    } finally {
      setStopping(false);
    }
  }

  if (loading && !job) return <Card className="p-6">Loading {label} job…</Card>;
  if (!job) return <Card className="p-6">Job unavailable in this {label} backend.</Card>;

  const showImport = needsFolderImport(job);
  const status = String(job.status || "").toLowerCase();
  const pollStopped = !ACTIVE_POLL.has(status);
  const isExtracting = status === "building_disk" || status === "processing" || status === "extracting";
  const isPipelineRunning =
    isExtracting ||
    ["indexing", "extracted", "disk_ready", "parsed", "artifacts_registered", "ocr", "ocring"].includes(status);
  const canStop = canRun && isPipelineRunning && !job.stop_requested && status !== "paused";
  const showResume = canRun && (status === "paused" || status === "failed");
  const showProcess = canRun && !showImport && !isExtracting && !["paused", "indexing", "indexed"].includes(status);

  return (
    <div>
      <PageHeader
        title={`${label} job ${job.id.slice(0, 8)}`}
        subtitle="Same processing layout as Disk RAG — pipeline stages, live logs, then RAG Q&A."
        actions={
          <div className="flex flex-wrap gap-2">
            <Button
              variant="outline"
              disabled={busy || deleting}
              onClick={() => evidencePanelRef.current?.openEvidenceFolder()}
            >
              <FileUp className="h-4 w-4" /> Select folder & start
            </Button>
            <Link to={`${base}/jobs/${jobId}/artifacts`}>
              <Button variant="outline">
                <ListChecks className="h-4 w-4" /> Artifacts
              </Button>
            </Link>
            {jobId ? <JobInventoryButton jobId={jobId} /> : null}
            {canRun ? (
              <>
                {canStop ? (
                  <Button variant="danger" loading={stopping} onClick={() => void runStop()}>
                    <Square className="h-4 w-4" /> Stop
                  </Button>
                ) : null}
                {showProcess ? (
                  <Button
                    variant="brand"
                    loading={busy}
                    onClick={() => void act(() => forensicApi.processJob(jobId), "Mobile pipeline started")}
                  >
                    <Play className="h-4 w-4" /> Process
                  </Button>
                ) : null}
                {showResume ? (
                  <Button
                    variant="outline"
                    loading={busy}
                    onClick={() => void act(() => forensicApi.resumeJob(jobId), "Mobile pipeline resumed")}
                  >
                    <RefreshCw className="h-4 w-4" /> Resume
                  </Button>
                ) : null}
                <Button variant="danger" loading={deleting} onClick={() => void hardDeleteJob()}>
                  <Trash2 className="h-4 w-4" /> Delete job
                </Button>
              </>
            ) : null}
          </div>
        }
      />

      <div className="mb-6 grid gap-4 sm:grid-cols-4">
        <Card className="p-4">
          <p className="text-xs font-semibold uppercase tracking-wider text-ink-400">Status</p>
          <div className="mt-2">
            <Badge tone={job.status === "failed" ? "red" : job.status === "completed" ? "green" : "indigo"}>
              {job.status}
            </Badge>
          </div>
        </Card>
        <Card className="p-4">
          <p className="text-xs font-semibold uppercase tracking-wider text-ink-400">Progress</p>
          <p className="mt-2 text-2xl font-bold text-ink-900">{job.progress_pct ?? 0}%</p>
        </Card>
        <Card className="p-4">
          <p className="text-xs font-semibold uppercase tracking-wider text-ink-400">Created</p>
          <p className="mt-2 text-sm text-ink-700">{new Date(job.created_at).toLocaleString()}</p>
        </Card>
        <Card className="p-4">
          <p className="text-xs font-semibold uppercase tracking-wider text-ink-400">Evidence</p>
          <p className="mt-2 text-sm font-semibold text-ink-800">{job.evidence_count ?? job.files_total ?? 0}</p>
        </Card>
      </div>

      {job.error ? <Card className="mb-4 border-red-200 p-4 text-sm text-red-700">{job.error}</Card> : null}

      <div className={showImport ? "mb-4" : "hidden"}>
        <Card className="p-5">
          <h3 className="mb-1 text-sm font-bold text-ink-800">Select the mobile image folder</h3>
          <p className="mb-4 text-xs text-ink-500">
            Use <strong>Select folder & start</strong>, then choose the drive (for example <strong>E:</strong>),
            open the case folder that contains <strong>.pas / .ufd / .ufdx / .zip</strong>, and click{" "}
            <strong>Use this directory</strong>. Original image files stay on that folder; delete job never removes them.
          </p>
          <HostEvidencePanel
            ref={evidencePanelRef}
            jobId={job.id}
            embedded
            autoProcess
            highlightStart
            lockedSourceType="mobile"
            initialSourceType="mobile"
            mobileOsLabel={label}
            allowLiveMobileAcquisition={true}
            onRegistered={() => void load(true)}
            onProcessingStarted={() => {
              setJob((prev) =>
                prev
                  ? { ...prev, status: "processing", progress_pct: Math.max(prev.progress_pct || 0, 1) }
                  : prev,
              );
              void load(true);
            }}
          />
        </Card>
      </div>

      {showImport ? (
        <Card className="mb-4 border-brand-200 bg-brand-50/60 p-4 text-xs text-brand-900">
          Extraction starts automatically after you select the mobile image folder. Process / Resume / Stop / Delete
          match Disk RAG once evidence is registered.
        </Card>
      ) : null}

      <div className="grid gap-6 lg:grid-cols-2 lg:items-start">
        <div ref={pipelinePanelRef} className="min-h-0">
          <AgentPipelineBanner job={job} pollStopped={pollStopped} compact />
        </div>
        <div className="flex min-h-0 flex-col gap-4 overflow-hidden">
          <JobActivityPanel
            jobId={jobId}
            uploadLines={[]}
            uploadProgress={null}
            uploading={false}
            showUploadActivity={false}
            sourceTransport="server"
            onRefreshLogs={() => void load(true)}
            panelHeight={logPanelHeight}
          />
          <ProgressAgentPanel jobId={jobId} active={!pollStopped} />
        </div>
      </div>

      <div className="mt-6 min-w-0">
        <RagQaPanel
          jobId={jobId}
          jobStatus={job.status}
          enrichment={job.enrichment}
          onActivity={() => void load(true)}
        />
      </div>
    </div>
  );
}
