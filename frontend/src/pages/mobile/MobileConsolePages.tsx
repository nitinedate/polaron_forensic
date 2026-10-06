import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  ArrowRight,
  CheckCircle2,
  FileText,
  ImageIcon,
  Smartphone,
} from "lucide-react";
import { Badge, Button, Card, LoadPanel, PageHeader } from "../../components/ui";
import { forensicApi } from "../../lib/forensicApi";
import { mobilePlatformService, mobileUiBasePath } from "../../lib/serviceMode";
import type { ApiService } from "../../lib/api";
import type { Job } from "../../lib/types/forensic";

type MobilePlatform = "android" | "ios";
type MobileJobEntry = { job: Job; platform: MobilePlatform };
type DirectoryMode = "jobs" | "rag" | "reports";

const tones: Record<string, "neutral" | "green" | "amber" | "red" | "indigo"> = {
  created: "neutral",
  registered: "amber",
  processing: "indigo",
  building_disk: "indigo",
  parsing: "indigo",
  indexing: "indigo",
  indexed: "green",
  completed: "green",
  ready: "green",
  report_ready: "green",
  failed: "red",
  paused: "amber",
};

const RAG_READY = new Set([
  "artifacts_registered",
  "parsed",
  "classified",
  "indexing",
  "indexed",
  "ready",
  "report_ready",
  "report_generating",
  "reporting",
  "completed",
]);

function platformLabel(platform: MobilePlatform): string {
  return platform === "ios" ? "iOS" : "Android";
}

function platformService(platform: MobilePlatform): ApiService {
  return `mobile-${platform}` as ApiService;
}

function jobHref(entry: MobileJobEntry): string {
  return `${mobileUiBasePath(entry.platform)}/jobs/${entry.job.id}`;
}

function reportHref(entry: MobileJobEntry): string {
  return `${jobHref(entry)}/report`;
}

function isRagReady(job: Job): boolean {
  return Boolean(job.enrichment?.baseline_ready) || RAG_READY.has(String(job.status || "").toLowerCase());
}

function useMobileDirectory() {
  const dedicatedPlatform = mobilePlatformService();
  const [items, setItems] = useState<MobileJobEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    const platforms: MobilePlatform[] = dedicatedPlatform
      ? [dedicatedPlatform]
      : ["android", "ios"];

    const settled = await Promise.allSettled(
      platforms.map(async (platform) => {
        const data = await forensicApi.listJobs(
          { page: 1, page_size: 100 },
          { service: platformService(platform) },
        );
        return (data.items ?? []).map((job) => ({ job, platform } as MobileJobEntry));
      }),
    );

    const next: MobileJobEntry[] = [];
    const failures: string[] = [];
    settled.forEach((result, index) => {
      const platform = platforms[index];
      if (result.status === "fulfilled") next.push(...result.value);
      else failures.push(`${platformLabel(platform)}: ${result.reason instanceof Error ? result.reason.message : "backend unavailable"}`);
    });
    next.sort((a, b) => Date.parse(b.job.updated_at) - Date.parse(a.job.updated_at));
    setItems(next);
    if (failures.length) setError(failures.join(" · "));
    setLoading(false);
  }, [dedicatedPlatform]);

  useEffect(() => {
    void load();
  }, [load]);

  return { items, loading, error, load, dedicatedPlatform };
}

function PlatformCard({ platform, mode }: { platform: MobilePlatform; mode: "acquire" | "import" }) {
  const label = platformLabel(platform);
  const base = mobileUiBasePath(platform);
  const acquire = mode === "acquire";
  return (
    <Card className="p-5">
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2">
            <Smartphone className="h-5 w-5 text-brand-600" />
            <h3 className="text-lg font-bold text-ink-900">{label}</h3>
          </div>
          <p className="mt-2 text-sm text-ink-500">
            {acquire
              ? `Acquire a connected ${label} device into sealed mobile evidence, then hand the result only to the ${label} backend.`
              : `Import an existing ${label} image, backup, or extraction package and run extraction, parsing, OCR and RAG in the ${label} backend.`}
          </p>
        </div>
        <Badge tone={platform === "ios" ? "indigo" : "green"}>{label} isolated</Badge>
      </div>
      <div className="mt-5">
        <Link to={acquire ? `${base}/acquire` : `${base}/new`}>
          <Button variant="brand">
            {acquire ? "Start acquisition" : "Import mobile image"}
            <ArrowRight className="h-4 w-4" />
          </Button>
        </Link>
      </div>
    </Card>
  );
}

function PipelineStrip() {
  const stages = ["Image / backup", "Extract", "Parse", "OCR", "RAG", "Report"];
  return (
    <Card className="p-5">
      <p className="text-xs font-bold uppercase tracking-wider text-ink-400">Mobile analysis pipeline</p>
      <div className="mt-4 flex flex-wrap items-center gap-2">
        {stages.map((stage, index) => (
          <div key={stage} className="flex items-center gap-2">
            <span className="rounded-full border border-ink-200 bg-white px-3 py-1.5 text-xs font-semibold text-ink-700">
              {stage}
            </span>
            {index < stages.length - 1 ? <ArrowRight className="h-3.5 w-3.5 text-ink-300" /> : null}
          </div>
        ))}
      </div>
      <p className="mt-3 text-xs text-ink-500">
        Android and iOS run this pipeline in different APIs, databases, Redis brokers, MinIO buckets and Celery queues. Only host-capacity leases are shared.
      </p>
    </Card>
  );
}

export function MobileOverviewPage() {
  const { items, loading, error, load } = useMobileDirectory();
  const stats = useMemo(() => {
    const android = items.filter((item) => item.platform === "android").length;
    const ios = items.filter((item) => item.platform === "ios").length;
    const active = items.filter((item) => !["completed", "ready", "failed"].includes(String(item.job.status).toLowerCase())).length;
    const ragReady = items.filter((item) => isRagReady(item.job)).length;
    return { android, ios, active, ragReady };
  }, [items]);

  return (
    <div>
      <PageHeader
        title="Mobile Forensics"
        subtitle="Dedicated Android and iOS acquisition, image extraction, RAG and reporting without using the Disk Forensics UI or backend."
      />

      {error && items.length > 0 ? (
        <Card className="mb-4 border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
          One mobile backend is temporarily unavailable. Jobs from the available backend are still shown. {error}
        </Card>
      ) : null}

      <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Card className="p-4"><p className="text-xs text-ink-400">Android jobs</p><p className="mt-1 text-2xl font-bold text-ink-900">{stats.android}</p></Card>
        <Card className="p-4"><p className="text-xs text-ink-400">iOS jobs</p><p className="mt-1 text-2xl font-bold text-ink-900">{stats.ios}</p></Card>
        <Card className="p-4"><p className="text-xs text-ink-400">Active pipelines</p><p className="mt-1 text-2xl font-bold text-ink-900">{stats.active}</p></Card>
        <Card className="p-4"><p className="text-xs text-ink-400">RAG-ready jobs</p><p className="mt-1 text-2xl font-bold text-ink-900">{stats.ragReady}</p></Card>
      </div>

      <div className="mt-4 grid gap-4 lg:grid-cols-2">
        <Card className="p-5">
          <div className="flex items-center gap-2"><Smartphone className="h-5 w-5 text-brand-600"/><h3 className="font-bold text-ink-900">Device → Image</h3></div>
          <p className="mt-2 text-sm text-ink-500">Acquire a connected Android or iOS device and produce sealed mobile evidence first.</p>
          <Link to="/mobile/acquisition"><Button className="mt-4" variant="outline">Open acquisition <ArrowRight className="h-4 w-4"/></Button></Link>
        </Card>
        <Card className="p-5">
          <div className="flex items-center gap-2"><ImageIcon className="h-5 w-5 text-brand-600"/><h3 className="font-bold text-ink-900">Images → Extraction → RAG</h3></div>
          <p className="mt-2 text-sm text-ink-500">Import an existing mobile image/package, extract artifacts, OCR supported content and build the mobile-only RAG index.</p>
          <Link to="/mobile/images"><Button className="mt-4" variant="outline">Import mobile evidence <ArrowRight className="h-4 w-4"/></Button></Link>
        </Card>
      </div>

      <div className="mt-4"><PipelineStrip /></div>

      <Card className="mt-4 overflow-hidden">
        <div className="flex items-center justify-between border-b border-ink-100 px-5 py-4">
          <div><h3 className="font-bold text-ink-900">Recent mobile jobs</h3><p className="text-xs text-ink-400">Android and iOS are shown together here, but each link remains pinned to its own backend.</p></div>
          <Link to="/mobile/jobs" className="text-xs font-semibold text-brand-700">View all</Link>
        </div>
        <LoadPanel loading={loading} error={error} hasData={items.length > 0} onRetry={() => void load()} empty={<div className="py-10 text-center text-sm text-ink-400">No mobile jobs yet.</div>}>
          <div className="divide-y divide-ink-100">
            {items.slice(0, 6).map((entry) => (
              <Link key={`${entry.platform}:${entry.job.id}`} to={jobHref(entry)} className="grid grid-cols-[auto_1fr_auto] items-center gap-3 px-5 py-3 hover:bg-ink-50">
                <Badge tone={entry.platform === "ios" ? "indigo" : "green"}>{platformLabel(entry.platform)}</Badge>
                <div className="min-w-0"><p className="truncate font-mono text-xs text-ink-600">{entry.job.id}</p><p className="mt-1 text-xs text-ink-400">{entry.job.status} · {entry.job.progress_pct ?? 0}%</p></div>
                <ArrowRight className="h-4 w-4 text-ink-300"/>
              </Link>
            ))}
          </div>
        </LoadPanel>
      </Card>
    </div>
  );
}

export function MobileAcquisitionHubPage() {
  return (
    <div>
      <PageHeader title="Mobile device → image" subtitle="Choose the mobile platform first. Android and iOS acquisition never share a backend or evidence store." />
      <div className="grid gap-4 lg:grid-cols-2">
        <PlatformCard platform="android" mode="acquire" />
        <PlatformCard platform="ios" mode="acquire" />
      </div>
      <div className="mt-4"><PipelineStrip /></div>
    </div>
  );
}

export function MobileImageProcessingPage() {
  return (
    <div>
      <PageHeader title="Mobile images → RAG" subtitle="Import already-acquired Android or iOS images/backups and send them directly to the matching mobile extraction/RAG backend." />
      <div className="grid gap-4 lg:grid-cols-2">
        <PlatformCard platform="android" mode="import" />
        <PlatformCard platform="ios" mode="import" />
      </div>
      <div className="mt-4"><PipelineStrip /></div>
    </div>
  );
}

function MobileDirectoryPage({ mode }: { mode: DirectoryMode }) {
  const { items, loading, error, load, dedicatedPlatform } = useMobileDirectory();
  const title = mode === "jobs" ? "Mobile jobs" : mode === "rag" ? "Mobile RAG" : "Mobile reports";
  const subtitle = mode === "jobs"
    ? "Track Android and iOS jobs without mixing their backend state."
    : mode === "rag"
      ? "Select a mobile job to query its own isolated RAG index."
      : "Open report generation for an Android or iOS job. Reports never use Disk report routes.";

  const visible = mode === "rag"
    ? [...items].sort((a, b) => Number(isRagReady(b.job)) - Number(isRagReady(a.job)))
    : items;

  return (
    <div>
      <PageHeader
        title={dedicatedPlatform ? `${platformLabel(dedicatedPlatform)} ${title.toLowerCase()}` : title}
        subtitle={subtitle}
        actions={mode === "jobs" && !dedicatedPlatform ? <Link to="/mobile/images"><Button variant="brand"><ImageIcon className="h-4 w-4"/> Import image</Button></Link> : undefined}
      />
      {error && visible.length > 0 ? (
        <Card className="mb-4 border-amber-200 bg-amber-50 p-4 text-sm text-amber-900">
          One mobile backend is temporarily unavailable. {error}
        </Card>
      ) : null}
      <Card className="overflow-hidden">
        <LoadPanel loading={loading} error={error} hasData={visible.length > 0} onRetry={() => void load()} empty={<div className="py-16 text-center text-sm text-ink-400"><Smartphone className="mx-auto mb-2 h-8 w-8"/>No mobile jobs available.</div>}>
          <div className="divide-y divide-ink-100">
            {visible.map((entry) => {
              const ragReady = isRagReady(entry.job);
              const href = mode === "reports" ? reportHref(entry) : jobHref(entry);
              return (
                <Link key={`${entry.platform}:${entry.job.id}`} to={href} className="grid gap-3 px-5 py-4 hover:bg-ink-50 md:grid-cols-[110px_1fr_180px] md:items-center">
                  <div><Badge tone={entry.platform === "ios" ? "indigo" : "green"}>{platformLabel(entry.platform)}</Badge></div>
                  <div className="min-w-0">
                    <div className="flex flex-wrap items-center gap-2"><span className="font-mono text-xs text-ink-600">{entry.job.id}</span><Badge tone={tones[entry.job.status] ?? "neutral"}>{entry.job.status}</Badge></div>
                    <div className="mt-2 h-1.5 max-w-lg rounded-full bg-ink-100"><div className="h-1.5 rounded-full bg-brand-500" style={{ width: `${Math.max(0, Math.min(100, entry.job.progress_pct || 0))}%` }}/></div>
                    <p className="mt-1 text-xs text-ink-400">Updated {new Date(entry.job.updated_at).toLocaleString()}</p>
                  </div>
                  <div className="flex items-center justify-end gap-2 text-xs font-semibold text-brand-700">
                    {mode === "rag" ? (ragReady ? <><CheckCircle2 className="h-4 w-4"/> Open RAG</> : <>Open pipeline <ArrowRight className="h-4 w-4"/></>) : mode === "reports" ? <><FileText className="h-4 w-4"/> Open report</> : <>Open job <ArrowRight className="h-4 w-4"/></>}
                  </div>
                </Link>
              );
            })}
          </div>
        </LoadPanel>
      </Card>
    </div>
  );
}

export function MobileUnifiedJobsPage() {
  return <MobileDirectoryPage mode="jobs" />;
}

export function MobileRagDirectoryPage() {
  return <MobileDirectoryPage mode="rag" />;
}

export function MobileReportsDirectoryPage() {
  return <MobileDirectoryPage mode="reports" />;
}
