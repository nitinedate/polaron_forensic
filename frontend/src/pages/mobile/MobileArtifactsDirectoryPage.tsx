import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ArrowRight, FolderSearch, Search, Smartphone } from "lucide-react";
import { Badge, Button, Card, Input, LoadPanel, PageHeader } from "../../components/ui";
import { forensicApi } from "../../lib/forensicApi";
import { mobilePlatformService, mobileUiBasePath } from "../../lib/serviceMode";
import type { ApiService } from "../../lib/api";
import type { Job } from "../../lib/types/forensic";

type Platform = "android" | "ios";
type Entry = { platform: Platform; job: Job };
const serviceFor = (platform: Platform) => `mobile-${platform}` as ApiService;

export function MobileArtifactsDirectoryPage() {
  const dedicated = mobilePlatformService();
  const [items, setItems] = useState<Entry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [caseId, setCaseId] = useState("");
  const [platformFilter, setPlatformFilter] = useState<"all" | Platform>(dedicated || "all");

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    const platforms: Platform[] = dedicated ? [dedicated] : ["android", "ios"];
    const settled = await Promise.allSettled(platforms.map(async (platform) => {
      const res = await forensicApi.listJobs({ page: 1, page_size: 250 }, { service: serviceFor(platform) });
      return (res.items || []).map((job) => ({ platform, job }));
    }));
    const next: Entry[] = [];
    const errors: string[] = [];
    settled.forEach((result, i) => result.status === "fulfilled" ? next.push(...result.value) : errors.push(`${platforms[i]} backend unavailable`));
    next.sort((a,b) => Date.parse(b.job.updated_at) - Date.parse(a.job.updated_at));
    setItems(next); setError(errors.length ? errors.join(" · ") : null); setLoading(false);
  }, [dedicated]);

  useEffect(() => { void load(); }, [load]);
  const filtered = useMemo(() => {
    const q = caseId.trim().toLowerCase();
    return items.filter(({ platform, job }) => {
      if (platformFilter !== "all" && platform !== platformFilter) return false;
      if (!q) return true;
      return String(job.case_id || "").toLowerCase().includes(q) || job.id.toLowerCase().includes(q);
    });
  }, [items, caseId, platformFilter]);

  return <div>
    <PageHeader title="Mobile Artifacts" subtitle="Separate Android and iOS evidence directories. Jobs are listed together only for navigation; artifact data remains in the platform-specific backend." />
    <Card className="mb-4 p-4">
      <div className="grid gap-3 lg:grid-cols-[minmax(0,1fr)_220px_auto] lg:items-end">
        <label><span className="mb-1 block text-xs font-bold uppercase tracking-wide text-ink-400">Filter by Case ID</span><div className="relative"><Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-400"/><Input className="pl-9" value={caseId} onChange={(e)=>setCaseId(e.target.value)} placeholder="Case ID or job ID"/></div></label>
        {!dedicated ? <label><span className="mb-1 block text-xs font-bold uppercase tracking-wide text-ink-400">Platform</span><select className="input" value={platformFilter} onChange={(e)=>setPlatformFilter(e.target.value as "all"|Platform)}><option value="all">Android + iOS</option><option value="android">Android only</option><option value="ios">iOS only</option></select></label> : <div/>}
        <Button variant="outline" onClick={()=>void load()}>Refresh</Button>
      </div>
      <p className="mt-2 text-xs text-ink-500">Workflow: Mobile Processing → Mobile Artifacts → Intake → Mobile Report.</p>
    </Card>
    <LoadPanel loading={loading} error={error} hasData={filtered.length>0} onRetry={()=>void load()} empty={<Card className="p-10 text-center text-sm text-ink-400">No Mobile jobs match this filter.</Card>}>
      <div className="grid gap-3">{filtered.map(({platform,job})=>{
        const label=platform==="ios"?"iOS":"Android";
        const base=mobileUiBasePath(platform);
        return <Card key={`${platform}:${job.id}`} className="p-4"><div className="flex flex-wrap items-center justify-between gap-3"><div><div className="flex items-center gap-2"><Smartphone className="h-4 w-4 text-brand-600"/><Badge tone={platform==="ios"?"indigo":"green"}>{label}</Badge><span className="font-mono text-sm font-semibold">{job.id}</span></div><p className="mt-1 text-xs text-ink-500">Case ID: <span className="font-mono">{job.case_id||"not linked"}</span> · {job.status} · {job.progress_pct??0}%</p></div><Link to={`${base}/jobs/${job.id}/artifacts`}><Button variant="brand"><FolderSearch className="h-4 w-4"/> Open {label} artifacts <ArrowRight className="h-4 w-4"/></Button></Link></div></Card>;
      })}</div>
    </LoadPanel>
  </div>;
}
