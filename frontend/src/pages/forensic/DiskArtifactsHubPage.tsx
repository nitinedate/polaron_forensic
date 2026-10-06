import { useCallback, useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { ArrowRight, FolderSearch, HardDrive, Search } from "lucide-react";
import { Badge, Button, Card, Input, LoadPanel, PageHeader } from "../../components/ui";
import { forensicApi } from "../../lib/forensicApi";
import type { Job } from "../../lib/types/forensic";

function matchesCase(job: Job, query: string): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return String(job.case_id || "").toLowerCase().includes(q) || job.id.toLowerCase().includes(q);
}

export function DiskArtifactsHubPage() {
  const [jobs, setJobs] = useState<Job[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [caseId, setCaseId] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const res = await forensicApi.listJobs({ page: 1, page_size: 250 });
      setJobs(res.items || []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not load Disk artifact jobs");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);
  const filtered = useMemo(() => jobs.filter((job) => matchesCase(job, caseId)), [jobs, caseId]);

  return (
    <div>
      <PageHeader
        title="Disk Artifacts"
        subtitle="Forensic evidence review for Disk Forensics. Open actual extracted files, review metadata, preview/download evidence, then continue to Intake."
      />
      <Card className="mb-4 p-4">
        <div className="grid gap-3 md:grid-cols-[minmax(0,1fr)_auto] md:items-end">
          <label className="block">
            <span className="mb-1 block text-xs font-bold uppercase tracking-wide text-ink-400">Filter by Case ID</span>
            <div className="relative">
              <Search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-ink-400" />
              <Input value={caseId} onChange={(e) => setCaseId(e.target.value)} placeholder="Case ID or job ID" className="pl-9" />
            </div>
          </label>
          <Button variant="outline" onClick={() => void load()}>Refresh</Button>
        </div>
        <p className="mt-2 text-xs text-ink-500">Workflow: Processing Pipeline → Artifacts → Intake → Report.</p>
      </Card>

      <LoadPanel loading={loading} error={error} hasData={filtered.length > 0} onRetry={() => void load()} empty={<Card className="p-10 text-center text-sm text-ink-400">No Disk jobs match this Case ID.</Card>}>
        <div className="grid gap-3">
          {filtered.map((job) => (
            <Card key={job.id} className="p-4">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <HardDrive className="h-4 w-4 text-brand-600" />
                    <span className="font-mono text-sm font-semibold text-ink-800">{job.id}</span>
                    <Badge tone={job.status === "failed" ? "red" : ["completed", "ready", "indexed", "classified"].includes(job.status) ? "green" : "indigo"}>{job.status}</Badge>
                  </div>
                  <p className="mt-1 text-xs text-ink-500">Case ID: <span className="font-mono">{job.case_id || "not linked"}</span> · {job.domain_pack} · {job.progress_pct ?? 0}%</p>
                </div>
                <Link to={`/forensic/jobs/${job.id}/artifacts`}>
                  <Button variant="brand"><FolderSearch className="h-4 w-4" /> Open artifacts <ArrowRight className="h-4 w-4" /></Button>
                </Link>
              </div>
            </Card>
          ))}
        </div>
      </LoadPanel>
    </div>
  );
}
