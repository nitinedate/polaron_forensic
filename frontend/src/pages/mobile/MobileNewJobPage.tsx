import { useState } from "react";
import { useNavigate } from "react-router-dom";
import { ArrowLeft, Smartphone } from "lucide-react";
import { Button, Card, Field, Input, PageHeader } from "../../components/ui";
import { forensicApi } from "../../lib/forensicApi";
import { mobilePlatformService, mobileUiBasePath } from "../../lib/serviceMode";
import { useToast } from "../../lib/toast";

export function MobileNewJobPage() {
  const platform = mobilePlatformService() ?? "android";
  const label = platform === "ios" ? "iOS" : "Android";
  const base = mobileUiBasePath(platform);
  const navigate = useNavigate(); const toast = useToast();
  const [caseId, setCaseId] = useState(""); const [legal, setLegal] = useState(false); const [loading, setLoading] = useState(false);
  async function create() {
    if (!legal || loading) return;
    setLoading(true);
    try {
      const job = await forensicApi.createJob({ type: `${platform}_mobile`, mobile_os: platform, source_type: "mobile", acquisition_mode: "import", case_id: caseId || null, domain_pack: "forensic", legal_authority_acknowledged: true });
      navigate(`${base}/jobs/${job.id}`, { state: { autoImport: true } });
    } catch (e) { toast.error(e instanceof Error ? e.message : "Create failed"); }
    finally { setLoading(false); }
  }
  return <div>
    <PageHeader title={`New ${label} extraction`} subtitle={`This job can only run in the ${label} backend and ${platform}-* worker queues.`}
      actions={<Button variant="ghost" onClick={() => navigate(base)}><ArrowLeft className="h-4 w-4"/> Back</Button>} />
    <Card className="max-w-2xl p-6 space-y-4">
      <div className="rounded-lg border border-brand-200 bg-brand-50 p-4"><div className="flex items-center gap-2 font-semibold text-brand-900"><Smartphone className="h-5 w-5"/>{label} only</div><p className="mt-1 text-xs text-brand-800">The operating system is fixed by this product. Android and iOS evidence cannot be mixed in the same backend.</p></div>
      <Field label="Case ID (optional)"><Input value={caseId} onChange={(e)=>setCaseId(e.target.value)} placeholder="Existing case UUID"/></Field>
      <label className="flex gap-3 rounded-lg border border-ink-100 p-3 text-sm text-ink-700"><input type="checkbox" checked={legal} onChange={(e)=>setLegal(e.target.checked)} className="mt-1"/><span>I confirm lawful authority and authorized scope for this {label} evidence.</span></label>
      <div className="flex justify-end"><Button variant="brand" loading={loading} disabled={!legal} onClick={() => void create()}>Create {label} job</Button></div>
    </Card>
  </div>;
}
