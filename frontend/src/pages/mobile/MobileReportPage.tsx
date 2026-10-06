import { useCallback, useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { ArrowLeft, Download, FileText, Play } from "lucide-react";
import { Button, Card, PageHeader } from "../../components/ui";
import { forensicApi } from "../../lib/forensicApi";
import type { ReportSection } from "../../lib/types/forensic";
import { mobilePlatformService, mobileUiBasePath } from "../../lib/serviceMode";
import { useToast } from "../../lib/toast";

export function MobileReportPage(){
  const {jobId=""}=useParams(); const navigate=useNavigate(); const toast=useToast(); const platform=mobilePlatformService()??"android"; const label=platform==="ios"?"iOS":"Android"; const base=mobileUiBasePath(platform);
  const [sections,setSections]=useState<ReportSection[]>([]); const [status,setStatus]=useState("not_started"); const [busy,setBusy]=useState(false);
  const load=useCallback(async()=>{ try{const [st,sec]=await Promise.all([forensicApi.getReportStatus(jobId),forensicApi.listReportSections(jobId).catch(()=>[])]);setStatus(st.status);setSections(sec);}catch{/* report may not exist yet */}},[jobId]);
  useEffect(()=>{void load();const t=window.setInterval(()=>void load(),5000);return()=>window.clearInterval(t);},[load]);
  async function start(){setBusy(true);try{await forensicApi.startReport(jobId,{report_type:"mobile_forensic"});toast.success(`${label} report queued`);await load();}catch(e){toast.error(e instanceof Error?e.message:"Report failed");}finally{setBusy(false);}}
  async function exportFmt(format:"pdf"|"docx"){setBusy(true);try{const ex=await forensicApi.exportReport(jobId,{format,template:"mobile_compact"});await forensicApi.downloadReportExport(ex.id);toast.success(`${format.toUpperCase()} exported`);}catch(e){toast.error(e instanceof Error?e.message:"Export failed");}finally{setBusy(false);}}
  return <div><PageHeader title={`${label} forensic report`} subtitle="Generated only from this mobile backend's evidence and RAG index." actions={<Button variant="ghost" onClick={()=>navigate(`${base}/jobs/${jobId}`)}><ArrowLeft className="h-4 w-4"/> Job</Button>}/>
    <Card className="mb-4 p-4"><div className="flex flex-wrap items-center gap-2"><span className="mr-3 text-sm text-ink-600">Status: <b>{status}</b></span><Button variant="brand" loading={busy} onClick={()=>void start()}><Play className="h-4 w-4"/> Generate</Button><Button variant="outline" disabled={busy||sections.length===0} onClick={()=>void exportFmt("pdf")}><Download className="h-4 w-4"/> PDF</Button><Button variant="outline" disabled={busy||sections.length===0} onClick={()=>void exportFmt("docx")}><Download className="h-4 w-4"/> DOCX</Button></div></Card>
    <div className="space-y-3">{sections.length===0?<Card className="p-8 text-center text-sm text-ink-400"><FileText className="mx-auto mb-2 h-7 w-7"/>No mobile report sections yet.</Card>:sections.map(s=><Card key={s.id} className="p-4"><h3 className="font-semibold text-ink-800">{s.section_key.split("_").join(" ")}</h3><p className="mt-2 whitespace-pre-wrap text-sm text-ink-600">{s.narrative_content||"Structured section ready."}</p></Card>)}</div>
  </div>;
}
