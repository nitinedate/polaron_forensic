import { PriorityEvidencePanel } from "../../components/forensic/PriorityEvidencePanel";
import { useCallback, useEffect, useMemo, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, ArrowRight, Images, MessageCircleMore, Smartphone, Trash2 } from "lucide-react";
import { Badge, Button, Card, PageHeader, Spinner } from "../../components/ui";
import { FamilyEvidenceDialog, type FamilyEvidenceTarget } from "../../components/forensic/FamilyEvidenceDialog";
import { MobileArtifactBoard, type MobileArtifactBoardData } from "../../components/forensic/MobileArtifactBoard";
import { forensicApi } from "../../lib/forensicApi";
import { mobilePlatformService, mobileUiBasePath } from "../../lib/serviceMode";
import type { ApiService } from "../../lib/api";
import type { Job } from "../../lib/types/forensic";
import { useToast } from "../../lib/toast";

const FAMILY = {
  whatsapp: { key:"whatsapp_messages", label:"WhatsApp messages", description:"Current and recovered WhatsApp conversations, media and attachments." },
  photos: { key:"pictures", label:"Pictures / images", description:"Recovered mobile photos and images with original downloads and pixel dimensions." },
  videos: { key:"videos", label:"Videos", description:"Recovered videos with original file size, pixel dimensions, codec/duration when available." },
  audio: { key:"audio", label:"Audio", description:"Recovered audio/voice notes with original downloads and duration metadata." },
  documents: { key:"documents", label:"Documents", description:"PDF, TXT, Office and other document evidence." },
  deleted: { key:"deleted_files", label:"All deleted files", description:"Recovered deleted mobile files." },
  deletedPhotos: { key:"deleted_photos", label:"Deleted pictures", description:"Recovered deleted pictures/images." },
  deletedVideos: { key:"deleted_videos", label:"Deleted videos", description:"Recovered deleted videos." },
  deletedDocs: { key:"deleted_documents", label:"Deleted documents", description:"Recovered deleted document files." },
  deletedWhatsApp: { key:"whatsapp_deleted_messages", label:"Deleted WhatsApp", description:"Recovered/deleted WhatsApp messages from the examiner device owner and other participants." },
} satisfies Record<string, FamilyEvidenceTarget>;

type Tab = "overview"|"whatsapp"|"media"|"deleted";

export function MobileArtifactsPage() {
  const {jobId=""}=useParams(); const toast=useToast();
  const platform=mobilePlatformService()??"android"; const service=`mobile-${platform}` as ApiService; const label=platform==="ios"?"iOS":"Android"; const base=mobileUiBasePath(platform);
  const [job,setJob]=useState<Job|null>(null); const [board,setBoard]=useState<MobileArtifactBoardData|null>(null); const [loading,setLoading]=useState(true); const [tab,setTab]=useState<Tab>("overview"); const [family,setFamily]=useState<FamilyEvidenceTarget|null>(null);
  const load=useCallback(async()=>{setLoading(true);try{const [j,b]=await Promise.all([forensicApi.getJob(jobId,{service}),forensicApi.getMobileArtifactBoard(jobId)]);setJob(j);setBoard(b as MobileArtifactBoardData);}catch(e){toast.error(e instanceof Error?e.message:"Mobile artifacts unavailable");}finally{setLoading(false);}},[jobId,service,toast]);
  useEffect(()=>{void load();},[load]);
  const countMap=useMemo(()=>new Map((board?.rows||[]).map((row)=>[row.key,row.count])),[board]);
  const cards=(targets:FamilyEvidenceTarget[])=> <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-3">{targets.map((target)=><button type="button" key={target.key} onClick={()=>setFamily({...target,count:countMap.get(target.key)||0})} className="rounded-2xl border border-ink-200 bg-white p-4 text-left shadow-panel transition hover:-translate-y-0.5 hover:border-brand-300"><div className="flex items-center justify-between gap-2"><p className="font-bold text-ink-900">{target.label}</p><Badge tone={(countMap.get(target.key)||0)>0?"green":"neutral"}>{(countMap.get(target.key)||0).toLocaleString()}</Badge></div><p className="mt-2 text-xs text-ink-500">{target.description}</p><p className="mt-3 text-xs font-semibold text-brand-700">Open evidence <ArrowRight className="inline h-3.5 w-3.5"/></p></button>)}</div>;
  if(loading&&!job)return <Spinner/>; if(!job)return <Card className="p-6">Job unavailable in this {label} backend.</Card>;
  return <div>
    <PageHeader title={`${label} Mobile Artifacts`} subtitle="Mobile-only artifact workspace: messages, media, documents and deleted evidence. Original evidence files remain downloadable from the platform-specific backend." actions={<div className="flex flex-wrap gap-2"><Link to={`${base}/jobs/${jobId}`}><Button variant="ghost"><ArrowLeft className="h-4 w-4"/> Processing</Button></Link><Link to={`${base}/jobs/${jobId}/intake`}><Button variant="brand">Continue to Intake <ArrowRight className="h-4 w-4"/></Button></Link></div>}/>
    <Card className="mb-4 p-4"><div className="flex flex-wrap items-center gap-3"><Smartphone className="h-5 w-5 text-brand-600"/><Badge tone={platform==="ios"?"indigo":"green"}>{label} isolated backend</Badge><span className="font-mono text-xs text-ink-500">Case {job.case_id||"not linked"}</span><span className="text-xs text-ink-500">{board?.total_files?.toLocaleString()||0} indexed files</span></div></Card>
    <PriorityEvidencePanel jobId={jobId} />
    <div className="mb-4 flex flex-wrap gap-2">{([[
      "overview","Overview",Smartphone],["whatsapp","WhatsApp",MessageCircleMore],["media","Media & files",Images],["deleted","Deleted evidence",Trash2]] as const).map(([id,text,Icon])=><Button key={id} variant={tab===id?"brand":"outline"} onClick={()=>setTab(id as Tab)}><Icon className="h-4 w-4"/>{text}</Button>)}</div>
    {tab==="overview"?<Card className="p-5"><MobileArtifactBoard jobId={jobId}/></Card>:null}
    {tab==="whatsapp"?<><Card className="mb-4 border-emerald-200 bg-emerald-50/50 p-4"><p className="font-semibold text-emerald-900">WhatsApp-style examiner view</p><p className="mt-1 text-xs text-emerald-800">Messages are aligned by sender, recovered deletions are marked explicitly, and linked images/videos/documents can be opened or downloaded from the original extracted evidence.</p></Card>{cards([FAMILY.whatsapp,FAMILY.deletedWhatsApp])}</>:null}
    {tab==="media"?cards([FAMILY.photos,FAMILY.videos,FAMILY.audio,FAMILY.documents]):null}
    {tab==="deleted"?<><Card className="mb-4 border-amber-200 bg-amber-50/60 p-4"><p className="font-semibold text-amber-900">Deleted / recovered evidence</p><p className="mt-1 text-xs text-amber-800">This section is intentionally separate from current data. Recovery state and deletion metadata are preserved for examiner review.</p></Card>{cards([FAMILY.deletedWhatsApp,FAMILY.deletedPhotos,FAMILY.deletedVideos,FAMILY.deletedDocs,FAMILY.deleted])}</>:null}
    <FamilyEvidenceDialog jobId={jobId} open={family!=null} family={family} onClose={()=>setFamily(null)}/>
  </div>;
}
