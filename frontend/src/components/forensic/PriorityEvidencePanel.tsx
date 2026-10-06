import { useCallback, useEffect, useRef, useState } from "react";
import { Button, Card, Spinner } from "../ui";
import { forensicApi } from "../../lib/forensicApi";
import type { Artifact, SuspiciousActivityCard, SuspiciousActivityPage, PriorityEvidencePage } from "../../lib/types/forensic";
import { EvidenceFrame } from "./EvidenceFrame";
import { ArtifactPreviewPanel } from "./ArtifactPreviewPanel";

const families = [
  ["whatsapp_messages", "WhatsApp chats"], ["deleted_whatsapp", "Deleted / residual chats"],
  ["browser", "Web / browser activity"], ["pictures", "Pictures"], ["videos", "Videos"],
  ["audio", "Audio"], ["documents", "Documents"], ["messages", "All messages"], ["emails", "Emails"], ["binary", "Binary fragments"], ["structured_data", "Structured exports"], ["downloads", "Downloads"], ["applications", "Applications"], ["accounts", "Accounts / users"], ["suspicious", "Suspicious Activity"],
] as const;

export function PriorityEvidencePanel({ jobId }: { jobId: string }) {
  const [family, setFamily] = useState("whatsapp_messages");
  const [page, setPage] = useState(1);
  const [priority, setPriority] = useState<PriorityEvidencePage | null>(null);
  const [media, setMedia] = useState<SuspiciousActivityPage | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [preview, setPreview] = useState<Artifact | null>(null);
  const requestId = useRef(0);
  const load = useCallback(async () => {
    const request = ++requestId.current;
    setLoading(true); setError("");
    try {
      if (family === "suspicious") {
        const result = await forensicApi.getSuspiciousActivity(jobId, page);
        if (request === requestId.current) setMedia(result);
      } else {
        const result = await forensicApi.getPriorityEvidence(jobId, family, page);
        if (request === requestId.current) setPriority(result);
      }
    } catch (e) { if (request === requestId.current) setError(e instanceof Error ? e.message : "Evidence could not be loaded"); }
    finally { if (request === requestId.current) setLoading(false); }
  }, [jobId, family, page ]);
  useEffect(() => { void load(); }, [load]);
  const openSource = async (id: string) => {
    try { setPreview(await forensicApi.getArtifact(jobId, id)); }
    catch (e) { setError(e instanceof Error ? e.message : "Source unavailable"); }
  };
  const total = family === "suspicious" ? media?.total || 0 : priority?.total || 0;
  return <Card className="mb-4 p-4">
    <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
      <div><h3 className="font-semibold text-ink-900">Priority evidence</h3>
        <p className="text-xs text-ink-500">Source-linked records, recovered states and image/video observations.</p></div>
      <Button variant="outline" onClick={() => void load()}>Refresh</Button>
    </div>
    <div className="mb-3 flex flex-wrap gap-2">{families.map(([key, label]) => <Button key={key}
      variant={family === key ? "brand" : "outline"} onClick={() => { setFamily(key); setPage(1); setPreview(null); }}>
      {label}{key !== "suspicious" && priority ? ` (${(priority.families[key] || 0).toLocaleString()})` : ""}
    </Button>)}</div>
    {family === "suspicious" && <p className="mb-3 text-xs text-ink-600">{media?.note}</p>}
    {error && <p role="alert" className="mb-3 text-sm text-red-700">{error}</p>}
    {loading ? <Spinner /> : <>
      {family === "suspicious" ? <div className="max-h-[520px] space-y-3 overflow-auto">{media?.items.map(item => {
        const card = {...item,...item.data,job_id:jobId} as SuspiciousActivityCard;
        return <div key={card.id} className="rounded-lg border p-3 text-xs">
          <p className="font-semibold">{card.category.replace(/_/g," ")} · pending examiner review</p>
          <p className="break-all">{card.source_path}</p><p className="break-all font-mono text-[10px]">SHA256 {card.source_sha256 || "Unavailable"}</p>
          <EvidenceFrame card={card} /><p className="my-2 whitespace-pre-wrap">{card.explanation}</p>
          <blockquote className="whitespace-pre-wrap border-l-2 pl-2">{card.excerpt}</blockquote>
          <p className="my-2">Method: {card.method} · Source record: {card.source_record_id}</p>
          {card.frame_sha256 && <p className="break-all">Frame SHA256 {card.frame_sha256} · {card.timestamp_seconds ?? "Image"}</p>}
          {card.job_artifact_id && <Button variant="outline" onClick={() => void openSource(card.job_artifact_id!)}>Open original evidence</Button>}
        </div>;
      })}</div> : <div className="max-h-[520px] overflow-auto"><table className="w-full text-left text-xs"><thead><tr className="border-b"><th className="p-2">Record / time</th><th className="p-2">Content</th><th className="p-2">Source evidence</th></tr></thead><tbody>
        {priority?.items.map((item) => <tr key={item.artifact_id} className="border-b align-top"><td className="p-2">{item.artifact_type}<br />{item.timestamp_utc || "Time unavailable"}<br /><strong>{item.state.replace(/_/g, " ")}</strong></td>
          <td className="max-w-md p-2"><p className="whitespace-pre-wrap break-words">{String(item.data.body || item.data.url || item.data.title || item.data.name || item.data.note || "Source record")}</p>
            {item.data.reference_only === true && <p className="font-semibold text-amber-800">Reference only — this database entry does not establish recovery of the file content.</p>}
            <details><summary className="cursor-pointer">Full record and provenance</summary><pre className="max-h-80 overflow-auto whitespace-pre-wrap break-all">{JSON.stringify({ data: item.data, forensic: item.forensic }, null, 2)}</pre></details>
            {item.linked_media?.map((link) => <Button key={link.id} variant="outline" onClick={() => void openSource(link.id)}>{link.file_path.split("/").pop()} · {link.match_basis.replace(/_/g, " ")}</Button>)}</td>
          <td className="max-w-xs break-all p-2">{String(item.forensic.source_path || "")}<br /><span className="font-mono text-[10px]">{String(item.forensic.source_sha256 || "")}</span>
            {item.job_artifact_id && <Button variant="outline" onClick={() => void openSource(item.job_artifact_id!)}>Open source</Button>}</td></tr>)}</tbody></table></div>}
      {total === 0 && <p className="py-4 text-xs text-ink-600">No records captured in this category yet. For Android chats and browser history, check acquired private databases and matching backup keys. Deleted or overwritten bytes may be unavailable.</p>}
      <div className="mt-3 flex items-center gap-3 text-xs"><span>{total.toLocaleString()} records · Page {page}</span><Button variant="outline" disabled={page <= 1} onClick={() => setPage(page - 1)}>Previous</Button><Button variant="outline" disabled={page * 50 >= total} onClick={() => setPage(page + 1)}>Next</Button></div>
    </>}
    {preview && <div className="mt-4"><Button variant="outline" onClick={() => setPreview(null)}>Close evidence</Button><ArtifactPreviewPanel jobId={jobId} artifact={preview} /></div>}
  </Card>;
}
