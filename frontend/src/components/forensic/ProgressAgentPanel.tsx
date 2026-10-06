import { useEffect, useState } from "react";
import { Activity } from "lucide-react";
import { forensicApi } from "../../lib/forensicApi";

type ProgressEvent = { id: number; stage?: string; decision: string; reason: string; created_at: string };

export function ProgressAgentPanel({ jobId, active = true }: { jobId: string; active?: boolean }) {
  const [events, setEvents] = useState<ProgressEvent[]>([]);
  const [error, setError] = useState("");
  useEffect(() => {
    let live = true;
    let timer: number | undefined;
    const poll = async () => {
      try {
        const result = await forensicApi.listProgressEvents(jobId);
        if (live) { setEvents(result.events); setError(""); }
      } catch (failure) {
        if (live) setError(failure instanceof Error ? failure.message : "Progress checks unavailable");
      } finally {
        if (live && active) timer = window.setTimeout(() => void poll(),15000);
      }
    };
    void poll();
    return () => { live = false; if (timer != null) window.clearTimeout(timer); };
  }, [jobId, active]);
  return <div className="rounded-xl border border-slate-200 bg-white p-4">
    <div className="mb-2 flex items-center gap-2 text-sm font-semibold"><Activity className="h-4 w-4" />progressAgent</div>
    <p className="mb-3 text-xs text-ink-500">Checks useful progress after one minute. Pauses and bounded operations are recorded; abandoned or stuck stage claims are recovered with a retry limit.</p>
    {error && <p className="text-xs text-amber-800">{error}</p>}
    {!events.length ? <p className="text-xs text-ink-500">No progress decisions recorded yet.</p> : <div className="max-h-56 overflow-auto"><table className="w-full text-left text-xs">
      <thead><tr><th className="p-2">Time</th><th className="p-2">Stage</th><th className="p-2">Decision</th><th className="p-2">Explanation</th></tr></thead>
      <tbody>{events.map(event => <tr key={event.id} className="border-t align-top"><td className="whitespace-nowrap p-2">{new Date(event.created_at).toLocaleTimeString()}</td><td className="p-2">{event.stage || "Acquisition"}</td><td className="p-2">{event.decision.replace(/_/g, " ")}</td><td className="p-2">{event.reason}</td></tr>)}</tbody>
    </table></div>}
  </div>;
}
