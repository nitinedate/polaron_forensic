import { useEffect, useRef, useState } from "react";
import { forensicApi } from "../../lib/forensicApi";
import type { SuspiciousActivityCard } from "../../lib/types/forensic";

export function EvidenceFrame({ card }: { card: SuspiciousActivityCard }) {
  const container = useRef<HTMLDivElement>(null);
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");
  useEffect(() => {
    if (card.frame_index == null || !card.job_artifact_id || !container.current) return;
    let active = true;
    const observer = new IntersectionObserver(entries => {
      if (!entries.some(entry => entry.isIntersecting)) return;
      observer.disconnect();
      void forensicApi.getMediaObservationFrame(card.job_id,card.job_artifact_id!,card.frame_index!)
        .then(result => { if (active) setUrl(result.data_url); })
        .catch(e => { if (active) setError(e instanceof Error ? e.message : "Evidence image unavailable"); });
    }, { rootMargin: "300px" });
    observer.observe(container.current);
    return () => { active = false; observer.disconnect(); };
  }, [card.job_id,card.job_artifact_id,card.frame_index]);
  return <div ref={container}>{url && <img className="mx-auto my-2 max-h-[55mm] max-w-full object-contain" src={url} alt={`Evidence derivative: ${card.source_path}`} />}
    {!url && card.frame_index != null && <p className="text-xs">{error || "Loading retained evidence frame…"}</p>}</div>;
}

