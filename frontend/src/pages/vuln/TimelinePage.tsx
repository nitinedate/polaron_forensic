import { useCallback, useEffect, useState } from "react";
import { Calendar, Clock } from "lucide-react";
import { Badge, Card, Field, PageHeader, Select, Spinner } from "../../components/ui";
import { vulnApi } from "../../lib/vulnApi";
import { useToast } from "../../lib/toast";
import type { Case } from "../../lib/types/forensic";
import type { TimelineEvent } from "../../lib/types/vuln";

const TYPE_TONE: Record<string, "neutral" | "green" | "amber" | "red" | "indigo"> = {
  scan: "indigo",
  vuln: "red",
  remediation: "green",
  forensic: "amber",
  auth: "neutral",
};

export function TimelinePage() {
  const toast = useToast();
  const [cases, setCases] = useState<Case[]>([]);
  const [caseId, setCaseId] = useState("");
  const [events, setEvents] = useState<TimelineEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    vulnApi
      .listCases({ page: 1, page_size: 50 })
      .then((res) => {
        setCases(res.items);
        if (res.items.length > 0) setCaseId(res.items[0].id);
      })
      .catch(() => undefined);
  }, []);

  const load = useCallback(async () => {
    if (!caseId) {
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const res = await vulnApi.getTimeline(caseId, 200);
      setEvents(res.events);
      setTotal(res.total);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to load timeline");
    } finally {
      setLoading(false);
    }
  }, [caseId, toast]);

  useEffect(() => {
    load();
  }, [load]);

  return (
    <div>
      <PageHeader
        title="Unified timeline"
        subtitle="Correlated events across scans, findings, and forensic activity."
      />

      <Card className="mb-6 p-4">
        <Field label="Case">
          <Select className="max-w-sm" value={caseId} onChange={(e) => setCaseId(e.target.value)}>
            <option value="">Select case…</option>
            {cases.map((c) => (
              <option key={c.id} value={c.id}>
                {c.title || c.number || c.id.slice(0, 8)}
              </option>
            ))}
          </Select>
        </Field>
        <p className="mt-2 text-xs text-ink-400">{total} total events</p>
      </Card>

      {loading ? (
        <Spinner />
      ) : events.length === 0 ? (
        <Card className="p-8 text-center">
          <Calendar className="mx-auto h-8 w-8 text-ink-300" />
          <p className="mt-3 text-sm text-ink-400">No timeline events for this case.</p>
        </Card>
      ) : (
        <div className="relative space-y-0">
          <div className="absolute left-[19px] top-2 bottom-2 w-px bg-ink-200" />
          {events.map((evt) => (
            <div key={evt.id} className="relative flex gap-4 pb-6 pl-2">
              <div className="relative z-10 flex h-10 w-10 shrink-0 items-center justify-center rounded-full border-2 border-white bg-brand-50 ring-1 ring-brand-200">
                <Clock className="h-4 w-4 text-brand-600" />
              </div>
              <Card className="flex-1 p-4">
                <div className="flex flex-wrap items-center gap-2">
                  <Badge tone={TYPE_TONE[evt.source_type] ?? "neutral"}>{evt.event_type}</Badge>
                  <span className="text-xs text-ink-400">
                    {new Date(evt.timestamp_utc).toLocaleString()}
                  </span>
                  {evt.actor && (
                    <span className="text-xs text-ink-500">· {evt.actor}</span>
                  )}
                </div>
                <p className="mt-2 text-sm text-ink-700">{evt.summary || "—"}</p>
                <p className="mt-1 text-xs text-ink-400">
                  Source: {evt.source_type}
                  {evt.source_id && ` · ${evt.source_id.slice(0, 12)}`}
                </p>
              </Card>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
