import { useState } from "react";
import { MessageSquare, Search } from "lucide-react";
import { Button, Card, Input } from "../ui";
import { forensicApi } from "../../lib/forensicApi";
import { useToast } from "../../lib/toast";

type Props = { jobId: string; ready: boolean };

export function MobileRagPanel({ jobId, ready }: Props) {
  const toast = useToast();
  const [query, setQuery] = useState("");
  const [answer, setAnswer] = useState<string | null>(null);
  const [items, setItems] = useState<Array<Record<string, unknown>>>([]);
  const [loading, setLoading] = useState(false);

  async function ask() {
    const q = query.trim();
    if (!q || loading) return;
    setLoading(true);
    try {
      const result = await forensicApi.retrieve(jobId, { query: q, top_k: 8, include_answer: true });
      setAnswer(result.answer ?? null);
      setItems(result.items ?? []);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : "Mobile evidence query failed");
    } finally { setLoading(false); }
  }

  return (
    <Card className="p-5">
      <div className="mb-2 flex items-center gap-2">
        <MessageSquare className="h-4 w-4 text-brand-600" />
        <h3 className="text-sm font-bold text-ink-800">Mobile evidence Q&amp;A</h3>
      </div>
      <p className="mb-3 text-xs text-ink-500">
        Searches only this mobile job's indexed extraction. It never queries Disk or the other mobile platform.
      </p>
      <div className="flex gap-2">
        <Input value={query} onChange={(e) => setQuery(e.target.value)} disabled={!ready || loading}
          placeholder={ready ? "e.g. Show WhatsApp chats with attachments" : "Indexing mobile evidence…"}
          onKeyDown={(e) => { if (e.key === "Enter") void ask(); }} />
        <Button variant="brand" disabled={!ready || !query.trim()} loading={loading} onClick={() => void ask()}>
          <Search className="h-4 w-4" /> Ask
        </Button>
      </div>
      {answer ? <div className="mt-4 rounded-lg bg-ink-50 p-3 text-sm text-ink-800 whitespace-pre-wrap">{answer}</div> : null}
      {items.length > 0 ? (
        <div className="mt-3 space-y-2">
          {items.slice(0, 5).map((item, i) => (
            <div key={String(item.id ?? i)} className="rounded-lg border border-ink-100 px-3 py-2 text-xs text-ink-600">
              <div className="font-semibold text-ink-800">{String(item.file_path ?? item.artifact_id ?? `Evidence ${i + 1}`)}</div>
              <div className="mt-1 line-clamp-3">{String(item.content ?? item.text ?? "Matched indexed mobile evidence")}</div>
            </div>
          ))}
        </div>
      ) : null}
    </Card>
  );
}
