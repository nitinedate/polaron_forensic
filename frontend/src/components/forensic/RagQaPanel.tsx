import { useState } from "react";

import { Eraser, MessageSquare, Search, Sparkles } from "lucide-react";

import { Button, Card, Input } from "../ui";
import { stripAxiomBranding } from "../../lib/displayText";
import { forensicApi } from "../../lib/forensicApi";
import { useToast } from "../../lib/toast";

export type RetrievalChunk = {
  id?: string;
  file_path?: string;
  content?: string;
  artifact_id?: string;
  chunk_type?: string;
  score?: number;
  rrf_score?: number;
  rerank_score?: number;
};

type QueryUnderstandResult = {
  dimensions?: string[];
  operating_systems?: string[];
  categories?: string[];
  artifact_ids?: string[];
  intent?: string;
  filters?: Record<string, unknown>;
  sub_questions?: string[];
};

type EnrichmentSnapshot = {
  enriching?: boolean;
  baseline_ready?: boolean;
  artifacts_parsed?: number;
  artifacts_total?: number;
  artifacts_pending?: number;
  rag_chunks?: number;
};

interface RagQaPanelProps {
  jobId: string;
  jobStatus: string;
  enrichment?: EnrichmentSnapshot | null;
  /** Refresh extraction log when a Q&A query starts/finishes. */
  onActivity?: () => void;
}

const INDEXED_STATUSES = new Set([
  "indexed",
  "ready",
  "report_ready",
  "report_generating",
  "reporting",
  "completed",
  "classified",
  "indexing",
  "parsed",
  "artifacts_registered",
]);

function renderAnswer(text: string) {
  const cleaned = stripAxiomBranding(text);
  // Minimal markdown-ish bold support for **terms**
  const parts = cleaned.split(/(\*\*[^*]+\*\*)/g);
  return parts.map((part, i) => {
    if (part.startsWith("**") && part.endsWith("**")) {
      return (
        <strong key={i} className="font-semibold text-ink-900">
          {part.slice(2, -2)}
        </strong>
      );
    }
    return <span key={i}>{part}</span>;
  });
}

export function RagQaPanel({ jobId, jobStatus, enrichment, onActivity }: RagQaPanelProps) {
  const toast = useToast();
  const [query, setQuery] = useState("");
  const [loading, setLoading] = useState(false);
  const [chunks, setChunks] = useState<RetrievalChunk[]>([]);
  const [answer, setAnswer] = useState<string | null>(null);
  const [confidence, setConfidence] = useState<string | null>(null);
  const [facts, setFacts] = useState<Record<string, unknown>>({});
  const [understanding, setUnderstanding] = useState<QueryUnderstandResult | null>(null);
  const [lastQuery, setLastQuery] = useState("");

  const ready = INDEXED_STATUSES.has(jobStatus);
  const enriching = Boolean(enrichment?.enriching);
  const parsedPct =
    enrichment?.artifacts_total && enrichment.artifacts_total > 0
      ? Math.round(((enrichment.artifacts_parsed ?? 0) / enrichment.artifacts_total) * 100)
      : null;

  function clearQa() {
    setQuery("");
    setLastQuery("");
    setAnswer(null);
    setConfidence(null);
    setFacts({});
    setChunks([]);
    setUnderstanding(null);
  }

  async function runQuery() {
    const q = query.trim();
    if (!q) return;
    setLoading(true);
    setLastQuery(q);
    setAnswer(null);
    setConfidence(null);
    setFacts({});
    onActivity?.();
    try {
      const [retrieveRes, understandRes] = await Promise.all([
        forensicApi.retrieve(jobId, { query: q, top_k: 8 }),
        forensicApi.queryUnderstand(jobId, q).catch(() => null),
      ]);
      setChunks(retrieveRes.items ?? []);
      setAnswer(retrieveRes.answer ?? null);
      setConfidence(retrieveRes.confidence ?? null);
      setFacts(retrieveRes.facts ?? {});
      setUnderstanding(understandRes);
      if ((retrieveRes.items ?? []).length === 0 && !retrieveRes.answer) {
        toast.error(
          enriching
            ? "No evidence yet for this question — only part of the disk is parsed so far. Try again later or ask about users, OS, or browser history."
            : "No matching evidence — try re-running Enrich from Inventory"
        );
      }
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Retrieval failed");
      setChunks([]);
      setAnswer(null);
      setUnderstanding(null);
    } finally {
      setLoading(false);
      onActivity?.();
    }
  }

  if (!ready) {
    return (
      <Card className="border-dashed border-ink-200 p-5">
        <div className="flex items-center gap-2 text-ink-500">
          <MessageSquare className="h-4 w-4" />
          <p className="text-sm">
            RAG verification Q&amp;A will appear here once Phase 3 indexing completes.
          </p>
        </div>
      </Card>
    );
  }

  return (
    <Card className="min-w-0 overflow-hidden p-5">
      <div className="mb-4 flex items-center gap-2">
        <Sparkles className="h-4 w-4 text-brand-600" />
        <h3 className="text-sm font-bold text-ink-800">RAG Verification — Ask &amp; Verify</h3>
      </div>
      <p className="mb-4 text-xs text-ink-500">
        Ask in plain language. Answers are grounded only in indexed evidence for this job — nothing
        is invented.
      </p>
      {enriching ? (
        <div className="mb-4 rounded-lg border border-amber-200 bg-amber-50/60 px-3 py-2 text-xs text-amber-900">
          Background enrichment is running
          {parsedPct != null ? ` (~${parsedPct}% of files parsed)` : ""}. Q&amp;A works on the
          baseline index now; questions about files still being parsed may return no answer yet.
          Searches can take 1–2 minutes while the GPU is also embedding new chunks.
        </div>
      ) : null}

      <div className="flex flex-wrap items-stretch gap-2">
        <Input
          className="min-w-[12rem] flex-1"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="e.g. Which users used this laptop?"
          onKeyDown={(e) => {
            if (e.key === "Enter") void runQuery();
          }}
          disabled={loading}
        />
        <Button
          className="shrink-0"
          variant="brand"
          loading={loading}
          onClick={() => void runQuery()}
        >
          <Search className="h-4 w-4" /> Ask
        </Button>
        <Button
          className="shrink-0"
          variant="outline"
          disabled={loading || (!query.trim() && !lastQuery && !answer && chunks.length === 0)}
          onClick={clearQa}
          title="Clear question and answer"
        >
          <Eraser className="h-4 w-4" /> Clear
        </Button>
      </div>

      {understanding && lastQuery && (
        <div className="mt-3 flex flex-wrap gap-2 text-xs">
          {(understanding.sub_questions?.length ?? 0) > 1 ? (
            understanding.sub_questions!.map((sub) => (
              <span key={sub} className="rounded bg-emerald-50 px-2 py-0.5 text-emerald-800">
                Sub-question: {sub}
              </span>
            ))
          ) : null}
          {understanding.operating_systems?.map((os) => (
            <span key={os} className="rounded bg-brand-50 px-2 py-0.5 text-brand-700">
              OS: {os}
            </span>
          ))}
          {understanding.categories?.map((cat) => (
            <span key={cat} className="rounded bg-indigo-50 px-2 py-0.5 text-indigo-700">
              {stripAxiomBranding(cat)}
            </span>
          ))}
        </div>
      )}

      {loading ? (
        <p className="mt-4 text-sm text-ink-500">
          {enriching
            ? "Searching indexed evidence… this may take up to 2 minutes while background enrichment runs."
            : "Searching indexed evidence…"}
        </p>
      ) : null}

      {lastQuery && !loading && (
        <div className="mt-4 space-y-4">
          {answer ? (
            <div className="rounded-lg border border-brand-200 bg-brand-50/40 p-4">
              <div className="mb-2 flex items-center justify-between gap-2">
                <p className="text-xs font-semibold uppercase tracking-wider text-brand-700">Answer</p>
                {confidence ? (
                  <span className="rounded bg-white px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-ink-500">
                    confidence: {confidence}
                  </span>
                ) : null}
              </div>
              <p className="whitespace-pre-wrap text-sm leading-relaxed text-ink-800">{renderAnswer(answer)}</p>
              {Array.isArray(facts.users) && (facts.users as string[]).length > 0 ? (
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {(facts.users as string[]).map((u) => (
                    <span
                      key={u}
                      className="rounded-md border border-brand-200 bg-white px-2 py-1 text-xs font-semibold text-brand-800"
                    >
                      {u}
                    </span>
                  ))}
                </div>
              ) : null}
            </div>
          ) : chunks.length > 0 ? (
            <div className="rounded-lg border border-ink-200 bg-ink-50/50 p-4">
              <p className="text-xs font-semibold uppercase tracking-wider text-ink-500">Answer</p>
              <p className="mt-2 text-sm text-ink-600">
                Evidence was found but no summary could be composed. Review the supporting evidence
                below, or try a more specific question (e.g. users, OS version, browser URLs).
              </p>
            </div>
          ) : null}

          {chunks.length > 0 ? (
            <div className="min-w-0">
              <p className="mb-2 text-xs font-semibold uppercase tracking-wider text-ink-400">
                Supporting evidence ({chunks.length})
              </p>
              <div className="space-y-2">
                {chunks.map((chunk, i) => {
                  const score = chunk.rerank_score ?? chunk.rrf_score ?? chunk.score ?? 0;
                  return (
                    <div
                      key={chunk.id ?? i}
                      className="min-w-0 overflow-hidden rounded-lg border border-ink-100 bg-ink-50/50 p-3"
                    >
                      <div className="mb-1 flex min-w-0 flex-wrap items-center gap-2 text-xs">
                        <span className="shrink-0 font-semibold text-brand-700">
                          #{i + 1}
                          {typeof score === "number" ? ` · ${(score as number).toFixed(3)}` : ""}
                        </span>
                        {chunk.file_path ? (
                          <span className="min-w-0 break-all font-mono text-ink-500" title={chunk.file_path}>
                            {chunk.file_path}
                          </span>
                        ) : null}
                      </div>
                      <p className="whitespace-pre-wrap break-words break-all text-xs leading-relaxed text-ink-600">
                        {(stripAxiomBranding(chunk.content ?? "")).slice(0, 400)}
                        {(chunk.content ?? "").length > 400 ? "…" : ""}
                      </p>
                    </div>
                  );
                })}
              </div>
            </div>
          ) : null}
        </div>
      )}
    </Card>
  );
}
