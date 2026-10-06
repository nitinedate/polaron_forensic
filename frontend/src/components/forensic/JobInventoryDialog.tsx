import { useCallback, useEffect, useState } from "react";
import { BarChart3, RefreshCw, Sparkles } from "lucide-react";

import { Button, Modal, Spinner } from "../ui";
import { forensicApi } from "../../lib/forensicApi";
import { useToast } from "../../lib/toast";
import type { JobInventory, LocalQueueInventory } from "../../lib/types/forensic";

function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 ** 2) return `${(n / 1024).toFixed(1)} KB`;
  if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MB`;
  return `${(n / 1024 ** 3).toFixed(2)} GB`;
}

function StatCard({ label, value, hint }: { label: string; value: string | number; hint?: string }) {
  return (
    <div className="rounded-lg border border-ink-100 bg-ink-50/60 px-3 py-2.5">
      <div className="text-[10px] font-semibold uppercase tracking-wider text-ink-400">{label}</div>
      <div className="mt-0.5 text-lg font-bold tabular-nums text-ink-900">{value}</div>
      {hint && <div className="mt-0.5 text-[11px] text-ink-500">{hint}</div>}
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div>
      <h4 className="mb-2 text-xs font-bold uppercase tracking-wider text-ink-500">{title}</h4>
      {children}
    </div>
  );
}

interface JobInventoryDialogProps {
  jobId: string;
  open: boolean;
  onClose: () => void;
  localQueue?: LocalQueueInventory;
}

export function JobInventoryDialog({ jobId, open, onClose, localQueue }: JobInventoryDialogProps) {
  const toast = useToast();
  const [loading, setLoading] = useState(false);
  const [enriching, setEnriching] = useState(false);
  const [continuing, setContinuing] = useState(false);
  const [inventory, setInventory] = useState<JobInventory | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const data = await forensicApi.getJobInventory(jobId);
      setInventory(data);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to load job inventory");
    } finally {
      setLoading(false);
    }
  }, [jobId, toast]);

  useEffect(() => {
    if (open) void load();
  }, [open, load]);

  async function runContinueBatches() {
    setContinuing(true);
    try {
      await forensicApi.continuePipelineBatches(jobId);
      toast.success("Next parallel extract + GPU index batches queued");
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to queue batch pipeline");
    } finally {
      setContinuing(false);
    }
  }

  async function runRagEnrich() {
    setEnriching(true);
    try {
      await forensicApi.enrichJob(jobId);
      toast.success("RAG enrichment queued — refresh inventory in a minute");
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to queue RAG enrichment");
    } finally {
      setEnriching(false);
    }
  }

  const topTypes = inventory
    ? Object.entries(inventory.artifacts.by_type)
        .sort((a, b) => b[1] - a[1])
        .slice(0, 8)
    : [];

  return (
    <Modal
      open={open}
      onClose={onClose}
      title="Job inventory"
      size="lg"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            Close
          </Button>
          <Button variant="outline" loading={continuing} onClick={() => void runContinueBatches()}>
            Continue next batches
          </Button>
          <Button variant="outline" loading={enriching} onClick={() => void runRagEnrich()}>
            <Sparkles className="h-4 w-4" /> Run RAG enrichment
          </Button>
          <Button variant="brand" loading={loading} onClick={() => void load()}>
            <RefreshCw className="h-4 w-4" /> Refresh
          </Button>
        </>
      }
    >
      {loading && !inventory ? (
        <Spinner className="py-10" />
      ) : inventory ? (
        <div className="space-y-5">
          <div className="flex flex-wrap items-center gap-2 text-sm text-ink-600">
            <span>
              Status: <strong className="text-ink-800">{inventory.job_status}</strong>
            </span>
            <span className="text-ink-300">·</span>
            <span>
              Progress: <strong className="text-ink-800">{inventory.progress_pct}%</strong>
            </span>
            <span className="text-ink-300">·</span>
            <span className="text-xs text-ink-400">
              Updated {new Date(inventory.generated_at).toLocaleString()}
            </span>
          </div>

          {localQueue && localQueue.total > 0 && (
            <Section title="Browser upload queue">
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
                <StatCard label="In queue" value={localQueue.total} hint={`${localQueue.queued} waiting`} />
                <StatCard label="Uploaded" value={localQueue.done} />
                <StatCard label="Failed" value={localQueue.failed} />
                <StatCard label="Queue size" value={formatBytes(localQueue.total_bytes)} />
              </div>
            </Section>
          )}

          <Section title="Evidence files (server)">
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <StatCard label="Total files" value={inventory.files.total} />
              <StatCard label="Storage" value={formatBytes(inventory.files.total_bytes)} />
              <StatCard label="Evidence groups" value={inventory.files.evidence_groups} />
              <StatCard
                label="Completed uploads"
                value={inventory.files.by_status?.completed ?? inventory.files.by_status?.done ?? inventory.files.extracted ?? 0}
              />
            </div>
          </Section>

          <Section title="Disk index">
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <StatCard label="Indexed files" value={inventory.disk_index.file_count} />
              <StatCard label="Directories" value={inventory.disk_index.dir_count} />
              <StatCard label="Interesting paths" value={inventory.disk_index.interesting_file_count} />
              <StatCard label="Tree nodes" value={inventory.disk_index.total_nodes} />
            </div>
          </Section>

          <Section title="Artifacts & entities">
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <StatCard label="Artifacts (DB)" value={inventory.artifacts.total} />
              <StatCard
                label="Annotated"
                value={
                  inventory.rag?.artifacts_annotated ??
                  inventory.artifacts_annotated ??
                  "—"
                }
              />
              <StatCard
                label="Entities (DB)"
                value={
                  inventory.rag?.postgres_entities ??
                  inventory.postgres_entities ??
                  "—"
                }
              />
              <StatCard
                label="Entities (Neo4j)"
                value={inventory.neo4j.available ? inventory.neo4j.entities : "—"}
                hint={inventory.neo4j.available ? undefined : "Neo4j unavailable"}
              />
            </div>
            <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-2">
              <StatCard label="Artifact categories" value={inventory.artifacts.category_total} />
              <StatCard label="Ontology nodes" value={inventory.neo4j.available ? inventory.neo4j.ontology_nodes : "—"} />
            </div>
            {topTypes.length > 0 && (
              <ul className="mt-2 max-h-28 overflow-y-auto rounded-lg border border-ink-100 text-xs text-ink-600">
                {topTypes.map(([type, count]) => (
                  <li key={type} className="flex justify-between border-b border-ink-50 px-3 py-1.5 last:border-0">
                    <span className="truncate font-mono">{type}</span>
                    <span className="ml-2 shrink-0 font-semibold tabular-nums">{count}</span>
                  </li>
                ))}
              </ul>
            )}
          </Section>

          <Section title="RAG — chunks & embeddings">
            {inventory.rag.gpu_enabled && (
              <p className="mb-2 rounded-md border border-emerald-200 bg-emerald-50 px-3 py-2 text-xs font-semibold text-emerald-800">
                Embedding device: {inventory.rag.embedding_device ?? "GPU"}
              </p>
            )}
            {inventory.rag.extract_coverage && inventory.rag.extract_coverage.pending > 0 && (
              <p className="mb-2 text-xs text-ink-600">
                Extract coverage: {inventory.rag.extract_coverage.extracted.toLocaleString()} /{" "}
                {inventory.rag.extract_coverage.interesting_total.toLocaleString()} interesting paths (
                {inventory.rag.extract_coverage.pending.toLocaleString()} pending, batch cap{" "}
                {inventory.rag.extract_coverage.batch_cap.toLocaleString()})
                {inventory.rag.extract_coverage.pending > 0 && inventory.job_status === "indexed" && (
                  <> — click <strong>Continue next batches</strong> below to process the rest.</>
                )}
              </p>
            )}
            {inventory.opensearch.chunks === 0 && inventory.rag.chunks_indexed === 0 && (
              <p className="mb-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-900">
                No chunks or embeddings indexed — AI Report retrieval will be empty. Click{" "}
                <strong>Run RAG enrichment</strong> below (no re-carve needed).
              </p>
            )}
            {inventory.opensearch.chunks > 0 && inventory.opensearch.embeddings === 0 && (
              <p className="mb-2 rounded-lg border border-amber-200 bg-amber-50 px-3 py-2 text-xs text-amber-900">
                Chunks exist but embeddings are 0 — re-run <strong>RAG enrichment</strong> after rebuilding
                the worker (embedding vectors require OpenSearch k-NN index).
              </p>
            )}
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <StatCard
                label="Chunks (OpenSearch)"
                value={inventory.opensearch.available ? inventory.opensearch.chunks : "—"}
                hint={inventory.opensearch.available ? undefined : "OpenSearch unavailable"}
              />
              <StatCard
                label="Embeddings (OpenSearch)"
                value={inventory.opensearch.available ? inventory.opensearch.embeddings : "—"}
                hint={
                  inventory.opensearch.embedding_coverage_pct
                    ? `${inventory.opensearch.embedding_coverage_pct}% of chunks`
                    : undefined
                }
              />
              <StatCard
                label="Embeddings (DB)"
                value={inventory.rag.embeddings_indexed}
                hint={
                  inventory.rag.embedding_coverage_pct
                    ? `${inventory.rag.embedding_coverage_pct}% coverage · ${inventory.rag.artifacts_enriched} artifacts`
                    : `${inventory.rag.artifacts_enriched} artifacts enriched`
                }
              />
              <StatCard
                label="Chunks (DB)"
                value={inventory.rag.chunks_indexed}
              />
            </div>
            <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-4">
              <StatCard
                label="Encyclopedia chunks"
                value={inventory.rag.encyclopedia_chunks ?? "—"}
                hint="Shared knowledge index"
              />
              <StatCard
                label="Evidence chunks"
                value={inventory.rag.evidence_chunks ?? inventory.rag.chunks_indexed}
              />
              <StatCard label="Parsed artifacts" value={inventory.rag.parsed_artifacts ?? inventory.artifacts.parsed ?? "—"} />
              <StatCard label="OCR artifacts" value={inventory.rag.ocr_artifacts ?? inventory.artifacts.ocr_done ?? "—"} />
            </div>
            <div className="mt-2 grid grid-cols-2 gap-2 sm:grid-cols-4">
              <StatCard
                label="Ollama vectors"
                value={Math.max(inventory.opensearch.ollama_embeddings, inventory.rag.ollama_embeddings)}
              />
              <StatCard
                label="Hash fallback"
                value={Math.max(inventory.opensearch.hash_embeddings, inventory.rag.hash_embeddings)}
              />
              <StatCard
                label="Artifacts indexed"
                value={inventory.opensearch.available ? inventory.opensearch.artifacts : "—"}
              />
              <StatCard label="Neo4j chunks" value={inventory.neo4j.available ? inventory.neo4j.chunks : "—"} />
            </div>
          </Section>

          <Section title="Neo4j graph">
            {inventory.neo4j.available ? (
              <div className="grid grid-cols-2 gap-2 sm:grid-cols-5">
                <StatCard label="Artifacts" value={inventory.neo4j.artifacts} />
                <StatCard label="Chunks" value={inventory.neo4j.chunks} />
                <StatCard label="Entities" value={inventory.neo4j.entities} />
                <StatCard label="Relationships" value={inventory.neo4j.relationships} />
                <StatCard label="OS artifacts" value={inventory.opensearch.artifacts} />
              </div>
            ) : (
              <p className="text-sm text-ink-500">
                Neo4j is not reachable{inventory.neo4j.error ? `: ${inventory.neo4j.error}` : ""}. Counts appear after
                RAG enrichment runs.
              </p>
            )}
          </Section>

          <Section title="Pipeline">
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
              <StatCard label="Checkpoints" value={inventory.pipeline.checkpoints} />
              <StatCard label="Extraction logs" value={inventory.pipeline.extraction_logs} />
            </div>
          </Section>
        </div>
      ) : (
        <p className="text-sm text-ink-500">No inventory data available.</p>
      )}
    </Modal>
  );
}

interface JobInventoryButtonProps {
  jobId: string;
  localQueue?: LocalQueueInventory;
  disabled?: boolean;
}

export function JobInventoryButton({ jobId, localQueue, disabled }: JobInventoryButtonProps) {
  const [open, setOpen] = useState(false);

  return (
    <>
      <Button variant="outline" disabled={disabled} onClick={() => setOpen(true)}>
        <BarChart3 className="h-4 w-4" /> Check inventory
      </Button>
      <JobInventoryDialog jobId={jobId} open={open} onClose={() => setOpen(false)} localQueue={localQueue} />
    </>
  );
}
