import { useEffect, useState } from "react";
import { GitBranch, Network, FolderTree } from "lucide-react";
import { Spinner } from "../ui";
import { forensicApi } from "../../lib/forensicApi";
import type { Artifact, ArtifactGraph, JobFileTree } from "../../lib/types/forensic";

type Tab = "entities" | "relationships" | "filetree";

function fileTreeFromMetadata(artifact: Artifact, jobId: string): JobFileTree | null {
  const raw = artifact.metadata?.file_tree as
    | { summary?: JobFileTree["summary"]; nodes?: JobFileTree["nodes"]; root?: JobFileTree["root"] }
    | undefined;
  if (!raw) return null;
  return {
    job_id: jobId,
    disk_artifact_id: artifact.id,
    summary: raw.summary ?? {
      total_nodes: 0,
      file_count: 0,
      dir_count: 0,
      interesting_file_count: 0,
    },
    nodes: raw.nodes ?? [],
    root: raw.root ?? null,
  };
}

export function ArtifactGraphPanel({ jobId, artifact }: { jobId: string; artifact: Artifact }) {
  const [tab, setTab] = useState<Tab>("entities");
  const [graph, setGraph] = useState<ArtifactGraph | null>(null);
  const [fileTree, setFileTree] = useState<JobFileTree | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const isDisk = artifact.artifact_type === "disk_image";

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    const graphReq = forensicApi.getArtifactGraph(jobId, artifact.id).catch(() => null);
    const treeReq = isDisk
      ? Promise.resolve(fileTreeFromMetadata(artifact, jobId))
      : forensicApi.getJobFileTree(jobId).catch(() => null);

    Promise.all([graphReq, treeReq])
      .then(([g, tree]) => {
        if (cancelled) return;
        setGraph(g);
        setFileTree(tree);
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : "Graph data unavailable");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, [jobId, artifact.id, artifact.artifact_type, isDisk, artifact.metadata]);

  const entities =
    graph?.entities ?? (artifact.metadata?.entities as ArtifactGraph["entities"] | undefined) ?? [];
  const relationships =
    graph?.relationships ??
    (artifact.metadata?.relationships as ArtifactGraph["relationships"] | undefined) ??
    [];
  const treeNodes = isDisk ? fileTree?.nodes ?? [] : fileTree?.nodes ?? [];

  const tabs: { id: Tab; label: string; icon: typeof Network }[] = [
    { id: "entities", label: `Entities (${entities.length})`, icon: Network },
    { id: "relationships", label: `Relations (${relationships.length})`, icon: GitBranch },
    { id: "filetree", label: `File tree (${treeNodes.length})`, icon: FolderTree },
  ];

  return (
    <div className="mt-4 rounded-lg border border-ink-100 bg-white">
      <div className="flex border-b border-ink-100">
        {tabs.map((t) => (
          <button
            key={t.id}
            type="button"
            onClick={() => setTab(t.id)}
            className={`flex items-center gap-1.5 px-3 py-2 text-xs font-semibold uppercase tracking-wider ${
              tab === t.id ? "border-b-2 border-brand-500 text-brand-700" : "text-ink-400 hover:text-ink-600"
            }`}
          >
            <t.icon className="h-3.5 w-3.5" />
            {t.label}
          </button>
        ))}
      </div>
      <div className="max-h-56 overflow-auto p-3">
        {loading && <Spinner className="py-4" />}
        {error && !loading && <p className="text-sm text-ink-400">{error}</p>}
        {!loading && tab === "entities" && (
          <ul className="space-y-1 text-sm">
            {entities.length === 0 ? (
              <li className="text-ink-400">No entities extracted yet — run Process to enrich.</li>
            ) : (
              entities.map((e) => (
                <li key={e.id} className="flex gap-2 font-mono text-xs">
                  <span className="shrink-0 rounded bg-ink-100 px-1.5 py-0.5 text-ink-500">{e.type}</span>
                  <span className="text-ink-700">{e.label}</span>
                </li>
              ))
            )}
          </ul>
        )}
        {!loading && tab === "relationships" && (
          <ul className="space-y-1 text-sm">
            {relationships.length === 0 ? (
              <li className="text-ink-400">No relationships yet.</li>
            ) : (
              relationships.map((r, i) => (
                <li key={`${r.type}-${i}`} className="font-mono text-xs text-ink-600">
                  <span className="text-brand-600">{r.type}</span> {r.from_id} → {r.to_id}
                  {r.label ? <span className="text-ink-400"> ({r.label})</span> : null}
                </li>
              ))
            )}
          </ul>
        )}
        {!loading && tab === "filetree" && (
          <ul className="space-y-0.5 font-mono text-xs">
            {treeNodes.length === 0 ? (
              <li className="text-ink-400">File tree available after disk processing.</li>
            ) : (
              treeNodes.slice(0, 150).map((n) => (
                <li
                  key={`${n.inode}-${n.path}`}
                  className={n.interesting ? "text-brand-700" : "text-ink-500"}
                >
                  {n.type === "dir" ? "📁" : "📄"} {n.path}
                </li>
              ))
            )}
            {treeNodes.length > 150 && (
              <li className="text-ink-400">…and {treeNodes.length - 150} more paths</li>
            )}
          </ul>
        )}
      </div>
    </div>
  );
}
