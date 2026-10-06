import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { FolderOpen, FolderPlus, ImageIcon, Play, RefreshCw, Upload, X } from "lucide-react";
import { Badge, Button, Card, PageHeader, Spinner } from "../../components/ui";
import { forensicApi } from "../../lib/forensicApi";
import { useToast } from "../../lib/toast";

type TreeNode = {
  node_id: string;
  parent_node_id?: string | null;
  node_type: string;
  root_label?: string;
  relative_path?: string;
  name: string;
  absolute_path?: string | null;
  host_path?: string | null;
  drive?: string;
  browse_path?: string;
  size_bytes?: number | null;
  mime_type?: string | null;
  eligible?: boolean;
  mounted?: boolean;
};

type Profile = {
  id: string;
  label: string;
  description?: string;
  stages?: string;
};

type ManifestItem = TreeNode & {
  selected: boolean;
  selection_state: string;
  source_root?: string;
  source_object_uri?: string | null;
};

const ELIGIBLE_IMAGE_EXTS = new Set([
  ".png",
  ".jpg",
  ".jpeg",
  ".gif",
  ".webp",
  ".bmp",
  ".tif",
  ".tiff",
  ".heic",
  ".heif",
  ".pdf",
]);

function isEligibleImageName(name: string) {
  const i = name.lastIndexOf(".");
  return i >= 0 && ELIGIBLE_IMAGE_EXTS.has(name.slice(i).toLowerCase());
}

type AddedRoot = {
  key: string;
  label: string;
  host_path?: string;
  drive?: string;
  browse_path?: string;
};

function formatBytes(n?: number | null) {
  if (n == null || Number.isNaN(n)) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

function rootKey(opts: { host_path?: string; drive?: string; browse_path?: string }) {
  if (opts.host_path) return `abs:${opts.host_path}`;
  return `drv:${opts.drive || ""}:${opts.browse_path || ""}`;
}

export function ImageEvidencePage() {
  const toast = useToast();
  const navigate = useNavigate();
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [profile, setProfile] = useState("STANDARD");
  const [nodes, setNodes] = useState<TreeNode[]>([]);
  const [drive, setDrive] = useState("");
  const [browsePath, setBrowsePath] = useState("");
  const [pastePath, setPastePath] = useState("");
  const [displayPath, setDisplayPath] = useState("This PC");
  const [addedRoots, setAddedRoots] = useState<AddedRoot[]>([]);
  const [files, setFiles] = useState<Record<string, ManifestItem>>({});
  const [focus, setFocus] = useState<TreeNode | null>(null);
  const [loading, setLoading] = useState(true);
  const [scanning, setScanning] = useState(false);
  const [busy, setBusy] = useState(false);
  const [repoError, setRepoError] = useState<string | null>(null);
  const [mountHint, setMountHint] = useState<string | null>(null);
  const [dragOver, setDragOver] = useState(false);
  const [uploadPct, setUploadPct] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const folderInputRef = useRef<HTMLInputElement>(null);

  const fileList = useMemo(() => Object.values(files), [files]);
  const selectedList = useMemo(() => fileList.filter((s) => s.selected), [fileList]);
  const selectedBytes = useMemo(
    () => selectedList.reduce((acc, s) => acc + (Number(s.size_bytes) || 0), 0),
    [selectedList]
  );

  const ensureSession = useCallback(async () => {
    if (sessionId) return sessionId;
    const res = await forensicApi.createRagSelectionSession({ processing_profile: profile });
    const id = String((res.session as { id?: string })?.id || "");
    setSessionId(id);
    return id;
  }, [sessionId, profile]);

  const loadTree = useCallback(
    async (opts?: { drive?: string; path?: string; host_path?: string }) => {
      setLoading(true);
      try {
        const tree = await forensicApi.getRagRepositoryTree({
          drive: opts?.drive ?? drive,
          path: opts?.path ?? browsePath,
          host_path: opts?.host_path,
        });
        setNodes((tree.nodes || []) as TreeNode[]);
        setRepoError(tree.error || null);
        setMountHint(tree.mount_hint || null);
        setDisplayPath(tree.display_path || "This PC");
        if (tree.drive_root != null) setDrive(String(tree.drive_root));
        if (tree.current_path != null) setBrowsePath(String(tree.current_path));
      } catch (e: unknown) {
        toast.error(e instanceof Error ? e.message : "Failed to browse host paths");
      } finally {
        setLoading(false);
      }
    },
    [browsePath, drive, toast]
  );

  useEffect(() => {
    void (async () => {
      try {
        const prof = await forensicApi.listRagProfiles();
        setProfiles((prof.profiles || []) as Profile[]);
      } catch {
        /* ignore */
      }
      if (!sessionId) {
        try {
          const res = await forensicApi.createRagSelectionSession({ processing_profile: profile });
          setSessionId(String((res.session as { id?: string })?.id || ""));
        } catch {
          /* schema may apply on first start */
        }
      }
      await loadTree({ drive: "", path: "" });
    })();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function openNode(node: TreeNode) {
    if (node.node_type !== "folder") {
      setFocus(node);
      return;
    }
    if (node.drive && !node.browse_path && node.node_id.startsWith("drive:")) {
      await loadTree({ drive: node.drive, path: "" });
      return;
    }
    if (node.host_path || node.absolute_path) {
      await loadTree({ host_path: node.host_path || node.absolute_path || undefined });
      return;
    }
    await loadTree({ drive: node.drive || drive, path: node.browse_path || "" });
  }

  async function goUp() {
    if (pastePath) setPastePath("");
    if (!browsePath) {
      await loadTree({ drive: "", path: "" });
      return;
    }
    const parts = browsePath.split("/").filter(Boolean);
    parts.pop();
    await loadTree({ drive, path: parts.join("/") });
  }

  async function scanAndMergeRoot(root: AddedRoot, selectNew = true) {
    setScanning(true);
    try {
      const res = await forensicApi.getRagRepositoryListFiles({
        host_path: root.host_path,
        drive: root.drive,
        path: root.browse_path,
      });
      if (res.error) {
        toast.error(String(res.error));
        return;
      }
      const incoming = (res.files || []) as TreeNode[];
      if (incoming.length === 0) {
        toast.error("No eligible images/PDFs found in that folder");
      }
      setFiles((prev) => {
        const next = { ...prev };
        for (const f of incoming) {
          const existing = next[f.node_id];
          next[f.node_id] = {
            ...f,
            selected: existing ? existing.selected : selectNew,
            selection_state: existing
              ? existing.selection_state
              : selectNew
                ? "checked"
                : "unchecked",
            source_root: root.key,
            relative_path: f.relative_path || f.name,
            name: f.name,
          };
        }
        return next;
      });
      if (res.truncated) {
        toast.error("File list truncated at limit — narrow folders or process in batches");
      }
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to list files");
    } finally {
      setScanning(false);
    }
  }

  async function addRoot(opts: {
    label: string;
    host_path?: string;
    drive?: string;
    browse_path?: string;
  }) {
    const key = rootKey(opts);
    if (addedRoots.some((r) => r.key === key)) {
      toast.error("Folder already added");
      return;
    }
    const root: AddedRoot = {
      key,
      label: opts.label,
      host_path: opts.host_path,
      drive: opts.drive,
      browse_path: opts.browse_path || "",
    };
    setAddedRoots((prev) => [...prev, root]);
    await scanAndMergeRoot(root, true);
  }

  async function addCurrentFolder() {
    const host =
      displayPath && (displayPath.includes("\\") || displayPath.startsWith("/"))
        ? displayPath
        : undefined;
    // Prefer resolved browse location from drive+path when no absolute paste
    if (drive) {
      const label = displayPath || `${drive}:/${browsePath}`;
      await addRoot({
        label,
        drive,
        browse_path: browsePath,
        host_path: host && !drive ? host : undefined,
      });
      return;
    }
    if (host) {
      await addRoot({ label: host, host_path: host });
      return;
    }
    toast.error("Open a folder in the browser first, or paste a path");
  }

  async function addPastedPath() {
    const raw = pastePath.trim();
    if (!raw) return;
    await addRoot({ label: raw, host_path: raw });
    await loadTree({ host_path: raw });
  }

  function removeRoot(key: string) {
    setAddedRoots((prev) => prev.filter((r) => r.key !== key));
    setFiles((prev) => {
      const next: Record<string, ManifestItem> = {};
      for (const [id, item] of Object.entries(prev)) {
        if (item.source_root !== key) next[id] = item;
      }
      return next;
    });
  }

  function toggleFile(nodeId: string, checked: boolean) {
    setFiles((prev) => {
      const item = prev[nodeId];
      if (!item) return prev;
      return {
        ...prev,
        [nodeId]: {
          ...item,
          selected: checked,
          selection_state: checked ? "checked" : "unchecked",
        },
      };
    });
  }

  async function ingestBrowserFiles(list: FileList | File[]) {
    const incoming = Array.from(list).filter((f) => isEligibleImageName(f.name));
    if (!incoming.length) {
      toast.error("No images or PDFs in that selection");
      return;
    }
    setBusy(true);
    const rootKey = `upload:${Date.now()}`;
    try {
      const sid = await ensureSession();
      setAddedRoots((prev) => [
        ...prev,
        { key: rootKey, label: `This computer (${incoming.length} file${incoming.length === 1 ? "" : "s"})` },
      ]);
      for (let i = 0; i < incoming.length; i++) {
        const file = incoming[i];
        const rel =
          (file as File & { webkitRelativePath?: string }).webkitRelativePath || file.name;
        setUploadPct(`${i + 1}/${incoming.length}: ${file.name}`);
        const res = await forensicApi.uploadRagSessionFile(sid, file, rel, (pct) => {
          setUploadPct(`${i + 1}/${incoming.length}: ${file.name} (${pct}%)`);
        });
        const items = (res.items || res.accepted || []) as Array<Record<string, unknown>>;
        setFiles((prev) => {
          const next = { ...prev };
          for (const raw of items) {
            const nodeId = String(raw.node_id || "");
            if (!nodeId) continue;
            const meta = (raw.metadata && typeof raw.metadata === "object"
              ? raw.metadata
              : {}) as Record<string, unknown>;
            next[nodeId] = {
              node_id: nodeId,
              node_type: String(raw.node_type || "image"),
              name: String(raw.name || file.name),
              relative_path: String(raw.relative_path || rel),
              root_label: String(raw.root_label || "This computer"),
              size_bytes: typeof raw.size_bytes === "number" ? raw.size_bytes : file.size,
              mime_type: raw.mime_type ? String(raw.mime_type) : file.type || null,
              selected: true,
              selection_state: "checked",
              source_root: rootKey,
              source_object_uri: String(raw.source_object_uri || meta.source_object_uri || ""),
              absolute_path: meta.source_absolute_path ? String(meta.source_absolute_path) : null,
              host_path: meta.source_absolute_path ? String(meta.source_absolute_path) : null,
            };
          }
          return next;
        });
      }
      toast.success(`Uploaded ${incoming.length} file(s) from this computer`);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Upload failed");
      setAddedRoots((prev) => prev.filter((r) => r.key !== rootKey));
    } finally {
      setUploadPct(null);
      setBusy(false);
    }
  }

  function selectAllFiles(checked: boolean) {
    setFiles((prev) => {
      const next: Record<string, ManifestItem> = {};
      for (const [id, item] of Object.entries(prev)) {
        next[id] = {
          ...item,
          selected: checked,
          selection_state: checked ? "checked" : "unchecked",
        };
      }
      return next;
    });
  }

  async function syncManifest() {
    const sid = await ensureSession();
    const items = selectedList.map((s) => ({
      node_id: s.node_id,
      parent_node_id: s.parent_node_id || null,
      node_type: s.node_type,
      root_label: s.root_label || null,
      relative_path: s.relative_path || s.name,
      name: s.name,
      selected: true,
      selection_state: "checked",
      size_bytes: s.size_bytes ?? null,
      mime_type: s.mime_type ?? null,
      metadata: {
        drive: s.drive || null,
        browse_path: s.browse_path || s.relative_path || null,
        source_absolute_path: s.absolute_path || s.host_path || null,
        source_object_uri: s.source_object_uri || null,
        source_root: s.source_root || null,
      },
    }));
    await forensicApi.putRagManifest(sid, { items, processing_profile: profile });
    return sid;
  }

  async function startProcessing() {
    if (selectedList.length === 0) {
      toast.error("Select at least one image or PDF");
      return;
    }
    setBusy(true);
    try {
      const sid = await syncManifest();
      const source_paths: Record<string, string> = {};
      for (const s of selectedList) {
        const p = s.absolute_path || s.host_path || s.source_object_uri;
        if (p) source_paths[s.node_id] = p;
      }
      const res = await forensicApi.startRagImageJob(sid, {
        processing_profile: profile,
        source_paths,
      });
      toast.success(`Started image evidence job (${res.registered}/${res.selected} registered)`);
      if (res.job_id) navigate(`/forensic/jobs/${res.job_id}`);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to start processing");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="space-y-4">
      <PageHeader
        title="Image evidence"
        subtitle="Upload images and PDFs from this computer — works from any browser. Server disk browse stays available when you are on the examiner workstation."
        actions={
          <div className="flex flex-wrap items-center gap-2">
            <Button variant="ghost" onClick={() => void loadTree({ drive: "", path: "" })}>
              <RefreshCw className="h-4 w-4" /> Drives
            </Button>
            <Button disabled={busy || selectedList.length === 0} onClick={() => void startProcessing()}>
              <Play className="h-4 w-4" /> {busy ? "Starting…" : "Start processing"}
            </Button>
          </div>
        }
      />

      {(repoError || mountHint) && (
        <Card className="border-amber-200 bg-amber-50 p-3 text-sm text-amber-900">
          {repoError}
          {mountHint ? <div className="mt-1 text-amber-800">{mountHint}</div> : null}
        </Card>
      )}

      <div className="flex flex-wrap items-center gap-3 text-sm">
        <label className="flex items-center gap-2">
          Profile
          <select
            className="rounded-xl border border-ink-300 bg-white/90 px-2 py-1 shadow-panel"
            value={profile}
            onChange={(e) => setProfile(e.target.value)}
            title="Controls OCR/embed intensity only — all agentic agents still run"
          >
            {(profiles.length ? profiles : [{ id: "STANDARD", label: "Standard" }]).map((p) => (
              <option key={p.id} value={p.id}>
                {p.label}
              </option>
            ))}
          </select>
        </label>
        <Badge tone="indigo">{selectedList.length} selected</Badge>
        <Badge tone="neutral">{fileList.length} files</Badge>
        <Badge tone="neutral">{formatBytes(selectedBytes)}</Badge>
        {scanning && <span className="text-xs text-slate-500">Scanning folders…</span>}
        {sessionId && <span className="text-xs text-slate-400">session {sessionId.slice(0, 8)}…</span>}
      </div>

      <input
        ref={fileInputRef}
        type="file"
        accept="image/*,.pdf"
        multiple
        className="hidden"
        onChange={(e) => {
          if (e.target.files?.length) void ingestBrowserFiles(e.target.files);
          e.target.value = "";
        }}
      />
      <input
        ref={folderInputRef}
        type="file"
        multiple
        // @ts-expect-error webkitdirectory is non-standard
        webkitdirectory=""
        className="hidden"
        onChange={(e) => {
          if (e.target.files?.length) void ingestBrowserFiles(e.target.files);
          e.target.value = "";
        }}
      />

      <div
        className={`rounded-2xl border-2 border-dashed px-4 py-6 text-center ${
          dragOver ? "border-brand-500 bg-brand-50" : "border-ink-300 bg-white/70"
        }`}
        onDragOver={(e) => {
          e.preventDefault();
          setDragOver(true);
        }}
        onDragLeave={() => setDragOver(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragOver(false);
          if (e.dataTransfer.files?.length) void ingestBrowserFiles(e.dataTransfer.files);
        }}
      >
        <p className="text-sm font-medium text-ink-800">Upload from this computer</p>
        <p className="mt-1 text-xs text-ink-500">
          Drag images or PDFs here, or pick files / a folder. Works from any client that can open this app.
        </p>
        <div className="mt-3 flex flex-wrap justify-center gap-2">
          <Button variant="ghost" disabled={busy} onClick={() => fileInputRef.current?.click()}>
            <Upload className="h-4 w-4" /> Choose files
          </Button>
          <Button variant="ghost" disabled={busy} onClick={() => folderInputRef.current?.click()}>
            <FolderOpen className="h-4 w-4" /> Choose folder
          </Button>
        </div>
        {uploadPct ? <p className="mt-2 text-xs text-brand-700">{uploadPct}</p> : null}
      </div>

      <div className="flex flex-wrap gap-2">
        <input
          className="min-w-[16rem] flex-1 rounded-xl border border-ink-300 bg-white/90 px-3 py-2 text-sm shadow-panel"
          placeholder="Optional server path — e.g. E:\Evidence\Photos (examiner workstation only)"
          value={pastePath}
          onChange={(e) => setPastePath(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") void addPastedPath();
          }}
        />
        <Button variant="ghost" onClick={() => void addPastedPath()}>
          <FolderPlus className="h-4 w-4" /> Add server path
        </Button>
        <Button variant="ghost" onClick={() => void addCurrentFolder()}>
          <FolderPlus className="h-4 w-4" /> Add current folder
        </Button>
      </div>

      {addedRoots.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {addedRoots.map((r) => (
            <span
              key={r.key}
              className="inline-flex max-w-full items-center gap-1 rounded-full border border-ink-300 bg-brand-50/80 px-3 py-1 text-xs text-ink-700 shadow-panel"
            >
              <FolderOpen className="h-3.5 w-3.5 shrink-0" />
              <span className="truncate" title={r.label}>
                {r.label}
              </span>
              <button
                type="button"
                className="rounded p-0.5 hover:bg-slate-200"
                aria-label={`Remove ${r.label}`}
                onClick={() => removeRoot(r.key)}
              >
                <X className="h-3.5 w-3.5" />
              </button>
            </span>
          ))}
        </div>
      )}

      <div className="grid gap-4 lg:grid-cols-[minmax(0,0.85fr)_minmax(0,1.15fr)]">
        <Card className="min-h-[18rem] overflow-hidden p-0">
          <div className="flex items-center justify-between gap-2 border-b border-ink-300 bg-brand-50/40 px-3 py-2.5 text-sm font-medium text-ink-700">
            <span className="flex items-center gap-2 truncate">
              <FolderOpen className="h-4 w-4 shrink-0 text-brand-600" /> {displayPath}
            </span>
            <Button variant="ghost" className="shrink-0 text-xs" onClick={() => void goUp()}>
              Up
            </Button>
          </div>
          <div className="max-h-[36vh] overflow-auto bg-white/50 py-1">
            {loading ? (
              <div className="flex justify-center py-12">
                <Spinner />
              </div>
            ) : nodes.length === 0 ? (
              <p className="p-4 text-sm text-ink-500">No entries. Refresh mounts or paste a path.</p>
            ) : (
              nodes.map((node) => {
                const isFolder = node.node_type === "folder";
                return (
                  <div
                    key={node.node_id}
                    className="mx-1 flex items-center gap-2 rounded-xl px-3 py-1.5 text-sm hover:bg-brand-50/70"
                  >
                    <span className="w-4 text-center text-ink-400">{isFolder ? "▸" : "·"}</span>
                    <button
                      type="button"
                      className="min-w-0 flex-1 truncate text-left"
                      onClick={() => void openNode(node)}
                    >
                      {node.name}
                      {node.mounted === false ? (
                        <span className="ml-2 text-xs text-amber-600">not mounted</span>
                      ) : null}
                    </button>
                    {!isFolder && (
                      <span className="shrink-0 text-xs text-ink-400">{formatBytes(node.size_bytes)}</span>
                    )}
                  </div>
                );
              })
            )}
          </div>
        </Card>

        <Card className="min-h-[18rem] overflow-hidden p-0">
          <div className="flex items-center gap-2 border-b border-ink-300 bg-brand-50/40 px-3 py-2.5 text-sm font-medium text-ink-700">
            <ImageIcon className="h-4 w-4 text-brand-600" /> Preview
          </div>
          <div className="space-y-3 bg-white/50 p-4">
            {focus ? (
              <div className="space-y-2">
                <div className="text-sm font-semibold text-ink-800">{focus.name}</div>
                <div className="break-all text-xs text-ink-500">
                  {focus.absolute_path || focus.host_path || `${focus.root_label}/${focus.relative_path}`}
                </div>
                <div className="flex flex-wrap gap-2 text-xs text-ink-500">
                  <span>{focus.mime_type || focus.node_type}</span>
                  <span>{formatBytes(focus.size_bytes)}</span>
                </div>
              </div>
            ) : (
              <p className="text-sm text-ink-500">Select a file in the list below to inspect metadata.</p>
            )}
            {selectedList.length > 0 && (
              <p className="text-xs text-ink-500">
                After start, open the job for agentic pipeline + RAG Q&amp;A.{" "}
                <Link className="text-brand-700 underline" to="/forensic/jobs">
                  Jobs
                </Link>
              </p>
            )}
          </div>
        </Card>
      </div>

      <Card className="overflow-hidden p-0">
        <div className="flex flex-wrap items-center justify-between gap-2 border-b border-ink-300 bg-brand-50/40 px-3 py-2.5">
          <span className="text-sm font-medium text-ink-700">
            File inventory ({fileList.length})
          </span>
          <div className="flex flex-wrap gap-2">
            <Button variant="ghost" className="text-xs" onClick={() => selectAllFiles(true)} disabled={fileList.length === 0}>
              Select all
            </Button>
            <Button variant="ghost" className="text-xs" onClick={() => selectAllFiles(false)} disabled={fileList.length === 0}>
              Clear
            </Button>
          </div>
        </div>
        <div className="max-h-[55vh] overflow-auto bg-white/50">
          {fileList.length === 0 ? (
            <p className="p-4 text-sm text-ink-500">
              Upload files from this computer, or add a server folder, to build the image/PDF list.
            </p>
          ) : (
            <table className="w-full text-left text-sm">
              <thead className="table-head sticky top-0 text-xs uppercase tracking-wide text-ink-700 backdrop-blur-sm">
                <tr>
                  <th className="w-10 px-3 py-2">
                    <input
                      type="checkbox"
                      checked={fileList.length > 0 && selectedList.length === fileList.length}
                      onChange={(e) => selectAllFiles(e.target.checked)}
                      aria-label="Select all files"
                    />
                  </th>
                  <th className="px-3 py-2">Name</th>
                  <th className="px-3 py-2">Folder</th>
                  <th className="px-3 py-2">Type</th>
                  <th className="px-3 py-2 text-right">Size</th>
                </tr>
              </thead>
              <tbody>
                {fileList.map((f) => (
                  <tr
                    key={f.node_id}
                    className={`border-t border-ink-50/80 hover:bg-brand-50/50 ${
                      focus?.node_id === f.node_id ? "bg-brand-50/70" : ""
                    }`}
                  >
                    <td className="px-3 py-1.5">
                      <input
                        type="checkbox"
                        checked={Boolean(f.selected)}
                        onChange={(e) => toggleFile(f.node_id, e.target.checked)}
                      />
                    </td>
                    <td className="px-3 py-1.5">
                      <button
                        type="button"
                        className="max-w-[28rem] truncate text-left font-medium text-ink-800"
                        onClick={() => setFocus(f)}
                      >
                        {f.name}
                      </button>
                      <div className="max-w-[28rem] truncate text-xs text-ink-400">{f.relative_path}</div>
                    </td>
                    <td className="max-w-[14rem] truncate px-3 py-1.5 text-xs text-ink-500" title={f.root_label}>
                      {f.root_label}
                    </td>
                    <td className="px-3 py-1.5 text-xs text-ink-500">{f.mime_type || f.node_type}</td>
                    <td className="px-3 py-1.5 text-right text-xs text-ink-500">{formatBytes(f.size_bytes)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </Card>
    </div>
  );
}
