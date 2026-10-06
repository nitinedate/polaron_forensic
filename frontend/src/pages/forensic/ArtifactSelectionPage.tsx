import { useCallback, useEffect, useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, FileSearch, FileSpreadsheet, Info } from "lucide-react";
import { Badge, Button, Card, PageHeader, Spinner } from "../../components/ui";
import { ArtifactCatalogSelector, type ArtifactBrowseSelection } from "../../components/forensic/ArtifactCatalogSelector";
import { ArtifactBrowsePanel } from "../../components/forensic/ArtifactBrowsePanel";
import { CollapsibleSection } from "../../components/forensic/CollapsibleSection";
import { FamilyEvidenceDialog, type FamilyEvidenceTarget } from "../../components/forensic/FamilyEvidenceDialog";
import { MobileArtifactBoard } from "../../components/forensic/MobileArtifactBoard";
import { MobileExaminerPanel } from "../../components/forensic/MobileExaminerPanel";
import { rememberJobService, serviceForJobCreate } from "../../lib/apiRouting";
import { forensicApi } from "../../lib/forensicApi";
import { useToast } from "../../lib/toast";
import type { Job } from "../../lib/types/forensic";

type EvidenceCoverage = Awaited<ReturnType<typeof forensicApi.getEvidenceCoverage>>;

export function ArtifactSelectionPage() {
  const { jobId } = useParams<{ jobId: string }>();
  const toast = useToast();
  const [job, setJob] = useState<Job | null>(null);
  const [loading, setLoading] = useState(true);
  const [browse, setBrowse] = useState<ArtifactBrowseSelection>({ catalogKey: null, catalogSection: null });
  const [artifactsOpen, setArtifactsOpen] = useState(true);
  const [rerunningInventory, setRerunningInventory] = useState(false);
  const [refreshingScope, setRefreshingScope] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [inventoryVersion, setInventoryVersion] = useState(0);
  const [coverage, setCoverage] = useState<EvidenceCoverage | null>(null);
  const [fileDialog, setFileDialog] = useState<FamilyEvidenceTarget | null>(null);

  const loadJob = useCallback(async () => {
    if (!jobId) return;
    try {
      const j = await forensicApi.getJob(jobId);
      const src =
        typeof j.disk_source?.source_type === "string" ? j.disk_source.source_type : null;
      rememberJobService(jobId, serviceForJobCreate(j.type, src));
      setJob(j);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to load job");
    } finally {
      setLoading(false);
    }
  }, [jobId, toast]);

  const loadCoverage = useCallback(async () => {
    if (!jobId) return;
    try {
      setCoverage(await forensicApi.getEvidenceCoverage(jobId));
    } catch {
      setCoverage(null);
    }
  }, [jobId]);

  useEffect(() => {
    void (async () => {
      await loadJob();
      await loadCoverage();
    })();
  }, [loadJob, loadCoverage]);

  function showEvidenceScope(
    scope: NonNullable<ArtifactBrowseSelection["scope"]>,
    label: string,
    prompt: string
  ) {
    setBrowse({
      catalogKey: null,
      catalogSection: null,
      scope,
      label,
      promptQuestion: prompt,
    });
    setArtifactsOpen(true);
  }

  const rerunInventory = async () => {
    if (!jobId) return;
    setRerunningInventory(true);
    try {
      const res = await forensicApi.rerunArtifactInventory(jobId);
      if (res.queued) {
        toast.success(`Artifact inventory rerun queued (${res.total?.toLocaleString() ?? "?"} artifacts)`);
      } else {
        toast.info("Artifact inventory is already running or no artifacts for this OS.");
      }
      await loadJob();
      setInventoryVersion((v) => v + 1);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to rerun artifact inventory");
    } finally {
      setRerunningInventory(false);
    }
  };

  const exportCatalog = async () => {
    if (!jobId) return;
    setExporting(true);
    try {
      await forensicApi.downloadArtifactCatalogExport(jobId);
      toast.success("Artifacts exported to Excel");
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Export failed");
    } finally {
      setExporting(false);
    }
  };

  const refreshScope = async () => {
    if (!jobId) return;
    setRefreshingScope(true);
    try {
      await forensicApi.refreshArtifactScope(jobId);
      setInventoryVersion((v) => v + 1);
      toast.success("Artifact counts refreshed from evidence");
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to refresh artifact counts");
    } finally {
      setRefreshingScope(false);
    }
  };

  if (!jobId) return null;

  return (
    <div>
      <PageHeader
        title="Artifacts & examination scope"
        subtitle="Select forensic artifacts for this examination. Objectives and procedures are configured in Case intake."
        actions={
          <div className="flex flex-wrap gap-2">
            <Button variant="brand" disabled={exporting || loading} onClick={() => void exportCatalog()}>
              <FileSpreadsheet className="h-4 w-4" />
              {exporting ? "Exporting…" : "Export Excel"}
            </Button>
            {job && ["indexed", "classified", "report_ready", "report_generating", "completed"].includes(job.status) && (
              <Button variant="outline" disabled={rerunningInventory} onClick={() => void rerunInventory()}>
                {rerunningInventory ? "Rerunning…" : "Rerun artifact inventory"}
              </Button>
            )}
            {["classified", "report_ready", "report_generating", "completed", "indexed"].includes(job?.status ?? "") && (
              <Link to={`/forensic/jobs/${jobId}/artifacts`}>
                <Button variant="outline">
                  <FileSearch className="h-4 w-4" /> Browse extracted
                </Button>
              </Link>
            )}
            <Link to={`/forensic/jobs/${jobId}`}>
              <Button variant="ghost">
                <ArrowLeft className="h-4 w-4" /> Back to job
              </Button>
            </Link>
          </div>
        }
      />

      <Card className="mb-4 flex items-start gap-3 border-brand-100 bg-brand-50/40 p-4">
        <Info className="mt-0.5 h-4 w-4 shrink-0 text-brand-600" />
        <div className="text-sm text-ink-600">
          <p className="font-medium text-ink-800">How this works</p>
          <p className="mt-1">
            Artifact counts are loaded from the database after ingestion. Opening this page does not re-run
            inventory — use <strong>Refresh</strong> in the catalog to re-merge live collector counts, or{" "}
            <strong>Rerun artifact inventory</strong> after changing prompts or scope.
            After the main pipeline finishes, inventory runs automatically when no stored counts exist.
            Configure examination objectives on the{" "}
            <Link to={`/forensic/jobs/${jobId}/intake`} className="font-medium text-brand-700 underline">
              Case intake
            </Link>{" "}
            page.
          </p>
          {job?.status && (
            <p className="mt-2">
              <Badge tone="indigo">Job status: {job.status}</Badge>
              {(job.progress_pct ?? 0) < 100 &&
                (job.pipeline_progress?.phase === "artifact_inventory" ||
                  job.pipeline_progress?.phase === "axiom_artifacts") && (
                <span className="ml-2">
                  <Badge tone="amber">Artifact inventory in progress</Badge>
                </span>
              )}
            </p>
          )}
        </div>
      </Card>

      {loading ? (
        <Card className="flex h-64 items-center justify-center">
          <Spinner />
        </Card>
      ) : (
        <div className="space-y-4">
          <Card className="p-4">
            <div className="flex flex-wrap items-start justify-between gap-3">
              <div>
                <p className="text-sm font-semibold text-ink-800">Saved evidences</p>
                <p className="mt-1 text-xs text-ink-500">
                  Every extracted file kept in the job (including tiny and extensionless). Open when you need the full
                  set, not only catalog matches.
                </p>
                {coverage ? (
                  <div className="mt-2 flex flex-wrap gap-2 text-xs">
                    <Badge tone="indigo">{coverage.total_files.toLocaleString()} files</Badge>
                    <Badge tone="neutral">{coverage.extensionless_count.toLocaleString()} extensionless</Badge>
                    <Badge tone="amber">{coverage.unclassified_count.toLocaleString()} unclassified</Badge>
                    <Badge tone="neutral">{coverage.tiny_le_1kb_count.toLocaleString()} ≤1 KB</Badge>
                  </div>
                ) : (
                  <p className="mt-2 text-xs text-ink-400">Coverage loads after extract/materialize.</p>
                )}
              </div>
              <div className="flex flex-wrap gap-2">
                <Button
                  variant="brand"
                  className="h-8 text-xs"
                  onClick={() =>
                    showEvidenceScope(
                      "all",
                      "All evidences",
                      "All files saved for this job (catalog and non-catalog)."
                    )
                  }
                >
                  Show all evidences
                </Button>
                <Button
                  variant="outline"
                  className="h-8 text-xs"
                  onClick={() =>
                    showEvidenceScope(
                      "extensionless",
                      "Extensionless files",
                      "Saved files with no/empty extension (prefs, History, Cookies, maildir, etc.)."
                    )
                  }
                >
                  Extensionless
                </Button>
                <Button
                  variant="outline"
                  className="h-8 text-xs"
                  onClick={() =>
                    setFileDialog({
                      key: "critical_files",
                      label: "Deleted / Modified / Anomalous Files",
                      description:
                        "Cross-platform critical files: deleted, modified, extensionless, spoofed extensions (Win/iOS/Linux).",
                      count: coverage?.total_files,
                    })
                  }
                >
                  Critical files
                </Button>
                <Button
                  variant="outline"
                  className="h-8 text-xs"
                  onClick={() =>
                    showEvidenceScope(
                      "unclassified",
                      "Unclassified evidences",
                      "Saved files not yet mapped to a catalog artifact."
                    )
                  }
                >
                  Unclassified
                </Button>
                <Button
                  variant="outline"
                  className="h-8 text-xs"
                  onClick={() =>
                    showEvidenceScope(
                      "tiny",
                      "Tiny files (≤1 KB)",
                      "Small saved evidences — often prefs, sidecars, or crypto headers."
                    )
                  }
                >
                  Tiny ≤1 KB
                </Button>
                <Button variant="ghost" className="h-8 text-xs" onClick={() => void loadCoverage()}>
                  Refresh counts
                </Button>
              </div>
            </div>
            {coverage?.by_extension?.length ? (
              <details className="mt-3">
                <summary className="cursor-pointer text-xs font-medium text-ink-600">
                  Extension breakdown (top {Math.min(20, coverage.by_extension.length)})
                </summary>
                <ul className="mt-2 max-h-40 overflow-y-auto font-mono text-[11px] text-ink-500">
                  {coverage.by_extension.slice(0, 20).map((row) => (
                    <li key={row.extension} className="flex justify-between gap-4 border-b border-ink-50 py-0.5">
                      <span>{row.extension}</span>
                      <span>
                        {row.count.toLocaleString()}
                        {row.tiny_le_1kb ? ` (${row.tiny_le_1kb} tiny)` : ""}
                      </span>
                    </li>
                  ))}
                </ul>
              </details>
            ) : null}
          </Card>
          {String(job?.type || "").includes("mobile") ||
          String(job?.disk_source?.source_type || "") === "mobile" ||
          Boolean(job?.disk_source?.mobile_os) ? (
            <>
              <Card className="p-4">
                <MobileArtifactBoard
                  jobId={jobId}
                  onOpenFamily={(row) => {
                    setBrowse({
                      catalogKey: null,
                      catalogSection: null,
                      // Do NOT use scope=all — that bypasses virtual message evidence and
                      // can surface the wrong file set next to the family dialog.
                      scope: null,
                      family: row.key,
                      q: null,
                      label: row.label,
                      promptQuestion:
                        row.description ||
                        `All ${row.label} evidence — select a name to preview content (any size).`,
                    });
                    setArtifactsOpen(true);
                  }}
                />
              </Card>
              <Card className="p-4">
                <MobileExaminerPanel jobId={jobId} />
              </Card>
            </>
          ) : null}
          <FamilyEvidenceDialog
            jobId={jobId!}
            open={fileDialog != null}
            family={fileDialog}
            onClose={() => setFileDialog(null)}
          />

          <CollapsibleSection
            title="Artifacts"
            subtitle="Artifact catalog for detected OS — grouped by category"
            open={artifactsOpen}
            onToggle={() => setArtifactsOpen((v) => !v)}
          >
            <div className="grid min-h-[560px] grid-cols-1 overflow-hidden xl:grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)]">
              <div className="max-h-[min(72vh,820px)] min-h-[520px] overflow-y-auto border-r border-ink-100">
                <ArtifactCatalogSelector
                  key={inventoryVersion}
                  jobId={jobId}
                  selected={browse}
                  onBrowse={setBrowse}
                  onScopeSaved={() => toast.success("Artifact scope applied")}
                  onRefresh={() => void refreshScope()}
                  refreshing={refreshingScope}
                />
              </div>
              <div className="max-h-[min(72vh,820px)] min-h-[520px] overflow-hidden">
                <ArtifactBrowsePanel jobId={jobId} selection={browse} />
              </div>
            </div>
          </CollapsibleSection>
        </div>
      )}
    </div>
  );
}
