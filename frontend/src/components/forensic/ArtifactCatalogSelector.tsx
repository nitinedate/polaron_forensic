import clsx from "clsx";
import { ChevronDown, ChevronRight, FileSpreadsheet, FolderTree, Search } from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type MouseEvent } from "react";

import { Badge, Button, Input, Spinner } from "../ui";
import { stripAxiomBranding } from "../../lib/displayText";
import { forensicApi } from "../../lib/forensicApi";
import { useToast } from "../../lib/toast";
import type { ArtifactCatalogSection, ArtifactScope } from "../../lib/types/forensic";

export interface ArtifactBrowseSelection {
  catalogKey: string | null;
  catalogSection: string | null;
  promptQuestion?: string | null;
  label?: string | null;
  /** Browse saved evidences without catalog filter. */
  scope?: "all" | "unclassified" | "extensionless" | "tiny" | null;
  /** Optional path/name filter (mobile board family Open). */
  q?: string | null;
  /** Mobile board family key — list every matching file. */
  family?: string | null;
}

interface ArtifactCatalogSelectorProps {
  jobId: string;
  selected?: ArtifactBrowseSelection;
  onBrowse?: (selection: ArtifactBrowseSelection) => void;
  onScopeSaved?: () => void;
  onRefresh?: () => void;
  refreshing?: boolean;
}

function sectionKeys(section: ArtifactCatalogSection): string[] {
  return section.subcategories.map((sub) => sub.key);
}

function countDomainLabel(domain?: string | null): string {
  if (!domain) return "records";
  return domain.replace(/_/g, " ");
}

function catalogQueryStatus(status?: string | null): string {
  const s = (status || "").toLowerCase();
  if (s === "failed" || s === "error") return "failed";
  return "done";
}

function queryStatusTone(status?: string | null): "green" | "amber" | "neutral" | "red" {
  const s = catalogQueryStatus(status);
  if (s === "done" || s === "stored") return "green";
  if (s === "failed") return "red";
  return "neutral";
}

function matchesArtifactSearch(
  query: string,
  sectionTitle: string,
  sub: ArtifactCatalogSection["subcategories"][0]
): boolean {
  const q = query.trim().toLowerCase();
  if (!q) return true;
  return [sectionTitle, sub.label, sub.description, sub.key, sub.recovery_method, sub.prompt_question].some(
    (field) => (field ?? "").toLowerCase().includes(q)
  );
}

export function ArtifactCatalogSelector({
  jobId,
  selected = { catalogKey: null, catalogSection: null },
  onBrowse,
  onScopeSaved,
  onRefresh,
  refreshing = false,
}: ArtifactCatalogSelectorProps) {
  const toast = useToast();
  const [scope, setScope] = useState<ArtifactScope | null>(null);
  const [enabled, setEnabled] = useState<Set<string>>(new Set());
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [savingReport, setSavingReport] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [reportSavedAt, setReportSavedAt] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [exporting, setExporting] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);

  const searchActive = searchQuery.trim().length > 0;

  const filteredSections = useMemo(() => {
    const source = scope?.sections ?? [];
    return source
      .map((section) => ({
        ...section,
        subcategories: section.subcategories.filter((sub) => {
          if (!searchActive && (sub.count ?? 0) <= 0) return false;
          if (searchActive && !matchesArtifactSearch(searchQuery.trim(), section.title, sub)) return false;
          return true;
        }),
      }))
      .filter((section) => section.subcategories.length > 0);
  }, [scope, searchActive, searchQuery]);

  useEffect(() => {
    if (!searchActive || filteredSections.length === 0) return;
    setExpanded(new Set(filteredSections.map((s) => s.title)));
  }, [searchActive, filteredSections]);

  const totalArtifacts = useMemo(
    () => scope?.sections.reduce((sum, section) => sum + (section.count ?? 0), 0) ?? 0,
    [scope]
  );

  const load = useCallback(async (opts?: { silent?: boolean }) => {
    if (!opts?.silent) setLoading(true);
    try {
      const res = await forensicApi.getArtifactScope(jobId);
      setScope(res);
      setLoadError(null);
      const savedForReport = res.report_saved_artifact_ids ?? [];
      setEnabled(new Set(savedForReport.length > 0 ? savedForReport : res.enabled_keys));
      setReportSavedAt(res.report_artifacts_saved_at ?? null);
      setExpanded(new Set(res.sections.map((section) => section.title)));
      setDirty(false);
    } catch (e: unknown) {
      const message = e instanceof Error ? e.message : "Failed to load artifacts";
      setLoadError(message);
      if (!opts?.silent) {
        toast.error(message);
      }
    } finally {
      if (!opts?.silent) setLoading(false);
    }
  }, [jobId, toast]);

  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (!scope?.axiom_inventory || scope.axiom_inventory.done) return;
    const id = window.setInterval(() => {
      void load({ silent: true });
    }, 4000);
    return () => window.clearInterval(id);
  }, [scope?.axiom_inventory?.done, load]);

  const sectionState = useMemo(() => {
    const map = new Map<string, { checked: boolean; indeterminate: boolean }>();
    if (!scope) return map;
    for (const section of scope.sections) {
      const keys = sectionKeys(section);
      const checkedCount = keys.filter((key) => enabled.has(key)).length;
      map.set(section.title, {
        checked: keys.length > 0 && checkedCount === keys.length,
        indeterminate: checkedCount > 0 && checkedCount < keys.length,
      });
    }
    return map;
  }, [scope, enabled]);

  function updateEnabled(next: Set<string>) {
    setEnabled(next);
    setDirty(true);
  }

  function toggleSub(key: string, event: MouseEvent) {
    event.stopPropagation();
    const next = new Set(enabled);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    updateEnabled(next);
  }

  function toggleSection(section: ArtifactCatalogSection, event: MouseEvent) {
    event.stopPropagation();
    const keys = sectionKeys(section);
    const allOn = keys.every((key) => enabled.has(key));
    const next = new Set(enabled);
    if (allOn) {
      for (const key of keys) next.delete(key);
    } else {
      for (const key of keys) next.add(key);
    }
    updateEnabled(next);
  }

  function useRecommended() {
    const rec = scope?.recommended_artifact_ids ?? [];
    updateEnabled(new Set(rec));
  }

  function selectAllInCatalog() {
    if (!scope) return;
    const keys = scope.sections.flatMap((section) => section.subcategories.map((sub) => sub.key));
    updateEnabled(new Set(keys));
  }

  function selectSection(title: string, promptQuestion?: string | null) {
    onBrowse?.({ catalogKey: null, catalogSection: title, scope: null, promptQuestion, label: title });
  }

  function selectSub(key: string, label: string, promptQuestion?: string | null) {
    onBrowse?.({ catalogKey: key, catalogSection: null, scope: null, promptQuestion, label });
  }

  async function saveForReport() {
    setSavingReport(true);
    try {
      const res = await forensicApi.saveSelectedJobArtifacts(jobId, {
        artifact_ids: Array.from(enabled),
      });
      setReportSavedAt(res.saved_at ?? null);
      setDirty(false);
      toast.success("Artifacts saved for report");
      onScopeSaved?.();
    } catch {
      toast.error("Failed to save artifacts for report");
    } finally {
      setSavingReport(false);
    }
  }

  async function save() {
    setSaving(true);
    try {
      const res = await forensicApi.updateArtifactScope(jobId, {
        enabled_keys: Array.from(enabled),
      });
      setScope(res);
      const savedForReport = res.report_saved_artifact_ids ?? [];
      setEnabled(new Set(savedForReport.length > 0 ? savedForReport : res.enabled_keys));
      setReportSavedAt(res.report_artifacts_saved_at ?? null);
      setDirty(false);
      toast.success("Artifact scope saved");
      onScopeSaved?.();
    } catch {
      toast.error("Failed to save artifact scope");
    } finally {
      setSaving(false);
    }
  }

  async function exportExcel() {
    setExporting(true);
    try {
      await forensicApi.downloadArtifactCatalogExport(jobId);
      toast.success("Artifacts exported to Excel");
    } catch {
      toast.error("Export failed");
    } finally {
      setExporting(false);
    }
  }

  function toggleExpanded(title: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(title)) next.delete(title);
      else next.add(title);
      return next;
    });
  }

  function expandAll() {
    if (!scope) return;
    setExpanded(new Set(scope.sections.map((section) => section.title)));
  }

  function collapseAll() {
    setExpanded(new Set());
  }

  if (loading) {
    return (
      <div className="flex h-full items-center justify-center">
        <Spinner />
      </div>
    );
  }

  if (loadError && !scope) {
    return (
      <div className="px-3 py-6 text-center text-xs text-ink-500">
        <p className="font-medium text-red-700">{loadError}</p>
        <p className="mt-2">Stored artifact counts could not be loaded. Check that the API is running, then retry.</p>
        {onRefresh ? (
          <Button variant="outline" className="mt-3 text-xs" loading={refreshing} onClick={onRefresh}>
            Retry
          </Button>
        ) : null}
      </div>
    );
  }

  if (!scope || scope.sections.length === 0) {
    return (
      <div className="px-3 py-6 text-center text-xs text-ink-500">
        <p>No artifact catalog loaded.</p>
        {scope?.axiom_inventory?.done ? (
          <p className="mt-2">
            Inventory complete ({scope.axiom_inventory.completed ?? 0} / {scope.axiom_inventory.total ?? 0}) —
            stored counts may still be loading. Try Refresh.
          </p>
        ) : null}
        {onRefresh ? (
          <Button variant="outline" className="mt-3 text-xs" loading={refreshing} onClick={onRefresh}>
            Refresh from database
          </Button>
        ) : null}
      </div>
    );
  }

  const allSelected = selected.catalogKey === null && selected.catalogSection === null;

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2 border-b border-ink-100 px-3 py-3">
        <FolderTree className="h-4 w-4 text-brand-600" />
        <span className="text-xs font-bold uppercase tracking-wider text-ink-500">Artifacts</span>
        {scope.platform && (
          <Badge tone="indigo">{scope.platform}</Badge>
        )}
        {scope.axiom_inventory && !scope.axiom_inventory.done ? (
          <Badge tone="amber">
            Counting {scope.axiom_inventory.completed ?? 0} / {scope.axiom_inventory.total ?? "?"}
          </Badge>
        ) : null}
        <span className="ml-auto text-xs text-ink-400">{totalArtifacts} total</span>
      </div>

      <div className="space-y-2 border-b border-ink-50 px-2 py-2">
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={expandAll}
            className="rounded px-2 py-1 text-xs font-medium text-ink-500 hover:bg-ink-50 hover:text-ink-700"
          >
            Expand all
          </button>
          <button
            type="button"
            onClick={collapseAll}
            className="rounded px-2 py-1 text-xs font-medium text-ink-500 hover:bg-ink-50 hover:text-ink-700"
          >
            Collapse all
          </button>
          <span className="hidden h-4 w-px bg-ink-100 sm:inline" aria-hidden />
          <Button variant="outline" className="text-xs" onClick={useRecommended}>
            Use recommended
          </Button>
          <Button variant="outline" className="text-xs" onClick={selectAllInCatalog}>
            Select all
          </Button>
          <Button variant="outline" className="text-xs" onClick={() => updateEnabled(new Set())}>
            Clear selection
          </Button>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {onRefresh ? (
            <Button variant="outline" className="text-xs" loading={refreshing} onClick={onRefresh}>
              Refresh
            </Button>
          ) : null}
          <Button
            variant="outline"
            className="gap-1.5 text-xs"
            loading={exporting}
            onClick={() => void exportExcel()}
          >
            <FileSpreadsheet className="h-4 w-4" />
            Export Excel
          </Button>
          <Button variant="brand" className="text-xs" loading={saving} disabled={!dirty} onClick={save}>
            Save scope
          </Button>
          <Button
            variant="outline"
            className="text-xs whitespace-nowrap"
            loading={savingReport}
            disabled={enabled.size === 0}
            onClick={() => void saveForReport()}
          >
            Save artifacts for Report
          </Button>
        </div>
      </div>

      {reportSavedAt ? (
        <p className="border-b border-emerald-100 bg-emerald-50 px-3 py-1.5 text-[10px] text-emerald-800">
          Report artifact selection saved {new Date(reportSavedAt).toLocaleString()}.
        </p>
      ) : null}

      <div className="border-b border-ink-50 px-2 py-2">
        <div className="relative">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-ink-400" />
          <Input
            className="pl-8 text-xs"
            placeholder="Search artifacts by name, category, or ID…"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
      </div>

      <p className="border-b border-ink-50 px-3 py-2 text-[10px] text-ink-400">
        All artifacts for the detected OS are shown. Items included in the report type are checked by default; others remain unchecked until you select them.
        Checked items appear in Section B when you save artifacts for the report.
        {scope.suggested_investigation_scope?.recommended_headers?.length ? (
          <span className="mt-1 block text-ink-600">
            Suggested investigation areas:{" "}
            {scope.suggested_investigation_scope.recommended_headers
              .slice(0, 4)
              .map((h) => h.header_title)
              .join("; ")}
          </span>
        ) : null}
      </p>

      <nav className="flex-1 overflow-y-auto p-2">
        <button
          type="button"
          onClick={() =>
            onBrowse?.({ catalogKey: null, catalogSection: null, scope: null, promptQuestion: null, label: null })
          }
          className={clsx(
            "mb-1 flex w-full items-center rounded-lg px-3 py-2 text-left text-sm font-medium transition",
            allSelected ? "bg-brand-50 text-brand-700 ring-1 ring-brand-200" : "text-ink-600 hover:bg-ink-50"
          )}
        >
          All artifacts
          <span className="ml-auto text-xs tabular-nums text-ink-500">
            {enabled.size} selected
          </span>
        </button>

        {filteredSections.length === 0 ? (
          <p className="px-3 py-6 text-center text-xs text-ink-400">No artifacts match your search.</p>
        ) : (
        filteredSections.map((section) => {
          const state = sectionState.get(section.title);
          const isExpanded = expanded.has(section.title);
          const sectionSelected =
            selected.catalogSection === section.title && selected.catalogKey === null;
          const sectionCount = section.count ?? section.subcategories.reduce((s, sub) => s + (sub.count ?? 0), 0);

          return (
            <div key={section.title} className="mb-1">
              <div
                className={clsx(
                  "flex w-full items-center rounded-lg transition",
                  sectionSelected ? "bg-brand-50" : "hover:bg-ink-50"
                )}
              >
                <button
                  type="button"
                  aria-label={isExpanded ? "Collapse section" : "Expand section"}
                  onClick={() => toggleExpanded(section.title)}
                  className="shrink-0 rounded p-2 text-ink-400 hover:text-ink-700"
                >
                  {isExpanded ? (
                    <ChevronDown className="h-3.5 w-3.5" />
                  ) : (
                    <ChevronRight className="h-3.5 w-3.5" />
                  )}
                </button>
                <input
                  type="checkbox"
                  className="shrink-0"
                  checked={state?.checked ?? false}
                  ref={(el) => {
                    if (el) el.indeterminate = Boolean(state?.indeterminate);
                  }}
                  onClick={(event) => toggleSection(section, event)}
                  onChange={() => undefined}
                  aria-label={`Toggle scope for ${section.title}`}
                />
                <button
                  type="button"
                  onClick={() => selectSection(section.title)}
                  className={clsx(
                    "flex min-w-0 flex-1 items-center gap-1 py-2 pr-3 text-left text-sm font-medium",
                    sectionSelected ? "text-brand-700" : "text-ink-700"
                  )}
                >
                  <span className="flex-1 truncate">{stripAxiomBranding(section.title)}</span>
                  <span className="shrink-0 text-xs tabular-nums text-ink-500">
                    {sectionCount}
                  </span>
                </button>
              </div>

              {isExpanded && (
                <div className="ml-7 space-y-0.5">
                  {section.subcategories.map((sub) => {
                    const subSelected = selected.catalogKey === sub.key;
                    const zeroCount = (sub.count ?? 0) === 0;
                    return (
                      <div
                        key={sub.key}
                        className={clsx(
                          "flex w-full items-center rounded-lg transition",
                          subSelected ? "bg-brand-50" : "hover:bg-ink-50",
                          sub.critical && !subSelected && !zeroCount && "bg-brand-50/30",
                        )}
                      >
                        <input
                          type="checkbox"
                          className="ml-3 shrink-0"
                          checked={enabled.has(sub.key)}
                          onClick={(event) => toggleSub(sub.key, event)}
                          onChange={() => undefined}
                          aria-label={`Toggle scope for ${sub.label}`}
                        />
                        <button
                          type="button"
                          onClick={() => selectSub(sub.key, sub.label, sub.prompt_question)}
                          title={[
                            sub.prompt_question || sub.description || sub.label,
                            sub.observation_focus ? `Focus: ${sub.observation_focus}` : "",
                            sub.query_key ? `Query: ${sub.query_key}` : "",
                          ]
                            .filter(Boolean)
                            .join("\n")}
                          className={clsx(
                            "flex min-w-0 flex-1 items-center gap-1 px-2 py-1.5 text-left text-xs",
                            subSelected
                              ? "font-semibold text-brand-700"
                              : "text-ink-500 hover:text-ink-700"
                          )}
                        >
                          <span className="min-w-0 flex-1 truncate">{stripAxiomBranding(sub.label)}</span>
                          {sub.in_template && (
                            <Badge tone="green">report default</Badge>
                          )}
                          {sub.count_domain ? (
                            <Badge tone="indigo">{countDomainLabel(sub.count_domain)}</Badge>
                          ) : null}
                          {sub.query_status ? (
                            <Badge tone={queryStatusTone(sub.query_status)}>
                              {catalogQueryStatus(sub.query_status)}
                            </Badge>
                          ) : null}
                          {sub.critical && (
                            <Badge tone="green">critical</Badge>
                          )}
                          <span className="shrink-0 tabular-nums text-ink-500">
                            {sub.count ?? 0}
                          </span>
                        </button>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })
        )}
      </nav>
    </div>
  );
}
