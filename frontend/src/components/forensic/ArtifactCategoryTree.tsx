import clsx from "clsx";
import { ChevronDown, ChevronRight, FolderTree } from "lucide-react";
import { useCallback, useEffect, useMemo, useState, type MouseEvent } from "react";

import { Badge, Button } from "../ui";
import { stripAxiomBranding } from "../../lib/displayText";
import { forensicApi } from "../../lib/forensicApi";
import { useToast } from "../../lib/toast";
import type { ArtifactCatalogSection, CategoryNode } from "../../lib/types/forensic";

interface ArtifactCategoryTreeProps {
  categories: CategoryNode[];
  selected: { category: string | null; subCategory: string | null };
  onSelect: (category: string | null, subCategory: string | null) => void;
  total?: number;
  jobId?: string;
}

function buildScopeLookup(sections: ArtifactCatalogSection[]) {
  const bySectionSub = new Map<string, { key: string; critical: boolean }>();
  const bySubLabel = new Map<string, { key: string; critical: boolean }>();

  for (const section of sections) {
    for (const sub of section.subcategories) {
      const entry = { key: sub.key, critical: sub.critical };
      bySectionSub.set(`${section.title.toLowerCase()}::${sub.label.toLowerCase()}`, entry);
      bySubLabel.set(sub.label.toLowerCase(), entry);
      if (sub.label.toLowerCase() !== (sub.key.split("::")[1] ?? "").toLowerCase()) {
        const labelFromKey = sub.key.split("::")[1];
        if (labelFromKey) bySubLabel.set(labelFromKey.toLowerCase(), entry);
      }
    }
  }

  return { bySectionSub, bySubLabel };
}

function resolveScopeEntry(
  category: string,
  subCategory: string | null | undefined,
  lookup: ReturnType<typeof buildScopeLookup>
) {
  if (!subCategory) return null;
  return (
    lookup.bySectionSub.get(`${category.toLowerCase()}::${subCategory.toLowerCase()}`) ??
    lookup.bySubLabel.get(subCategory.toLowerCase()) ??
    lookup.bySubLabel.get(category.toLowerCase())
  );
}

/**
 * The scope key for any tree node. Uses the backend catalog key when one exists,
 * otherwise synthesizes "Category::Subcategory" — which matches the backend's
 * is_artifact_in_scope() fallback (it keys uncatalogued artifacts by
 * axiom_category::axiom_sub_category). This makes EVERY category and subcategory
 * selectable, and the selection genuinely controls report inclusion.
 */
function nodeScopeKey(
  category: string,
  subCategory: string | null | undefined,
  lookup: ReturnType<typeof buildScopeLookup>
): { key: string; critical: boolean } | null {
  if (!subCategory) return null;
  const resolved = resolveScopeEntry(category, subCategory, lookup);
  if (resolved) return resolved;
  return { key: `${category}::${subCategory}`, critical: false };
}

export function ArtifactCategoryTree({
  categories,
  selected,
  onSelect,
  total,
  jobId,
}: ArtifactCategoryTreeProps) {
  const toast = useToast();
  const [scopeSections, setScopeSections] = useState<ArtifactCatalogSection[]>([]);
  const [enabled, setEnabled] = useState<Set<string>>(new Set());
  const [scopeLoading, setScopeLoading] = useState(Boolean(jobId));
  const [saving, setSaving] = useState(false);
  const [dirty, setDirty] = useState(false);

  const grouped = useMemo(
    () =>
      categories.reduce<Map<string, CategoryNode[]>>((acc, node) => {
        const list = acc.get(node.category) ?? [];
        list.push(node);
        acc.set(node.category, list);
        return acc;
      }, new Map()),
    [categories]
  );

  const scopeLookup = useMemo(() => buildScopeLookup(scopeSections), [scopeSections]);

  const defaultExpanded = useMemo(
    () =>
      new Set(
        Array.from(grouped.entries())
          .filter(([, nodes]) => nodes.some((n) => n.count > 0))
          .map(([category]) => category)
      ),
    [grouped]
  );

  const [expanded, setExpanded] = useState<Set<string>>(defaultExpanded);

  const loadScope = useCallback(async () => {
    if (!jobId) return;
    setScopeLoading(true);
    try {
      const res = await forensicApi.getArtifactScope(jobId);
      setScopeSections(res.sections);
      setEnabled(new Set(res.enabled_keys));
      setDirty(false);
    } catch {
      toast.error("Failed to load artifact scope");
    } finally {
      setScopeLoading(false);
    }
  }, [jobId, toast]);

  useEffect(() => {
    loadScope();
  }, [loadScope]);

  useEffect(() => {
    setExpanded((prev) => {
      const next = new Set(prev);
      for (const category of defaultExpanded) next.add(category);
      return next;
    });
  }, [defaultExpanded]);

  const sectionScopeState = useMemo(() => {
    const map = new Map<string, { checked: boolean; indeterminate: boolean; keys: string[] }>();
    for (const [category, nodes] of grouped.entries()) {
      const keys = nodes
        .map((node) => nodeScopeKey(category, node.sub_category, scopeLookup)?.key)
        .filter((key): key is string => Boolean(key));
      const uniqueKeys = [...new Set(keys)];
      const checkedCount = uniqueKeys.filter((key) => enabled.has(key)).length;
      map.set(category, {
        keys: uniqueKeys,
        checked: uniqueKeys.length > 0 && checkedCount === uniqueKeys.length,
        indeterminate: checkedCount > 0 && checkedCount < uniqueKeys.length,
      });
    }
    return map;
  }, [grouped, scopeLookup, enabled]);

  const allSelected = selected.category === null;

  function toggleCategoryExpand(category: string) {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(category)) next.delete(category);
      else next.add(category);
      return next;
    });
  }

  function expandAll() {
    setExpanded(new Set(grouped.keys()));
  }

  function collapseAll() {
    setExpanded(new Set());
  }

  function updateEnabled(next: Set<string>) {
    setEnabled(next);
    setDirty(true);
  }

  function toggleScopeKey(key: string, event: MouseEvent) {
    event.stopPropagation();
    const next = new Set(enabled);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    updateEnabled(next);
  }

  function toggleSectionScope(category: string, event: MouseEvent) {
    event.stopPropagation();
    const state = sectionScopeState.get(category);
    if (!state || state.keys.length === 0) return;
    const allOn = state.keys.every((key) => enabled.has(key));
    const next = new Set(enabled);
    if (allOn) {
      for (const key of state.keys) next.delete(key);
    } else {
      for (const key of state.keys) next.add(key);
    }
    updateEnabled(next);
  }

  async function saveScope() {
    if (!jobId) return;
    setSaving(true);
    try {
      const res = await forensicApi.updateArtifactScope(jobId, {
        enabled_keys: Array.from(enabled),
      });
      setScopeSections(res.sections);
      setEnabled(new Set(res.enabled_keys));
      setDirty(false);
      toast.success("Artifact scope saved");
    } catch {
      toast.error("Failed to save artifact scope");
    } finally {
      setSaving(false);
    }
  }

  return (
    <div className="flex h-full flex-col">
      <div className="flex items-center gap-2 border-b border-ink-100 px-3 py-3">
        <FolderTree className="h-4 w-4 text-brand-600" />
        <span className="text-xs font-bold uppercase tracking-wider text-ink-500">Categories</span>
        {total !== undefined && (
          <span className="ml-auto text-xs text-ink-400">{total} artifacts</span>
        )}
      </div>

      <div className="flex flex-wrap items-center gap-1 border-b border-ink-50 px-2 py-1.5">
        <button
          type="button"
          onClick={expandAll}
          className="rounded px-2 py-0.5 text-[10px] font-medium text-ink-500 hover:bg-ink-50 hover:text-ink-700"
        >
          Expand all
        </button>
        <button
          type="button"
          onClick={collapseAll}
          className="rounded px-2 py-0.5 text-[10px] font-medium text-ink-500 hover:bg-ink-50 hover:text-ink-700"
        >
          Collapse all
        </button>
        {jobId && (
          <Button
            variant="brand"
            className="ml-auto !px-2 !py-0.5 text-[10px]"
            loading={saving}
            disabled={!dirty || scopeLoading}
            onClick={saveScope}
          >
            Save scope
          </Button>
        )}
      </div>

      {jobId && (
        <p className="border-b border-ink-50 px-3 py-2 text-[10px] text-ink-400">
          Check the categories and subcategories to include in the report, then click Save scope.
        </p>
      )}

      <nav className="flex-1 overflow-y-auto p-2">
        <button
          type="button"
          onClick={() => onSelect(null, null)}
          className={clsx(
            "mb-1 flex w-full items-center rounded-lg px-3 py-2 text-left text-sm font-medium transition",
            allSelected ? "bg-brand-50 text-brand-700 ring-1 ring-brand-200" : "text-ink-600 hover:bg-ink-50"
          )}
        >
          <span className="flex-1">All artifacts</span>
          {typeof total === "number" && total > 0 ? (
            <span className="text-xs font-normal text-ink-400">{total.toLocaleString()}</span>
          ) : null}
        </button>

        {Array.from(grouped.entries()).map(([category, nodes]) => {
          const catSelected = selected.category === category && selected.subCategory === null;
          const catCount = nodes.reduce((s, n) => s + n.count, 0);
          const isExpanded = expanded.has(category);
          const subs = nodes.filter((n) => n.sub_category);
          const sectionScope = sectionScopeState.get(category);

          return (
            <div key={category} className="mb-1">
              <div
                className={clsx(
                  "flex w-full items-center rounded-lg transition",
                  catSelected ? "bg-brand-50" : "hover:bg-ink-50"
                )}
              >
                <button
                  type="button"
                  aria-label={isExpanded ? "Collapse category" : "Expand category"}
                  onClick={() => toggleCategoryExpand(category)}
                  className="shrink-0 rounded p-2 text-ink-400 hover:text-ink-700"
                >
                  {isExpanded ? (
                    <ChevronDown className="h-3.5 w-3.5" />
                  ) : (
                    <ChevronRight className="h-3.5 w-3.5" />
                  )}
                </button>
                {sectionScope && sectionScope.keys.length > 0 && (
                  <input
                    type="checkbox"
                    className="shrink-0"
                    checked={sectionScope.checked}
                    ref={(el) => {
                      if (el) el.indeterminate = sectionScope.indeterminate;
                    }}
                    onClick={(event) => toggleSectionScope(category, event)}
                    onChange={() => undefined}
                    aria-label={`Include all of ${category} in report`}
                  />
                )}
                <button
                  type="button"
                  onClick={() => onSelect(category, null)}
                  className={clsx(
                    "flex min-w-0 flex-1 items-center gap-1 py-2 pr-3 text-left text-sm font-medium",
                    catSelected ? "text-brand-700" : "text-ink-700"
                  )}
                >
                  <span className="flex-1 truncate">{stripAxiomBranding(category)}</span>
                  <span className="shrink-0 text-xs tabular-nums text-ink-500">
                    {catCount}
                  </span>
                </button>
              </div>

              {isExpanded && (
                <div className="ml-7 space-y-0.5">
                  {subs.map((node) => {
                    const subSelected =
                      selected.category === category && selected.subCategory === node.sub_category;
                    const scopeEntry = nodeScopeKey(category, node.sub_category, scopeLookup);
                    return (
                      <div
                        key={`${category}-${node.sub_category}`}
                        className={clsx(
                          "flex w-full items-center rounded-lg transition",
                          subSelected ? "bg-brand-50" : "hover:bg-ink-50",
                          scopeEntry?.critical && !subSelected && "bg-brand-50/30"
                        )}
                      >
                        {scopeEntry ? (
                          <input
                            type="checkbox"
                            className="ml-3 shrink-0"
                            checked={enabled.has(scopeEntry.key)}
                            onClick={(event) => toggleScopeKey(scopeEntry.key, event)}
                            onChange={() => undefined}
                            aria-label={`Include ${node.sub_category} in report`}
                          />
                        ) : (
                          <span className="ml-3 w-4 shrink-0" />
                        )}
                        <button
                          type="button"
                          onClick={() => onSelect(category, node.sub_category ?? null)}
                          className={clsx(
                            "flex min-w-0 flex-1 items-center gap-1 px-2 py-1.5 text-left text-xs",
                            subSelected
                              ? "font-semibold text-brand-700"
                              : "text-ink-500 hover:text-ink-700"
                          )}
                        >
                          <span className="flex-1 truncate">{stripAxiomBranding(node.sub_category)}</span>
                          {scopeEntry?.critical && <Badge tone="green">critical</Badge>}
                          <span className="shrink-0 tabular-nums text-ink-500">
                            {node.count}
                          </span>
                        </button>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}

        {categories.length === 0 && (
          <p className="px-3 py-6 text-center text-xs text-ink-400">No categories yet</p>
        )}
      </nav>
    </div>
  );
}
