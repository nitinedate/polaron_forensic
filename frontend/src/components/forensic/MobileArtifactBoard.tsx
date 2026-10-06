import { useCallback, useEffect, useState } from "react";
import { ChevronDown, ChevronRight, ExternalLink, FolderOpen, RefreshCw, Smartphone } from "lucide-react";
import { Badge, Button, Spinner } from "../ui";
import { forensicApi } from "../../lib/forensicApi";
import { useToast } from "../../lib/toast";
import { FamilyEvidenceDialog, type FamilyEvidenceTarget } from "./FamilyEvidenceDialog";
import { stripVendorBranding } from "../../lib/displayText";

export type MobileArtifactBoardRow = {
  key: string;
  label: string;
  category: string;
  count: number;
  description: string;
  available: boolean;
  sample_paths?: string[];
  primary_path?: string | null;
  artifact_ids?: string[];
  primary_artifact_id?: string | null;
  catalog_key?: string | null;
  browse_query?: string | null;
  limitation?: string | null;
};

export type MobileArtifactCoverage = {
  coverage_key: string;
  discovered: number;
  processed: number;
  artifacts: number;
  recovered?: number;
  errors: number;
  status: string;
};

export type MobileArtifactBoardData = {
  job_id: string;
  total_files: number;
  families_available: number;
  families_total: number;
  acquisition_methods?: string[];
  mtp_only?: boolean;
  note?: string;
  packages_scanned?: number;
  coverage?: MobileArtifactCoverage[];
  normalized_analysis?: {
    total_artifacts?: number;
    inventory_total?: number;
    inventory_by_status?: Record<string, number>;
  };
  rows: MobileArtifactBoardRow[];
};

interface MobileArtifactBoardProps {
  jobId: string;
  onOpenFamily?: (row: MobileArtifactBoardRow) => void;
}

export function MobileArtifactBoard({ jobId, onOpenFamily }: MobileArtifactBoardProps) {
  const toast = useToast();
  const [data, setData] = useState<MobileArtifactBoardData | null>(null);
  const [loading, setLoading] = useState(false);
  const [open, setOpen] = useState(false);
  const [dialogFamily, setDialogFamily] = useState<FamilyEvidenceTarget | null>(null);

  const load = useCallback(
    async (refresh = false) => {
      setLoading(true);
      try {
        const board = await forensicApi.getMobileArtifactBoard(jobId, { refresh });
        setData(board);
      } catch (e: unknown) {
        setData(null);
        toast.error(e instanceof Error ? e.message : "Could not load mobile artifact board");
      } finally {
        setLoading(false);
      }
    },
    [jobId, toast]
  );

  useEffect(() => {
    if (open) void load(false);
  }, [open, load]);

  function openEvidence(row: MobileArtifactBoardRow) {
    if (!row.available) return;
    // Dialog: left = all names for this family, right = selected content.
    setDialogFamily({
      key: row.key,
      label: row.label,
      description: row.description,
      catalog_key: row.catalog_key,
      browse_query: row.browse_query,
      count: row.count,
    });
    // Also deep-link the main Artifacts browse panel when the parent wired it.
    onOpenFamily?.(row);
  }

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <p className="flex items-center gap-2 text-sm font-semibold text-ink-800">
            <Smartphone className="h-4 w-4 text-brand-600" />
            Mobile artifact inventory
          </p>
          <p className="mt-1 text-xs text-ink-500">
            {data
              ? `${data.families_available}/${data.families_total} families with evidence · ${data.total_files.toLocaleString()} files indexed${
                  typeof data.packages_scanned === "number" && data.packages_scanned > 0
                    ? ` · ${data.packages_scanned} package(s) (.pas/.ufd/.ufdx/.zip)`
                    : ""
                }${data.mtp_only ? " · MTP/logical acquire (app DBs often unavailable)" : ""} · Open shows all matching files (names left, content right)`
              : "Family counts — expand to load."}
          </p>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button variant="outline" className="h-8 text-xs" onClick={() => setOpen((v) => !v)}>
            {open ? <ChevronDown className="mr-1 h-3.5 w-3.5" /> : <ChevronRight className="mr-1 h-3.5 w-3.5" />}
            {open ? "Collapse" : "Expand"}
          </Button>
          <Button
            variant="outline"
            className="h-8 text-xs"
            disabled={!open}
            onClick={() => void load(true)}
          >
            <RefreshCw className="mr-1 h-3.5 w-3.5" />
            Refresh
          </Button>
        </div>
      </div>

      {!open ? null : loading ? (
        <div className="flex h-40 items-center justify-center">
          <Spinner />
        </div>
      ) : !data ? (
        <div className="rounded-md border border-ink-100 bg-ink-50/50 px-3 py-4 text-sm text-ink-500">
          Mobile artifact board unavailable until evidence is registered and indexed.
        </div>
      ) : (
        <>

      {data.note ? <p className="text-[11px] text-ink-500">{stripVendorBranding(data.note)}</p> : null}

      {data.coverage && data.coverage.length > 0 ? (
        <div className="rounded-md border border-ink-100 bg-ink-50/40 px-3 py-2">
          <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-[11px] text-ink-600">
            <span className="font-semibold text-ink-700">Processing coverage</span>
            <span>
              {data.coverage.filter((c) => c.status === "complete" || c.status === "available" || c.status === "not_present").length}
              /{data.coverage.length} groups finalized
            </span>
            <span>
              {data.coverage.reduce((n, c) => n + Number(c.processed || 0), 0).toLocaleString()} / {data.coverage.reduce((n, c) => n + Number(c.discovered || 0), 0).toLocaleString()} discovered items processed
            </span>
            {data.coverage.reduce((n, c) => n + Number(c.errors || 0), 0) > 0 ? (
              <span className="font-medium text-amber-700">
                {data.coverage.reduce((n, c) => n + Number(c.errors || 0), 0).toLocaleString()} processing error(s)
              </span>
            ) : null}
          </div>
        </div>
      ) : null}

      <div className="table-shell overflow-hidden rounded-md border border-ink-100">
        <div className="overflow-x-auto">
        <table className="min-w-full text-left text-xs">
          <thead className="table-head text-[10px] uppercase tracking-wide text-ink-700">
            <tr>
              <th className="px-3 py-2 font-semibold">Artifact</th>
              <th className="px-3 py-2 font-semibold">Count</th>
              <th className="px-3 py-2 font-semibold">Description</th>
              <th className="px-3 py-2 font-semibold">Path</th>
              <th className="px-3 py-2 font-semibold">Open</th>
            </tr>
          </thead>
          <tbody>
            {data.rows.map((row) => (
              <tr key={row.key} className="border-t border-ink-100 align-top">
                <td className="px-3 py-2">
                  <div className="font-semibold text-ink-800">{stripVendorBranding(row.label)}</div>
                  <div
                    className={
                      row.category === "Deleted"
                        ? "text-[10px] font-medium text-amber-700"
                        : "text-[10px] text-ink-400"
                    }
                  >
                    {stripVendorBranding(row.category)}
                  </div>
                </td>
                <td className="px-3 py-2">
                  <Badge tone={row.count > 0 ? "green" : "neutral"}>{row.count.toLocaleString()}</Badge>
                </td>
                <td className="max-w-md px-3 py-2 text-ink-600">{stripVendorBranding(row.description)}</td>
                <td className="max-w-xs px-3 py-2 font-mono text-[10px] text-ink-500">
                  {row.primary_path ? (
                    <span className="break-all" title={row.primary_path}>
                      {row.primary_path}
                    </span>
                  ) : (
                    <span className="italic text-ink-400">—</span>
                  )}
                </td>
                <td className="px-3 py-2">
                  <Button
                    variant="outline"
                    className="h-7 px-2 text-[11px]"
                    disabled={!row.available}
                    onClick={() => openEvidence(row)}
                  >
                    {row.available ? (
                      <>
                        <ExternalLink className="mr-1 h-3 w-3" />
                        Open
                      </>
                    ) : (
                      <>
                        <FolderOpen className="mr-1 h-3 w-3" />
                        N/A
                      </>
                    )}
                  </Button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        </div>
      </div>

      <FamilyEvidenceDialog
        jobId={jobId}
        open={dialogFamily != null}
        family={dialogFamily}
        onClose={() => setDialogFamily(null)}
      />
        </>
      )}
    </div>
  );
}
