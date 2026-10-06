import { useCallback, useEffect, useRef, useState } from "react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { AlertTriangle, ChevronLeft, ChevronRight } from "lucide-react";
import clsx from "clsx";
import { Badge, Card, Field, PageHeader, Select, Spinner } from "../../components/ui";
import { vulnApi } from "../../lib/vulnApi";
import { useToast } from "../../lib/toast";
import type { Case } from "../../lib/types/forensic";
import type { Vulnerability } from "../../lib/types/vuln";

const PAGE_SIZE = 25;

const SEV_TONE: Record<string, "neutral" | "green" | "amber" | "red" | "indigo"> = {
  critical: "red",
  high: "red",
  medium: "amber",
  low: "green",
  info: "neutral",
};

export function VulnExplorerPage() {
  const toast = useToast();
  const parentRef = useRef<HTMLDivElement>(null);

  const [cases, setCases] = useState<Case[]>([]);
  const [caseId, setCaseId] = useState("");
  const [severity, setSeverity] = useState("");
  const [page, setPage] = useState(1);
  const [items, setItems] = useState<Vulnerability[]>([]);
  const [total, setTotal] = useState(0);
  const [selected, setSelected] = useState<Vulnerability | null>(null);
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
      const res = await vulnApi.listVulnerabilities(caseId, {
        page,
        page_size: PAGE_SIZE,
        severity: severity || undefined,
      });
      setItems(res.items);
      setTotal(res.total);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to load vulnerabilities");
    } finally {
      setLoading(false);
    }
  }, [caseId, page, severity, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const virtualizer = useVirtualizer({
    count: items.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 52,
    overscan: 10,
  });

  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE));

  return (
    <div>
      <PageHeader
        title="Vulnerability explorer"
        subtitle="Browse and triage findings imported from Nessus scans."
      />

      <Card className="mb-4 p-4">
        <div className="flex flex-wrap gap-4">
          <Field label="Case">
            <Select
              className="min-w-[200px]"
              value={caseId}
              onChange={(e) => {
                setCaseId(e.target.value);
                setPage(1);
              }}
            >
              <option value="">Select case…</option>
              {cases.map((c) => (
                <option key={c.id} value={c.id}>
                  {c.title || c.number || c.id.slice(0, 8)}
                </option>
              ))}
            </Select>
          </Field>
          <Field label="Severity">
            <Select
              className="w-36"
              value={severity}
              onChange={(e) => {
                setSeverity(e.target.value);
                setPage(1);
              }}
            >
              <option value="">All</option>
              <option value="critical">critical</option>
              <option value="high">high</option>
              <option value="medium">medium</option>
              <option value="low">low</option>
            </Select>
          </Field>
          <div className="flex items-end">
            <span className="text-sm text-ink-400">{total} findings</span>
          </div>
        </div>
      </Card>

      <div className="grid gap-4 lg:grid-cols-5">
        <Card className="lg:col-span-3">
          {loading ? (
            <Spinner />
          ) : items.length === 0 ? (
            <p className="py-16 text-center text-sm text-ink-400">No vulnerabilities found.</p>
          ) : (
            <>
              <div ref={parentRef} className="max-h-[520px] overflow-y-auto">
                <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
                  {virtualizer.getVirtualItems().map((row) => {
                    const v = items[row.index];
                    const active = selected?.id === v.id;
                    return (
                      <button
                        key={v.id}
                        onClick={() => setSelected(v)}
                        className={clsx(
                          "absolute left-0 top-0 flex w-full items-start gap-3 border-b border-ink-50 px-4 py-3 text-left transition",
                          active ? "bg-brand-50" : "hover:bg-ink-50"
                        )}
                        style={{ height: row.size, transform: `translateY(${row.start}px)` }}
                      >
                        <AlertTriangle
                          className={clsx(
                            "mt-0.5 h-4 w-4 shrink-0",
                            v.severity === "critical" || v.severity === "high"
                              ? "text-red-500"
                              : "text-amber-500"
                          )}
                        />
                        <div className="min-w-0 flex-1">
                          <p className="truncate text-sm font-semibold text-ink-800">
                            {v.synopsis || v.plugin_id || "Finding"}
                          </p>
                          <p className="text-xs text-ink-400">
                            {v.cve || v.plugin_family || "—"}
                          </p>
                        </div>
                        <Badge tone={SEV_TONE[v.severity] ?? "neutral"}>{v.severity}</Badge>
                      </button>
                    );
                  })}
                </div>
              </div>
              <div className="flex items-center justify-between border-t border-ink-100 px-4 py-2">
                <span className="text-xs text-ink-400">
                  Page {page} of {totalPages}
                </span>
                <div className="flex gap-1">
                  <button
                    disabled={page <= 1}
                    onClick={() => setPage((p) => p - 1)}
                    className="rounded p-1 text-ink-400 hover:bg-ink-100 disabled:opacity-40"
                  >
                    <ChevronLeft className="h-4 w-4" />
                  </button>
                  <button
                    disabled={page >= totalPages}
                    onClick={() => setPage((p) => p + 1)}
                    className="rounded p-1 text-ink-400 hover:bg-ink-100 disabled:opacity-40"
                  >
                    <ChevronRight className="h-4 w-4" />
                  </button>
                </div>
              </div>
            </>
          )}
        </Card>

        <Card className="lg:col-span-2 p-5">
          {!selected ? (
            <p className="py-16 text-center text-sm text-ink-400">Select a finding to view details.</p>
          ) : (
            <div>
              <Badge tone={SEV_TONE[selected.severity] ?? "neutral"}>{selected.severity}</Badge>
              <h3 className="mt-3 text-lg font-bold text-ink-900">
                {selected.synopsis || "Vulnerability finding"}
              </h3>
              <dl className="mt-4 space-y-3 text-sm">
                {selected.cve && (
                  <div>
                    <dt className="text-xs font-semibold uppercase text-ink-400">CVE</dt>
                    <dd className="font-mono text-ink-700">{selected.cve}</dd>
                  </div>
                )}
                {(selected.cvss != null || selected.score_available === false) && (
                  <div>
                    <dt className="text-xs font-semibold uppercase text-ink-400">CVSS</dt>
                    <dd className="text-ink-700">{selected.score_available === false ? "Unscored" : selected.cvss}</dd>
                  </div>
                )}
                {(selected.port || selected.service) && (
                  <div>
                    <dt className="text-xs font-semibold uppercase text-ink-400">Service</dt>
                    <dd className="text-ink-700">
                      {selected.protocol}/{selected.port} {selected.service}
                    </dd>
                  </div>
                )}
                <div>
                  <dt className="text-xs font-semibold uppercase text-ink-400">Status</dt>
                  <dd>
                    <Badge tone="neutral">{selected.status}</Badge>
                  </dd>
                </div>
                {selected.remediation && (
                  <div>
                    <dt className="text-xs font-semibold uppercase text-ink-400">Remediation</dt>
                    <dd className="whitespace-pre-wrap text-ink-600">{selected.remediation}</dd>
                  </div>
                )}
              </dl>
            </div>
          )}
        </Card>
      </div>
    </div>
  );
}
