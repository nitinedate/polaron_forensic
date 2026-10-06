import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { Download, FileOutput, FileText, Upload } from "lucide-react";
import clsx from "clsx";
import { Badge, Button, Card, Field, Input, PageHeader, Select, Spinner } from "../../components/ui";
import { vulnApi } from "../../lib/vulnApi";
import { useToast } from "../../lib/toast";
import type { Case, GapMergeCandidate } from "../../lib/types/forensic";

type GapFirewall = {
  make_model?: string;
  policies_logs?: string;
};

type GapInternet = {
  type?: string;
  vendors?: string;
  vpn_sdwans?: string;
  ids_ips?: string;
  dns_security?: string;
};

type GapOperatingSystems = {
  windows?: string;
  linux?: string;
  mac?: string;
};

export type GapIntake = {
  client_name?: string;
  branch_locations?: string;
  contact_person?: string;
  date_of_visit?: string;
  geographic_locations?: string;
  num_offices?: string;
  num_endpoints?: string;
  operating_systems?: GapOperatingSystems;
  data_centers?: string;
  critical_servers?: string;
  critical_devices?: string;
  web_apps?: string;
  mobile_apps?: string;
  firewall?: GapFirewall;
  internet?: GapInternet;
  nac?: string;
  antivirus?: string;
  backup_storage?: string;
  author?: string;
  document_version?: string;
  has_saved_intake?: boolean;
};

function hasStoredIntake(data: GapIntake): boolean {
  return Boolean(data.has_saved_intake);
}

function kolkataYmd(offsetDays = 0): string {
  const parts = new Intl.DateTimeFormat("en-CA", {
    timeZone: "Asia/Kolkata",
    year: "numeric",
    month: "2-digit",
    day: "2-digit",
  }).formatToParts(new Date());
  const year = Number(parts.find((p) => p.type === "year")?.value);
  const month = Number(parts.find((p) => p.type === "month")?.value);
  const day = Number(parts.find((p) => p.type === "day")?.value);
  const dt = new Date(Date.UTC(year, month - 1, day + offsetDays));
  return dt.toISOString().slice(0, 10);
}

function mergeDayBadge(label: string): { text: string; tone: "green" | "neutral" | "indigo" } {
  if (label === "today") return { text: "Today", tone: "green" };
  if (label === "yesterday") return { text: "Yesterday", tone: "neutral" };
  return { text: label, tone: "indigo" };
}

function SectionHeading({ children }: { children: ReactNode }) {
  return (
    <h4 className="border-b border-ink-200 pb-2 text-sm font-bold uppercase tracking-wide text-ink-700">{children}</h4>
  );
}

function FieldGroupPanel({ children, className }: { children: ReactNode; className?: string }) {
  return (
    <div
      className={clsx(
        "rounded-xl border border-ink-200 bg-gradient-to-b from-white to-ink-50/80 p-4 shadow-sm ring-1 ring-ink-100/80 sm:p-5",
        className,
      )}
    >
      {children}
    </div>
  );
}

export function ReportsExportPage() {
  const toast = useToast();
  const [cases, setCases] = useState<Case[]>([]);
  const [mergeCandidates, setMergeCandidates] = useState<GapMergeCandidate[]>([]);
  const [selectedCaseId, setSelectedCaseId] = useState("");
  const [summary, setSummary] = useState<Record<string, unknown> | null>(null);
  const [gapIntake, setGapIntake] = useState<GapIntake>({});
  const [intakeLoaded, setIntakeLoaded] = useState(false);
  const [intakeHasData, setIntakeHasData] = useState(false);
  const [loading, setLoading] = useState(true);
  const [exporting, setExporting] = useState(false);
  const [importing, setImporting] = useState(false);
  const [gapExporting, setGapExporting] = useState<"pdf" | "docx" | "merged" | null>(null);
  const [savingIntake, setSavingIntake] = useState(false);
  const [pipeline, setPipeline] = useState<Array<{ engine: string; role: string }>>([]);
  const [mergeCaseIds, setMergeCaseIds] = useState<string[]>([]);
  const [mergeFromDate, setMergeFromDate] = useState(() => kolkataYmd(-1));
  const mergeToDate = kolkataYmd(0);
  const fileRef = useRef<HTMLInputElement>(null);

  const patchIntake = useCallback((patch: Partial<GapIntake>) => {
    setGapIntake((prev) => ({ ...prev, ...patch }));
  }, []);

  const patchNested = useCallback(
    <K extends "operating_systems" | "firewall" | "internet">(
      key: K,
      patch: GapIntake[K] extends object | undefined ? Partial<NonNullable<GapIntake[K]>> : never,
    ) => {
      setGapIntake((prev) => ({
        ...prev,
        [key]: { ...(prev[key] as object), ...patch },
      }));
    },
    [],
  );

  const loadMergeCandidates = useCallback(async () => {
    try {
      const mergeRes = await vulnApi.listGapMergeCandidates({ from_date: mergeFromDate });
      setMergeCandidates(mergeRes.items || []);
      setMergeCaseIds((prev) => prev.filter((id) => (mergeRes.items || []).some((c) => c.id === id)));
    } catch {
      setMergeCandidates([]);
    }
  }, [mergeFromDate]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [caseRes, pipe] = await Promise.all([
        vulnApi.listCases({ page: 1, page_size: 50 }),
        vulnApi.getOrchestratorPipeline(),
      ]);
      setCases(caseRes.items);
      setPipeline(pipe.pipeline);
      if (caseRes.items.length > 0) setSelectedCaseId(caseRes.items[0].id);
      else if (caseRes.items.length === 0) setSelectedCaseId("00000000-0000-4000-8000-000000000001");
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to load report data");
    } finally {
      setLoading(false);
    }
  }, [toast]);

  const loadSummary = useCallback(async () => {
    if (!selectedCaseId) return;
    try {
      setSummary(await vulnApi.getVulnReportSummary(selectedCaseId));
    } catch {
      setSummary(null);
    }
  }, [selectedCaseId]);

  const loadGapIntake = useCallback(async () => {
    if (!selectedCaseId) return;
    setIntakeLoaded(false);
    try {
      const data = (await vulnApi.getGapIntake(selectedCaseId)) as GapIntake;
      setGapIntake(data);
      setIntakeHasData(hasStoredIntake(data));
      setIntakeLoaded(true);
    } catch {
      setGapIntake({});
      setIntakeHasData(false);
      setIntakeLoaded(true);
    }
  }, [selectedCaseId]);

  useEffect(() => {
    load();
  }, [load]);

  useEffect(() => {
    void loadMergeCandidates();
  }, [loadMergeCandidates]);

  useEffect(() => {
    loadSummary();
    loadGapIntake();
  }, [loadSummary, loadGapIntake]);

  async function exportCsv() {
    if (!selectedCaseId) return;
    setExporting(true);
    try {
      await vulnApi.exportVulnReportCsv(selectedCaseId);
      toast.success("Solution-set CSV downloaded");
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Export failed");
    } finally {
      setExporting(false);
    }
  }

  async function exportXlsx() {
    if (!selectedCaseId) return;
    setExporting(true);
    try {
      await vulnApi.exportVulnReportXlsx(selectedCaseId);
      toast.success("Solution Set Excel downloaded");
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Export failed");
    } finally {
      setExporting(false);
    }
  }

  async function exportCoverage() {
    if (!selectedCaseId) return;
    setExporting(true);
    try {
      await vulnApi.exportServiceCoverageCsv(selectedCaseId);
      toast.success("Service coverage CSV downloaded");
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Coverage export failed");
    } finally {
      setExporting(false);
    }
  }

  async function importCsvFile(file: File) {
    if (!selectedCaseId) return;
    setImporting(true);
    try {
      const text = await file.text();
      const result = await vulnApi.importVulnReportCsv(selectedCaseId, text);
      toast.success(`Imported ${result.imported} findings`);
      loadSummary();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Import failed");
    } finally {
      setImporting(false);
    }
  }

  async function saveGapIntake() {
    if (!selectedCaseId) return;
    setSavingIntake(true);
    try {
      const { has_saved_intake: _ignored, ...payload } = gapIntake;
      const saved = (await vulnApi.saveGapIntake(selectedCaseId, payload)) as GapIntake;
      setGapIntake(saved);
      setIntakeHasData(hasStoredIntake(saved));
      try {
        await loadMergeCandidates();
      } catch {
        /* non-fatal */
      }
      toast.success(intakeHasData ? "Site overview updated" : "Site overview saved");
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Save failed");
    } finally {
      setSavingIntake(false);
    }
  }

  async function exportGap(fmt: "pdf" | "docx") {
    if (!selectedCaseId) return;
    setGapExporting(fmt);
    try {
      const { has_saved_intake: _ignored, ...payload } = gapIntake;
      await vulnApi.saveGapIntake(selectedCaseId, payload);
      if (fmt === "pdf") await vulnApi.exportGapReportPdf(selectedCaseId);
      else await vulnApi.exportGapReportDocx(selectedCaseId);
      await vulnApi.exportVulnReportXlsx(selectedCaseId);
      toast.success(`Gap Assessment Report (${fmt.toUpperCase()}) and Solution Set Excel downloaded`);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Gap report export failed";
      toast.error(msg.includes("timeout") ? "Report generation timed out — try again or disable LLM enrichment." : msg);
    } finally {
      setGapExporting(null);
    }
  }

  function toggleMergeCase(caseId: string) {
    setMergeCaseIds((prev) =>
      prev.includes(caseId) ? prev.filter((id) => id !== caseId) : [...prev, caseId],
    );
  }

  async function exportMergedGap() {
    const ids = Array.from(new Set(mergeCaseIds));
    if (ids.length < 2) {
      toast.error("Select at least two cases to merge");
      return;
    }
    setGapExporting("merged");
    try {
      await vulnApi.exportMergedGapReportPdf(ids);
      toast.success("Merged Gap Assessment Report downloaded");
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "Merged gap report export failed";
      toast.error(msg.includes("timeout") ? "Merge timed out — try again or disable LLM enrichment." : msg);
    } finally {
      setGapExporting(null);
    }
  }

  const os = gapIntake.operating_systems ?? {};
  const fw = gapIntake.firewall ?? {};
  const inet = gapIntake.internet ?? {};

  return (
    <div>
      <PageHeader
        title="Reports & export"
        subtitle="Export vulnerability findings as a Solution Set Excel (Risk, Host, Protocol, Port, Name) or Polaron Gap Assessment Report (PDF/DOCX) per case. Creating a gap report also downloads the Excel."
      />

      {loading ? (
        <Spinner />
      ) : (
        <>
          <Card className="mb-6 p-4">
            <Field label="Case" hint="Reports are generated per case from open vuln findings.">
              <Select value={selectedCaseId} onChange={(e) => setSelectedCaseId(e.target.value)}>
                <option value="">Select case…</option>
                {cases.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.title || c.number || c.id.slice(0, 8)}
                  </option>
                ))}
              </Select>
            </Field>
          </Card>

          <div className="grid gap-6 lg:grid-cols-2">
            <Card className="p-6">
              <div className="mb-4 flex items-center gap-2">
                <FileOutput className="h-5 w-5 text-brand-600" />
                <h3 className="font-bold text-ink-900">Solution-set Excel</h3>
              </div>
              <div className="space-y-4">
                <div className="rounded-lg border border-ink-200 bg-ink-50 p-3 text-xs text-ink-600">
                  <p className="mb-2 font-semibold text-ink-800">Scan orchestrator pipeline</p>
                  <div className="flex flex-wrap gap-1">
                    {pipeline.map((s) => (
                      <Badge key={s.engine} tone="indigo">
                        {s.engine}
                      </Badge>
                    ))}
                  </div>
                </div>
                <Button variant="brand" loading={exporting} onClick={exportXlsx} disabled={!selectedCaseId}>
                  <Download className="h-4 w-4" /> Export solution-set Excel
                </Button>
                <Button variant="ghost" loading={exporting} onClick={exportCsv} disabled={!selectedCaseId}>
                  <Download className="h-4 w-4" /> Export solution-set CSV
                </Button>
                <Button variant="ghost" loading={exporting} onClick={exportCoverage} disabled={!selectedCaseId}>
                  <Download className="h-4 w-4" /> Service coverage CSV
                </Button>
                <input
                  ref={fileRef}
                  type="file"
                  accept=".csv,text/csv"
                  className="hidden"
                  onChange={(e) => {
                    const f = e.target.files?.[0];
                    if (f) importCsvFile(f);
                    e.target.value = "";
                  }}
                />
                <Button
                  variant="ghost"
                  loading={importing}
                  disabled={!selectedCaseId}
                  onClick={() => fileRef.current?.click()}
                >
                  <Upload className="h-4 w-4" /> Import CSV
                </Button>
              </div>
            </Card>

            <Card className="p-6">
              <h3 className="font-bold text-ink-900">Finding summary</h3>
              {!summary ? (
                <p className="mt-4 text-sm text-ink-400">Select a case to view finding counts.</p>
              ) : (
                <dl className="mt-4 space-y-3 text-sm">
                  <div>
                    <dt className="text-xs font-semibold uppercase text-ink-400">Polaron — Findings by severity</dt>
                    <dd className="mt-1 flex flex-wrap gap-1">
                      {Object.entries((summary.findings_by_severity as Record<string, number>) || {}).map(
                        ([sev, count]) => (
                          <Badge key={sev} tone="neutral">
                            {sev}: {count}
                          </Badge>
                        ),
                      )}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-xs font-semibold uppercase text-ink-400">Findings by engine</dt>
                    <dd className="mt-1 flex flex-wrap gap-1">
                      {Object.entries((summary.findings_by_engine as Record<string, number>) || {}).map(
                        ([eng, count]) => (
                          <Badge key={eng} tone="indigo">
                            {eng}: {count}
                          </Badge>
                        ),
                      )}
                    </dd>
                  </div>
                </dl>
              )}
            </Card>
          </div>

          <Card className="mt-6 p-6">
            <div className="mb-6 flex flex-wrap items-start justify-between gap-4">
              <div>
                <div className="mb-2 flex items-center gap-2">
                  <FileText className="h-5 w-5 text-brand-600" />
                  <h3 className="font-bold text-ink-900">Gap Assessment Report</h3>
                </div>
                <p className="max-w-3xl text-sm text-ink-600">
                  Enter site overview and infrastructure details for the PDF. Data is saved per case and auto-loaded
                  when you switch cases.
                </p>
              </div>
              {intakeHasData && intakeLoaded && <Badge tone="green">Saved for this case</Badge>}
            </div>

            {!intakeLoaded && selectedCaseId ? (
              <Spinner />
            ) : (
              <div className="space-y-8">
                <section>
                  <SectionHeading>Site overview</SectionHeading>
                  <FieldGroupPanel className="mt-4">
                    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                      <Field label="Client name">
                        <Input
                          value={gapIntake.client_name ?? ""}
                          onChange={(e) => patchIntake({ client_name: e.target.value })}
                          placeholder="LILAVATI HOSPITAL"
                        />
                      </Field>
                      <Field label="Branch location(s)">
                        <Input
                          value={gapIntake.branch_locations ?? ""}
                          onChange={(e) => patchIntake({ branch_locations: e.target.value })}
                        />
                      </Field>
                      <Field label="Contact person">
                        <Input
                          value={gapIntake.contact_person ?? ""}
                          onChange={(e) => patchIntake({ contact_person: e.target.value })}
                        />
                      </Field>
                      <Field label="Date of visit">
                        <Input
                          value={gapIntake.date_of_visit ?? ""}
                          onChange={(e) => patchIntake({ date_of_visit: e.target.value })}
                          placeholder="DD-MM-YYYY"
                        />
                      </Field>
                      <Field label="Author">
                        <Input value={gapIntake.author ?? ""} onChange={(e) => patchIntake({ author: e.target.value })} />
                      </Field>
                      <Field label="Document version">
                        <Input
                          value={gapIntake.document_version ?? ""}
                          onChange={(e) => patchIntake({ document_version: e.target.value })}
                          placeholder="1.0"
                        />
                      </Field>
                    </div>
                  </FieldGroupPanel>
                </section>

                <section>
                  <SectionHeading>General information</SectionHeading>
                  <FieldGroupPanel className="mt-4">
                    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                      <Field label="Geographic locations">
                        <Input
                          value={gapIntake.geographic_locations ?? ""}
                          onChange={(e) => patchIntake({ geographic_locations: e.target.value })}
                        />
                      </Field>
                      <Field label="Number of offices">
                        <Input
                          value={gapIntake.num_offices ?? ""}
                          onChange={(e) => patchIntake({ num_offices: e.target.value })}
                        />
                      </Field>
                      <Field label="Number of endpoints">
                        <Input
                          value={gapIntake.num_endpoints ?? ""}
                          onChange={(e) => patchIntake({ num_endpoints: e.target.value })}
                          placeholder="600+"
                        />
                      </Field>
                    </div>
                  </FieldGroupPanel>
                </section>

                <section>
                  <SectionHeading>Operating systems</SectionHeading>
                  <FieldGroupPanel className="mt-4">
                    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                      <Field label="Windows">
                        <Input
                          value={os.windows ?? ""}
                          onChange={(e) => patchNested("operating_systems", { windows: e.target.value })}
                        />
                      </Field>
                      <Field label="Linux/Ubuntu">
                        <Input
                          value={os.linux ?? ""}
                          onChange={(e) => patchNested("operating_systems", { linux: e.target.value })}
                        />
                      </Field>
                      <Field label="Mac">
                        <Input
                          value={os.mac ?? ""}
                          onChange={(e) => patchNested("operating_systems", { mac: e.target.value })}
                        />
                      </Field>
                      <Field label="Data centers">
                        <Input
                          value={gapIntake.data_centers ?? ""}
                          onChange={(e) => patchIntake({ data_centers: e.target.value })}
                        />
                      </Field>
                    </div>
                  </FieldGroupPanel>
                </section>

                <section>
                  <SectionHeading>IT security &amp; network</SectionHeading>
                  <FieldGroupPanel className="mt-4">
                    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
                      <Field label="Critical servers">
                        <Input
                          value={gapIntake.critical_servers ?? ""}
                          onChange={(e) => patchIntake({ critical_servers: e.target.value })}
                        />
                      </Field>
                      <Field label="Critical devices">
                        <Input
                          value={gapIntake.critical_devices ?? ""}
                          onChange={(e) => patchIntake({ critical_devices: e.target.value })}
                        />
                      </Field>
                      <Field label="Web applications">
                        <Input
                          value={gapIntake.web_apps ?? ""}
                          onChange={(e) => patchIntake({ web_apps: e.target.value })}
                        />
                      </Field>
                      <Field label="Mobile applications">
                        <Input
                          value={gapIntake.mobile_apps ?? ""}
                          onChange={(e) => patchIntake({ mobile_apps: e.target.value })}
                        />
                      </Field>
                    </div>
                  </FieldGroupPanel>
                </section>

                <section>
                  <SectionHeading>Firewall</SectionHeading>
                  <FieldGroupPanel className="mt-4">
                    <div className="grid gap-4 sm:grid-cols-2">
                      <Field label="Make &amp; model">
                        <Input
                          value={fw.make_model ?? ""}
                          onChange={(e) => patchNested("firewall", { make_model: e.target.value })}
                        />
                      </Field>
                      <Field label="Policies &amp; logs">
                        <Input
                          value={fw.policies_logs ?? ""}
                          onChange={(e) => patchNested("firewall", { policies_logs: e.target.value })}
                        />
                      </Field>
                    </div>
                  </FieldGroupPanel>
                </section>

                <section>
                  <SectionHeading>Internet connectivity</SectionHeading>
                  <FieldGroupPanel className="mt-4">
                    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                      <Field label="Type">
                        <Input value={inet.type ?? ""} onChange={(e) => patchNested("internet", { type: e.target.value })} />
                      </Field>
                      <Field label="Vendors">
                        <Input
                          value={inet.vendors ?? ""}
                          onChange={(e) => patchNested("internet", { vendors: e.target.value })}
                        />
                      </Field>
                      <Field label="VPN &amp; SDWAN">
                        <Input
                          value={inet.vpn_sdwans ?? ""}
                          onChange={(e) => patchNested("internet", { vpn_sdwans: e.target.value })}
                        />
                      </Field>
                      <Field label="IDS/IPS">
                        <Input
                          value={inet.ids_ips ?? ""}
                          onChange={(e) => patchNested("internet", { ids_ips: e.target.value })}
                        />
                      </Field>
                      <Field label="DNS security">
                        <Input
                          value={inet.dns_security ?? ""}
                          onChange={(e) => patchNested("internet", { dns_security: e.target.value })}
                        />
                      </Field>
                    </div>
                  </FieldGroupPanel>
                </section>

                <section>
                  <SectionHeading>Other infrastructure</SectionHeading>
                  <FieldGroupPanel className="mt-4">
                    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
                      <Field label="Network access control (NAC)">
                        <Input value={gapIntake.nac ?? ""} onChange={(e) => patchIntake({ nac: e.target.value })} />
                      </Field>
                      <Field label="Antivirus">
                        <Input
                          value={gapIntake.antivirus ?? ""}
                          onChange={(e) => patchIntake({ antivirus: e.target.value })}
                        />
                      </Field>
                      <Field label="Backup storage">
                        <Input
                          value={gapIntake.backup_storage ?? ""}
                          onChange={(e) => patchIntake({ backup_storage: e.target.value })}
                        />
                      </Field>
                    </div>
                  </FieldGroupPanel>
                </section>

                <div className="flex flex-wrap gap-2 border-t border-ink-100 pt-6">
                  <Button
                    variant={intakeHasData ? "brand" : "outline"}
                    loading={savingIntake}
                    onClick={() => void saveGapIntake()}
                    disabled={!selectedCaseId}
                  >
                    {intakeHasData ? "Update site overview" : "Save site overview"}
                  </Button>
                  <Button
                    variant="brand"
                    loading={gapExporting === "pdf"}
                    disabled={!selectedCaseId}
                    onClick={() => void exportGap("pdf")}
                  >
                    <Download className="h-4 w-4" /> Download PDF
                  </Button>
                  <Button
                    variant="outline"
                    loading={gapExporting === "docx"}
                    disabled={!selectedCaseId}
                    onClick={() => void exportGap("docx")}
                  >
                    <Download className="h-4 w-4" /> Download DOCX
                  </Button>
                </div>

                <section className="border-t border-ink-100 pt-6">
                  <SectionHeading>Merge gap reports</SectionHeading>
                  <p className="mt-2 max-w-3xl text-sm text-ink-600">
                    Cases with a saved site overview in the selected date range appear here — today
                    first. From defaults to yesterday and can go further back. To is always today.
                    Identical findings are combined with IP addresses appended by comma; different
                    findings stay separate in one merged PDF.
                  </p>
                  <div className="mt-4 grid max-w-xl grid-cols-1 gap-3 sm:grid-cols-2">
                    <Field label="From" hint="Editable. Go further back for older reports.">
                      <Input
                        type="date"
                        value={mergeFromDate}
                        max={mergeToDate}
                        onChange={(e) => {
                          const next = e.target.value || kolkataYmd(-1);
                          setMergeFromDate(next > mergeToDate ? mergeToDate : next);
                        }}
                      />
                    </Field>
                    <Field label="To" hint="Always today. Cannot be changed.">
                      <Input type="date" value={mergeToDate} disabled readOnly />
                    </Field>
                  </div>
                  <FieldGroupPanel className="mt-4">
                    <div className="max-h-64 space-y-2 overflow-y-auto">
                      {mergeCandidates.length === 0 ? (
                        <p className="text-sm text-ink-400">
                          No merge candidates. Save a site overview on cases in the selected date range.
                        </p>
                      ) : (
                        mergeCandidates.map((c) => {
                          const checked = mergeCaseIds.includes(c.id);
                          const label = c.title || c.number || c.id.slice(0, 8);
                          const dayBadge = mergeDayBadge(c.day_label);
                          const d = c.gap_details || {};
                          const detailParts = [
                            d.client_name ? `Client: ${d.client_name}` : null,
                            d.branch_locations ? `Branch: ${d.branch_locations}` : null,
                            d.contact_person ? `Contact: ${d.contact_person}` : null,
                            d.date_of_visit ? `Visit: ${d.date_of_visit}` : null,
                            d.author ? `Author: ${d.author}` : null,
                            d.document_version ? `Ver: ${d.document_version}` : null,
                            d.num_endpoints ? `Endpoints: ${d.num_endpoints}` : null,
                          ].filter(Boolean);
                          const created = c.created_at
                            ? new Date(c.created_at).toLocaleString("en-IN", {
                                day: "2-digit",
                                month: "short",
                                year: "numeric",
                                hour: "2-digit",
                                minute: "2-digit",
                              })
                            : "";
                          return (
                            <label
                              key={c.id}
                              className="flex cursor-pointer items-start gap-2 rounded-lg border border-transparent px-2 py-2 text-sm hover:border-ink-100 hover:bg-ink-50"
                            >
                              <input
                                type="checkbox"
                                className="mt-1 h-4 w-4 rounded border-ink-300"
                                checked={checked}
                                onChange={() => toggleMergeCase(c.id)}
                              />
                              <span className="min-w-0 flex-1">
                                <span className="flex flex-wrap items-center gap-1.5">
                                  <span className="font-medium text-ink-800">{label}</span>
                                  <Badge tone={dayBadge.tone}>{dayBadge.text}</Badge>
                                  <span className="font-mono text-[10px] text-ink-400">
                                    {c.id.slice(0, 8)}
                                  </span>
                                </span>
                                {created ? (
                                  <span className="mt-0.5 block text-[11px] text-ink-500">
                                    Created {created}
                                  </span>
                                ) : null}
                                {detailParts.length > 0 ? (
                                  <span className="mt-0.5 block text-[11px] text-ink-600">
                                    {detailParts.join(" · ")}
                                  </span>
                                ) : (
                                  <span className="mt-0.5 block text-[11px] text-ink-400">
                                    Site overview saved (no detail fields filled)
                                  </span>
                                )}
                              </span>
                            </label>
                          );
                        })
                      )}
                    </div>
                    <div className="mt-4 flex flex-wrap items-center gap-2">
                      <Button
                        variant="brand"
                        loading={gapExporting === "merged"}
                        disabled={mergeCaseIds.length < 2}
                        onClick={() => void exportMergedGap()}
                      >
                        <Download className="h-4 w-4" /> Merge &amp; download PDF
                      </Button>
                      <span className="text-xs text-ink-500">
                        {mergeCaseIds.length} case{mergeCaseIds.length === 1 ? "" : "s"} selected
                        {mergeCaseIds.length > 0 && mergeCaseIds.length < 2
                          ? " · pick one more"
                          : ""}
                      </span>
                    </div>
                  </FieldGroupPanel>
                </section>
              </div>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
