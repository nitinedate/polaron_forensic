import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams, Link } from "react-router-dom";
import { Download, Info } from "lucide-react";
import { Badge, Button, Card, Field, PageHeader, Select, Spinner } from "../../../components/ui";
import { ChartCard, MetricBarChart, MetricDonutChart, MetricRadialGauge } from "../../../components/charts";
import { namedValues, statusColor } from "../../../lib/chartCounts";
import { vulnApi, type VulnDashboardLayer } from "../../../lib/vulnApi";
import { useToast } from "../../../lib/toast";
import { useAuth } from "../../../lib/auth";

const LAYERS: { id: string; label: string }[] = [
  { id: "executive", label: "Executive Risk" },
  { id: "vm_operations", label: "VM Operations" },
  { id: "coverage", label: "Coverage & Hygiene" },
  { id: "scanner_health", label: "Scanner / Agent Health" },
  { id: "remediation", label: "Remediation & SLA" },
  { id: "compliance", label: "Compliance" },
  { id: "exceptions", label: "Exception Governance" },
  { id: "asset_intelligence", label: "Asset Intelligence" },
];

function WidgetCard({ title, children, definition }: { title: string; children: React.ReactNode; definition?: string }) {
  return (
    <Card className="p-4">
      <div className="mb-3 flex items-start justify-between gap-2">
        <h3 className="text-sm font-semibold text-ink-900">{title}</h3>
        {definition ? (
          <span title={definition} className="text-ink-400">
            <Info className="h-4 w-4" />
          </span>
        ) : null}
      </div>
      {children}
    </Card>
  );
}

export function VulnDashboardsPage() {
  const toast = useToast();
  const { hasPermission } = useAuth();
  const [params, setParams] = useSearchParams();
  const layer = params.get("layer") || "executive";
  const [data, setData] = useState<VulnDashboardLayer | null>(null);
  const [loading, setLoading] = useState(true);
  const [severity, setSeverity] = useState(params.get("severity") || "");
  const [environment, setEnvironment] = useState(params.get("environment") || "");

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const res = await vulnApi.getDashboard(layer);
      setData(res);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to load dashboard");
    } finally {
      setLoading(false);
    }
  }, [layer, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const applyFilters = () => {
    const next = new URLSearchParams(params);
    next.set("layer", layer);
    if (severity) next.set("severity", severity);
    else next.delete("severity");
    if (environment) next.set("environment", environment);
    else next.delete("environment");
    setParams(next);
  };

  const exportJson = async () => {
    try {
      const res = await vulnApi.exportDashboard(layer, "json");
      const blob = new Blob([JSON.stringify(res, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `vuln-dashboard-${layer}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Export failed");
    }
  };

  const widgets = data?.widgets || {};
  const kpis = (widgets.kpis || widgets.executive || {}) as Record<string, number>;
  const severityBreakdown = (widgets.severity_breakdown || []) as Array<{ label: string; value: number }>;
  const aging = (widgets.aging || []) as Array<{ label: string; value: number }>;
  const scanners = (widgets.scanners || []) as Array<Record<string, string | null>>;

  const freshness = data?.freshness;
  const dict = data?.metric_dictionary || {};

  const layerLabel = useMemo(() => LAYERS.find((l) => l.id === layer)?.label || layer, [layer]);

  return (
    <div>
      <PageHeader
        title="Vulnerability Dashboards"
        subtitle="BRD analytics layers — filters update widgets; drill into operations from Functionality hub."
        actions={
          hasPermission("dashboard:export") ? (
            <Button variant="outline" onClick={exportJson}>
              <Download className="mr-2 h-4 w-4" />
              Export JSON
            </Button>
          ) : null
        }
      />

      {freshness ? (
        <div className="mb-4 rounded-lg border border-ink-200 bg-ink-50 px-3 py-2 text-xs text-ink-600">
          Data freshness: {freshness.last_ingestion_at}
          {freshness.stale ? <Badge tone="amber">Stale</Badge> : <Badge tone="green">Current</Badge>}
        </div>
      ) : null}

      <Card className="mb-6 p-4">
        <div className="mb-3 flex flex-wrap gap-2">
          {LAYERS.map((l) => (
            <button
              key={l.id}
              type="button"
              onClick={() => {
                const next = new URLSearchParams(params);
                next.set("layer", l.id);
                setParams(next);
              }}
              className={
                layer === l.id
                  ? "rounded-lg bg-brand-600 px-3 py-1.5 text-xs font-semibold text-white"
                  : "rounded-lg border border-ink-200 px-3 py-1.5 text-xs font-semibold text-ink-600 hover:bg-ink-50"
              }
            >
              {l.label}
            </button>
          ))}
        </div>
        <div className="grid gap-3 md:grid-cols-4">
          <Field label="Severity">
            <Select value={severity} onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setSeverity(e.target.value)}>
              <option value="">All</option>
              <option value="critical">Critical</option>
              <option value="high">High</option>
              <option value="medium">Medium</option>
              <option value="low">Low</option>
            </Select>
          </Field>
          <Field label="Environment">
            <Select value={environment} onChange={(e: React.ChangeEvent<HTMLSelectElement>) => setEnvironment(e.target.value)}>
              <option value="">All</option>
              <option value="production">Production</option>
              <option value="staging">Staging</option>
              <option value="development">Development</option>
            </Select>
          </Field>
          <div className="flex items-end">
            <Button onClick={applyFilters}>Apply filters</Button>
          </div>
          <div className="flex items-end justify-end text-sm">
            <Link to="/vuln/ops" className="font-semibold text-brand-700 hover:underline">
              Go to Functionality →
            </Link>
          </div>
        </div>
      </Card>

      <h2 className="mb-3 text-base font-semibold text-ink-800">{layerLabel}</h2>

      {loading ? (
        <div className="flex justify-center py-12">
          <Spinner />
        </div>
      ) : (
        <>
        <div className="row g-3 mb-4">
          <div className="col-6 col-xl-3">
            <ChartCard title="Enterprise risk" subtitle={dict.enterprise_risk_score} height={170}>
              <MetricRadialGauge value={Number(kpis.enterprise_risk_score ?? 0)} label="Risk" max={10} />
            </ChartCard>
          </div>
          <div className="col-6 col-xl-3">
            <ChartCard title="Coverage" subtitle={dict.coverage_pct} height={170}>
              <MetricRadialGauge value={Number(kpis.coverage_pct ?? 0)} label="Coverage %" />
            </ChartCard>
          </div>
          <div className="col-6 col-xl-3">
            <ChartCard title="SLA overdue" subtitle={dict.sla_overdue_pct} height={170}>
              <MetricRadialGauge value={Number(kpis.sla_overdue_pct ?? 0)} label="Overdue %" />
            </ChartCard>
          </div>
          <div className="col-6 col-xl-3">
            <WidgetCard title="KEV open" definition={dict.kev_open}>
              <p className="text-3xl font-semibold">{kpis.kev_open ?? "—"}</p>
            </WidgetCard>
          </div>
        </div>

        <div className="row g-3 mb-4">
          <div className="col-12 col-lg-6">
            <ChartCard title="Polaron — Findings by severity" subtitle="CVSS v3 bands">
              <MetricDonutChart
                data={severityBreakdown.map((s) => ({
                  name: s.label,
                  value: s.value,
                  fill: statusColor(s.label),
                }))}
                centerLabel="Findings"
                emptyLabel="No open findings"
              />
            </ChartCard>
          </div>
          <div className="col-12 col-lg-6">
            <ChartCard title="Finding age" subtitle="Aging buckets from API">
              <MetricBarChart
                data={namedValues(aging.map((s) => ({ name: s.label, value: s.value })))}
                emptyLabel="No aging data"
              />
            </ChartCard>
          </div>
        </div>

        {(layer === "scanner_health" || layer === "all") && (
          <Card className="overflow-hidden p-4">
            <h3 className="mb-3 text-sm font-semibold">Scanners</h3>
            <div className="overflow-x-auto">
              <table className="min-w-full text-left text-sm">
                <thead>
                  <tr className="table-head border-b border-brand-300/70 text-ink-700">
                    <th className="py-2 pr-4">Name</th>
                    <th className="py-2 pr-4">Status</th>
                    <th className="py-2 pr-4">Heartbeat</th>
                    <th className="py-2">Feed</th>
                  </tr>
                </thead>
                <tbody>
                  {scanners.map((s) => (
                    <tr key={String(s.id)} className="border-b border-ink-50">
                      <td className="py-2 pr-4">{s.name}</td>
                      <td className="py-2 pr-4">{s.status}</td>
                      <td className="py-2 pr-4">{s.last_heartbeat_at || "—"}</td>
                      <td className="py-2">{s.plugin_feed_updated_at || "—"}</td>
                    </tr>
                  ))}
                  {scanners.length === 0 ? (
                    <tr>
                      <td colSpan={4} className="py-4 text-ink-400">
                        No scanners registered — add them under Functionality.
                      </td>
                    </tr>
                  ) : null}
                </tbody>
              </table>
            </div>
          </Card>
        )}
        </>
      )}
    </div>
  );
}
