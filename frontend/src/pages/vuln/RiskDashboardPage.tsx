import { useCallback, useEffect, useState } from "react";
import { AlertOctagon, Server, TrendingUp } from "lucide-react";
import { Badge, Card, Field, PageHeader, Select, Spinner } from "../../components/ui";
import { ChartCard, MetricBarChart, MetricDonutChart } from "../../components/charts";
import { namedValues } from "../../lib/chartCounts";
import { vulnApi } from "../../lib/vulnApi";
import { useToast } from "../../lib/toast";
import type { Case } from "../../lib/types/forensic";
import type { Asset, AssetRisk } from "../../lib/types/vuln";

export function RiskDashboardPage() {
  const toast = useToast();
  const [cases, setCases] = useState<Case[]>([]);
  const [caseId, setCaseId] = useState("");
  const [assets, setAssets] = useState<Asset[]>([]);
  const [risks, setRisks] = useState<Map<string, AssetRisk>>(new Map());
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
      const res = await vulnApi.listAssets({ case_id: caseId, page: 1, page_size: 50 });
      setAssets(res.items);
      const riskMap = new Map<string, AssetRisk>();
      await Promise.all(
        res.items.slice(0, 20).map(async (a) => {
          try {
            const r = await vulnApi.getAssetRisk(a.id);
            riskMap.set(a.id, r);
          } catch {
            /* skip */
          }
        })
      );
      setRisks(riskMap);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to load assets");
    } finally {
      setLoading(false);
    }
  }, [caseId, toast]);

  useEffect(() => {
    load();
  }, [load]);

  const totalCritical = Array.from(risks.values()).reduce((s, r) => s + r.critical_count, 0);
  const totalHigh = Array.from(risks.values()).reduce((s, r) => s + r.high_count, 0);
  const avgRisk =
    assets.length > 0
      ? assets.reduce((s, a) => s + (a.risk_score ?? 0), 0) / assets.filter((a) => a.risk_score).length
      : 0;

  return (
    <div>
      <PageHeader
        title="Risk dashboard"
        subtitle="Aggregate asset risk scores and severity breakdowns per case."
      />

      <Card className="mb-6 p-4">
        <Field label="Case">
          <Select className="max-w-sm" value={caseId} onChange={(e) => setCaseId(e.target.value)}>
            <option value="">Select case…</option>
            {cases.map((c) => (
              <option key={c.id} value={c.id}>
                {c.title || c.number || c.id.slice(0, 8)}
              </option>
            ))}
          </Select>
        </Field>
      </Card>

      {loading ? (
        <Spinner />
      ) : (
        <>
          <div className="row g-3 mb-4">
            <div className="col-12 col-lg-7">
              <ChartCard title="Severity mix" subtitle="From asset risk API">
                <MetricBarChart
                  data={namedValues([
                    { name: "Critical", value: totalCritical, fill: "#dc2626" },
                    { name: "High", value: totalHigh, fill: "#ea580c" },
                    { name: "Assets", value: assets.length, fill: "#f47b20" },
                  ])}
                />
              </ChartCard>
            </div>
            <div className="col-12 col-lg-5">
              <ChartCard title="Risk bands" subtitle="Asset risk scores">
                <MetricDonutChart
                  data={namedValues([
                    {
                      name: "High",
                      value: assets.filter((a) => (a.risk_score ?? 0) >= 8).length,
                      fill: "#dc2626",
                    },
                    {
                      name: "Medium",
                      value: assets.filter((a) => (a.risk_score ?? 0) >= 5 && (a.risk_score ?? 0) < 8).length,
                      fill: "#d97706",
                    },
                    {
                      name: "Low",
                      value: assets.filter((a) => (a.risk_score ?? 0) > 0 && (a.risk_score ?? 0) < 5).length,
                      fill: "#059669",
                    },
                  ])}
                  centerLabel="Assets"
                  emptyLabel="No scored assets"
                />
              </ChartCard>
            </div>
          </div>
          <div className="mb-6 grid gap-4 sm:grid-cols-4">
            <Card className="p-4">
              <div className="flex items-center gap-2 text-ink-400">
                <Server className="h-4 w-4" />
                <span className="text-xs font-semibold uppercase">Assets</span>
              </div>
              <p className="mt-2 text-3xl font-bold text-ink-900">{assets.length}</p>
            </Card>
            <Card className="p-4">
              <div className="flex items-center gap-2 text-red-500">
                <AlertOctagon className="h-4 w-4" />
                <span className="text-xs font-semibold uppercase">Critical</span>
              </div>
              <p className="mt-2 text-3xl font-bold text-red-600">{totalCritical}</p>
            </Card>
            <Card className="p-4">
              <div className="flex items-center gap-2 text-amber-500">
                <AlertOctagon className="h-4 w-4" />
                <span className="text-xs font-semibold uppercase">High</span>
              </div>
              <p className="mt-2 text-3xl font-bold text-amber-600">{totalHigh}</p>
            </Card>
            <Card className="p-4">
              <div className="flex items-center gap-2 text-brand-600">
                <TrendingUp className="h-4 w-4" />
                <span className="text-xs font-semibold uppercase">Avg risk</span>
              </div>
              <p className="mt-2 text-3xl font-bold text-ink-900">
                {avgRisk ? avgRisk.toFixed(1) : "—"}
              </p>
            </Card>
          </div>

          <Card className="overflow-hidden">
            {assets.length === 0 ? (
              <p className="px-5 py-16 text-center text-sm text-ink-400">No assets discovered.</p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-left text-sm">
                  <thead>
                    <tr className="table-head border-b border-brand-300/70 text-xs uppercase tracking-wider text-ink-700">
                      <th className="px-5 py-3 font-semibold">Asset</th>
                      <th className="px-5 py-3 font-semibold">IP</th>
                      <th className="px-5 py-3 font-semibold">OS</th>
                      <th className="px-5 py-3 font-semibold">Risk score</th>
                      <th className="px-5 py-3 font-semibold">Findings</th>
                      <th className="px-5 py-3 font-semibold">Top CVEs</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-ink-100">
                    {assets.map((a) => {
                      const risk = risks.get(a.id);
                      return (
                        <tr key={a.id} className="hover:bg-ink-50/60">
                          <td className="px-5 py-3 font-semibold text-ink-800">
                            {a.hostname || "—"}
                          </td>
                          <td className="px-5 py-3 font-mono text-xs text-ink-600">
                            {a.primary_ip || "—"}
                          </td>
                          <td className="px-5 py-3 text-ink-500">{a.os || "—"}</td>
                          <td className="px-5 py-3">
                            {a.risk_score != null ? (
                              <Badge
                                tone={
                                  a.risk_score >= 8 ? "red" : a.risk_score >= 5 ? "amber" : "green"
                                }
                              >
                                {a.risk_score.toFixed(1)}
                              </Badge>
                            ) : (
                              "—"
                            )}
                          </td>
                          <td className="px-5 py-3 text-ink-500">
                            {risk ? (
                              <span>
                                {risk.critical_count}c / {risk.high_count}h / {risk.medium_count}m
                              </span>
                            ) : (
                              "—"
                            )}
                          </td>
                          <td className="px-5 py-3 font-mono text-xs text-ink-500">
                            {risk?.top_cves.slice(0, 2).join(", ") || "—"}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
