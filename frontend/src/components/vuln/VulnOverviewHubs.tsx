import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  AlertTriangle,
  ClipboardList,
  LayoutDashboard,
  Radar,
  ShieldAlert,
} from "lucide-react";
import { Card, Spinner } from "../ui";
import { ChartCard, MetricBarChart, MetricRadialGauge } from "../charts";
import { vulnApi, type VulnOverview } from "../../lib/vulnApi";
import { isVulnModuleEnabled } from "../../lib/vulnFlags";
import { useAuth } from "../../lib/auth";
import { namedValues } from "../../lib/chartCounts";

/** Additive Overview section — only rendered when module + perms allow. */
export function VulnOverviewHubs() {
  const { hasPermission } = useAuth();
  const enabled =
    isVulnModuleEnabled() && (hasPermission("vuln:read") || hasPermission("scan:read"));
  const [data, setData] = useState<VulnOverview | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!enabled) return;
    setLoading(true);
    vulnApi
      .getOverview()
      .then(setData)
      .catch(() => setData(null))
      .finally(() => setLoading(false));
  }, [enabled]);

  const riskSeries = useMemo(
    () =>
      namedValues([
        { name: "Risk", value: data?.dashboards.enterprise_risk_score ?? 0, fill: "#dc2626" },
        { name: "KEV open", value: data?.dashboards.kev_open ?? 0, fill: "#d97706" },
        { name: "Critical", value: data?.dashboards.critical_open ?? 0, fill: "#ea580c" },
        { name: "Open", value: data?.dashboards.open_findings ?? 0, fill: "#1f2733" },
      ]),
    [data],
  );
  const opsSeries = useMemo(
    () =>
      namedValues([
        { name: "Running", value: data?.functionality.scans_running ?? 0, fill: "#4f46e5" },
        { name: "Failed 24h", value: data?.functionality.failed_24h ?? 0, fill: "#dc2626" },
        { name: "Remediation", value: data?.functionality.open_remediation ?? 0, fill: "#d97706" },
        { name: "Exceptions", value: data?.functionality.exceptions_pending ?? 0, fill: "#f47b20" },
      ]),
    [data],
  );

  if (!enabled) return null;

  return (
    <section className="mt-10 border-t border-ink-100 pt-8">
      <div className="mb-4">
        <h2 className="text-lg font-semibold text-ink-900">Vulnerability management</h2>
        <p className="text-sm text-ink-500">
          Two hubs on the same console — analytics dashboards and operational functionality stay separate.
        </p>
      </div>
      {loading && !data ? (
        <div className="flex justify-center py-8">
          <Spinner />
        </div>
      ) : (
        <div className="row g-4">
          <div className="col-12 col-lg-6">
            <Card className="h-full p-5">
              <div className="mb-4 flex items-start gap-3">
                <div className="rounded-lg bg-brand-50 p-2 text-brand-700">
                  <LayoutDashboard className="h-5 w-5" />
                </div>
                <div>
                  <h3 className="font-semibold text-ink-900">Vulnerability Dashboards</h3>
                  <p className="text-sm text-ink-500">
                    Executive risk, coverage, SLA, scanner health, compliance (BRD analytics).
                  </p>
                </div>
              </div>
              <div className="row g-3 mb-4">
                <div className="col-6">
                  <ChartCard title="Coverage" subtitle="From /api/vuln/overview" height={160}>
                    <MetricRadialGauge value={data?.dashboards.coverage_pct ?? 0} label="Coverage %" />
                  </ChartCard>
                </div>
                <div className="col-6">
                  <ChartCard title="SLA overdue" subtitle="Open findings past SLA" height={160}>
                    <MetricRadialGauge value={data?.dashboards.sla_overdue_pct ?? 0} label="Overdue %" />
                  </ChartCard>
                </div>
                <div className="col-12">
                  <ChartCard title="Risk snapshot" subtitle="Live API metrics" height={200}>
                    <MetricBarChart data={riskSeries} />
                  </ChartCard>
                </div>
              </div>
              <Link
                to="/vuln/dashboards"
                className="inline-flex items-center gap-2 rounded-lg bg-brand-600 px-4 py-2 text-sm font-semibold text-white hover:bg-brand-700"
              >
                <ShieldAlert className="h-4 w-4" />
                Open dashboards
              </Link>
            </Card>
          </div>

          <div className="col-12 col-lg-6">
            <Card className="h-full p-5">
              <div className="mb-4 flex items-start gap-3">
                <div className="rounded-lg bg-ink-100 p-2 text-ink-700">
                  <Radar className="h-5 w-5" />
                </div>
                <div>
                  <h3 className="font-semibold text-ink-900">Vulnerability Functionality</h3>
                  <p className="text-sm text-ink-500">Scans, policies, remediation, reports (SOP operations).</p>
                </div>
              </div>
              <div className="mb-4">
                <ChartCard title="Operations load" subtitle="Scans and queue from the overview API" height={280}>
                  <MetricBarChart data={opsSeries} />
                </ChartCard>
              </div>
              <div className="flex flex-wrap gap-2">
                <Link
                  to="/vuln/ops"
                  className="inline-flex items-center gap-2 rounded-lg bg-ink-900 px-4 py-2 text-sm font-semibold text-white hover:bg-ink-800"
                >
                  <ClipboardList className="h-4 w-4" />
                  Open operations
                </Link>
                <Link
                  to="/vuln/scans"
                  className="inline-flex items-center gap-2 rounded-lg border border-ink-200 px-4 py-2 text-sm font-semibold text-ink-700 hover:bg-ink-50"
                >
                  <Activity className="h-4 w-4" />
                  Scan jobs
                </Link>
                <Link
                  to="/vuln/exceptions"
                  className="inline-flex items-center gap-2 rounded-lg border border-ink-200 px-4 py-2 text-sm font-semibold text-ink-700 hover:bg-ink-50"
                >
                  <AlertTriangle className="h-4 w-4" />
                  Exceptions
                </Link>
              </div>
            </Card>
          </div>
        </div>
      )}
    </section>
  );
}
