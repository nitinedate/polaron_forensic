import { useEffect, useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  ClipboardList,
  FileOutput,
  ListChecks,
  Radar,
  Server,
  Shield,
  Timer,
  AlertTriangle,
} from "lucide-react";
import { Card, PageHeader, Spinner } from "../../components/ui";
import { ChartCard, MetricBarChart, MetricRadialGauge } from "../../components/charts";
import { vulnApi, type VulnOverview } from "../../lib/vulnApi";
import { namedValues } from "../../lib/chartCounts";

const ACTIONS = [
  {
    to: "/vuln/scanners",
    title: "Scanners",
    desc: "Central GMP plus network scanner tokens (no laptop install)",
    icon: Server,
  },
  {
    to: "/vuln/connect",
    title: "Connect client network",
    desc: "Paste a scanner token so this site’s IPs can be scanned from the server",
    icon: Radar,
  },
  {
    to: "/vuln/agents",
    title: "Agents",
    desc: "Agent lifecycle Planned → Healthy / Stale → Retired (BRD §8.3)",
    icon: Radar,
  },
  {
    to: "/vuln/credentials",
    title: "Credentials",
    desc: "Vault references only — no plaintext secrets (BRD §8)",
    icon: ClipboardList,
  },
  {
    to: "/vuln/policies",
    title: "Policies & schedules",
    desc: "Reusable templates — Draft → Approved → Published (SOP §7)",
    icon: ClipboardList,
  },
  {
    to: "/vuln/scans",
    title: "Scan jobs",
    desc: "Basic / Advanced / Web / Credentialed with pre-scan gates (SOP §3–6)",
    icon: Radar,
  },
  {
    to: "/vuln/findings",
    title: "Vuln explorer",
    desc: "Severity + contextual risk triage (SOP §3.2 / BRD §9)",
    icon: Shield,
  },
  {
    to: "/vuln/remediation",
    title: "Remediation board",
    desc: "Assign, SLA, rescan verify (SOP §9)",
    icon: ListChecks,
  },
  {
    to: "/vuln/exceptions",
    title: "Exceptions",
    desc: "Risk acceptance with segregation of duties (BRD §10)",
    icon: AlertTriangle,
  },
  {
    to: "/vuln/timeline",
    title: "Timeline",
    desc: "Case activity and scan lifecycle events",
    icon: Timer,
  },
  {
    to: "/vuln/reports",
    title: "Reports export",
    desc: "PDF / CSV / JSON with audience templates (SOP §8)",
    icon: FileOutput,
  },
];

export function VulnOpsHomePage() {
  const [overview, setOverview] = useState<VulnOverview | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    vulnApi
      .getOverview()
      .then(setOverview)
      .catch(() => setOverview(null))
      .finally(() => setLoading(false));
  }, []);

  const opsSeries = useMemo(
    () =>
      namedValues([
        { name: "Running", value: overview?.functionality.scans_running ?? 0, fill: "#4f46e5" },
        { name: "Failed 24h", value: overview?.functionality.failed_24h ?? 0, fill: "#dc2626" },
        { name: "Remediation", value: overview?.functionality.open_remediation ?? 0, fill: "#d97706" },
        { name: "Exceptions", value: overview?.functionality.exceptions_pending ?? 0, fill: "#f47b20" },
      ]),
    [overview],
  );

  return (
    <div>
      <PageHeader
        title="Vulnerability Functionality"
        subtitle="SOP operational workspace — separate from analytics dashboards."
        actions={
          <Link to="/vuln/dashboards" className="text-sm font-semibold text-brand-700 hover:underline">
            ← Dashboards hub
          </Link>
        }
      />

      {loading ? (
        <div className="mb-6 flex justify-center py-6">
          <Spinner />
        </div>
      ) : (
        <div className="row g-3 mb-6">
          <div className="col-12 col-lg-8">
            <ChartCard title="Operations load" subtitle="Live from /api/vuln/overview">
              <MetricBarChart data={opsSeries} />
            </ChartCard>
          </div>
          <div className="col-6 col-lg-2">
            <ChartCard title="Coverage" height={220}>
              <MetricRadialGauge value={overview?.dashboards.coverage_pct ?? 0} label="Coverage %" />
            </ChartCard>
          </div>
          <div className="col-6 col-lg-2">
            <ChartCard title="SLA" height={220}>
              <MetricRadialGauge value={overview?.dashboards.sla_overdue_pct ?? 0} label="Overdue %" />
            </ChartCard>
          </div>
        </div>
      )}

      <Card className="mb-6 border-amber-200 bg-amber-50 p-4 text-sm text-amber-950">
        <p className="font-semibold">Pre-scan controls (required before launch)</p>
        <p className="mt-1">
          Authorization reference, target validation, forbidden ranges, scanner health, plugin feed freshness,
          credential test, maintenance window, and concurrency estimate must be confirmed on each scan job.
        </p>
      </Card>

      <div className="row g-3">
        {ACTIONS.map((a) => (
          <div key={a.to} className="col-12 col-sm-6 col-xl-3">
            <Link to={a.to} className="block h-full">
              <Card className="h-full p-4 transition hover:ring-1 hover:ring-brand-200">
                <a.icon className="mb-3 h-5 w-5 text-ink-500" />
                <h3 className="font-semibold text-ink-900">{a.title}</h3>
                <p className="mt-1 text-sm text-ink-500">{a.desc}</p>
              </Card>
            </Link>
          </div>
        ))}
      </div>
    </div>
  );
}
