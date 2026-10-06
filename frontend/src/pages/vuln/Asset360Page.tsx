import { useCallback, useEffect, useState } from "react";
import { useParams, Link } from "react-router-dom";
import { Card, PageHeader, Spinner, Badge } from "../../components/ui";
import { vulnApi } from "../../lib/vulnApi";
import type { Asset, AssetRisk } from "../../lib/types/vuln";
import { useToast } from "../../lib/toast";

export function Asset360Page() {
  const { assetId = "" } = useParams();
  const toast = useToast();
  const [asset, setAsset] = useState<Asset | null>(null);
  const [risk, setRisk] = useState<AssetRisk | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    if (!assetId) return;
    setLoading(true);
    try {
      const [a, r] = await Promise.all([vulnApi.getAsset(assetId), vulnApi.getAssetRisk(assetId)]);
      setAsset(a);
      setRisk(r);
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to load asset");
    } finally {
      setLoading(false);
    }
  }, [assetId, toast]);

  useEffect(() => {
    load();
  }, [load]);

  if (loading) {
    return (
      <div className="flex justify-center py-16">
        <Spinner />
      </div>
    );
  }

  if (!asset) {
    return <PageHeader title="Asset not found" subtitle="Return to dashboards or asset lists." />;
  }

  return (
    <div>
      <PageHeader
        title={asset.hostname || asset.primary_ip || asset.id.slice(0, 8)}
        subtitle="Asset 360 — identity, risk, and identifiers (BRD §7.4)"
        actions={
          <Link to="/vuln/dashboards?layer=asset_intelligence" className="text-sm font-semibold text-brand-700">
            ← Asset intelligence
          </Link>
        }
      />
      <div className="grid gap-4 md:grid-cols-3">
        <Card className="p-4">
          <p className="text-xs font-semibold uppercase text-ink-400">Identity</p>
          <p className="mt-2 text-sm">Hostname: {asset.hostname || "—"}</p>
          <p className="text-sm">IP: {asset.primary_ip || "—"}</p>
          <p className="text-sm">OS: {asset.os || "—"}</p>
          <p className="text-sm">Type: {asset.asset_type || "—"}</p>
        </Card>
        <Card className="p-4">
          <p className="text-xs font-semibold uppercase text-ink-400">Risk</p>
          <p className="mt-2 text-3xl font-semibold">{risk?.risk_score ?? asset.risk_score ?? "—"}</p>
          <p className="mt-2 text-sm">Findings: {risk?.finding_count ?? 0}</p>
          <p className="text-sm">
            C/H/M/L: {risk?.critical_count}/{risk?.high_count}/{risk?.medium_count}/{risk?.low_count}
          </p>
        </Card>
        <Card className="p-4">
          <p className="text-xs font-semibold uppercase text-ink-400">Identifiers</p>
          <ul className="mt-2 space-y-1 text-sm">
            {asset.identifiers.map((i) => (
              <li key={i.id}>
                <Badge>{i.id_type}</Badge>
                {i.value}
              </li>
            ))}
            {asset.identifiers.length === 0 ? <li className="text-ink-400">None</li> : null}
          </ul>
        </Card>
      </div>
      {risk?.top_cves?.length ? (
        <Card className="mt-4 p-4">
          <p className="mb-2 text-xs font-semibold uppercase text-ink-400">Top CVEs</p>
          <div className="flex flex-wrap gap-2">
            {risk.top_cves.map((c) => (
              <Badge key={c}>{c}</Badge>
            ))}
          </div>
        </Card>
      ) : null}
    </div>
  );
}
