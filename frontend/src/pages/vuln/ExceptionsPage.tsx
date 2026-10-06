import { useCallback, useEffect, useState } from "react";
import { Badge, Button, Card, PageHeader, Spinner } from "../../components/ui";
import { InsightCharts } from "../../components/charts";
import { countBy } from "../../lib/chartCounts";
import { vulnApi } from "../../lib/vulnApi";
import { useAuth } from "../../lib/auth";
import { useToast } from "../../lib/toast";

export function ExceptionsPage() {
  const { hasPermission } = useAuth();
  const toast = useToast();
  const canApprove = hasPermission("exception:approve");
  const [items, setItems] = useState<Array<Record<string, unknown>>>([]);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setItems(await vulnApi.listExceptions());
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Failed to load exceptions");
    } finally {
      setLoading(false);
    }
  }, [toast]);

  useEffect(() => {
    load();
  }, [load]);

  const decide = async (id: string, status: "approved" | "rejected") => {
    try {
      await vulnApi.decideException(id, { status });
      toast.success(`Exception ${status}`);
      load();
    } catch (e: unknown) {
      toast.error(e instanceof Error ? e.message : "Decision failed (SoD may block self-approval)");
    }
  };

  return (
    <div>
      <PageHeader
        title="Exception governance"
        subtitle="Pending / approved risk exceptions — approver cannot be the requester."
      />
      {!loading && items.length > 0 && (
        <InsightCharts
          left={{
            title: "Exception status",
            subtitle: "From /api/vuln/exceptions",
            data: countBy(items, (ex) => String(ex.status || "pending")),
            kind: "bar",
          }}
        />
      )}
      {loading ? (
        <div className="flex justify-center py-12">
          <Spinner />
        </div>
      ) : (
        <Card className="overflow-hidden p-0">
          <div className="overflow-x-auto">
          <table className="min-w-full text-left text-sm">
            <thead>
              <tr className="table-head border-b border-brand-300/70 text-ink-700">
                <th className="px-4 py-3">Finding</th>
                <th className="px-4 py-3">Status</th>
                <th className="px-4 py-3">Reason</th>
                <th className="px-4 py-3">Expires</th>
                <th className="px-4 py-3">Actions</th>
              </tr>
            </thead>
            <tbody>
              {items.map((ex) => (
                <tr key={String(ex.id)} className="border-b border-ink-50">
                  <td className="px-4 py-3 font-mono text-xs">{String(ex.finding_id).slice(0, 8)}…</td>
                  <td className="px-4 py-3">
                    <Badge>{String(ex.status)}</Badge>
                  </td>
                  <td className="px-4 py-3 max-w-xs truncate">{String(ex.reason || "—")}</td>
                  <td className="px-4 py-3">{ex.expires_at ? String(ex.expires_at) : "—"}</td>
                  <td className="px-4 py-3">
                    {canApprove && ex.status === "pending" ? (
                      <div className="flex gap-2">
                        <Button onClick={() => decide(String(ex.id), "approved")}>
                          Approve
                        </Button>
                        <Button variant="outline" onClick={() => decide(String(ex.id), "rejected")}>
                          Reject
                        </Button>
                      </div>
                    ) : (
                      "—"
                    )}
                  </td>
                </tr>
              ))}
              {items.length === 0 ? (
                <tr>
                  <td colSpan={5} className="px-4 py-8 text-center text-ink-400">
                    No exceptions yet.
                  </td>
                </tr>
              ) : null}
            </tbody>
          </table>
          </div>
        </Card>
      )}
    </div>
  );
}
